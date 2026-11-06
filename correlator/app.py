#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Correlator (RCA) do Projeto 1 (SSLE).

Recebe os alertas do Alertmanager (webhook), junta os que estão a disparar,
mapeia-os no grafo de dependências do inventário (build/graph.json) e escolhe
como CAUSA RAIZ o nó que explica mais sintomas. Escreve UMA linha JSON por
incidente em /var/log/ssle/incidents.json (que um agente Wazuh lê — §3.5 do
plano) e expõe métricas em /metrics para o Prometheus global.

Depende só de Flask (stdlib + flask). Metrics em texto, sem prometheus_client.
"""
import json, os, threading, time
from datetime import datetime, timezone
from flask import Flask, request, jsonify

GRAPH_PATH = os.environ.get("CORRELATOR_GRAPH", "/opt/correlator/graph.json")
LOG_PATH = os.environ.get("CORRELATOR_LOG", "/var/log/ssle/incidents.json")
WINDOW_S = int(os.environ.get("CORRELATOR_WINDOW", "120"))

DOWN_ALERTS = {"ElementDown", "ServiceDown", "SiteUnreachable"}
SEV_ORDER = {"critical": 3, "warning": 2, "info": 1}

app = Flask(__name__)
_lock = threading.Lock()
_active = {}            # fingerprint -> alert dict
_last_sig = {}          # site -> assinatura do último incidente emitido
_metrics = {"incidents_total": 0, "active_alerts": 0, "last_noise_reduction": 0.0}


def _load_graph():
    try:
        with open(GRAPH_PATH) as fh:
            g = json.load(fh)
    except Exception:
        g = {"nodes": [], "edges": []}
    adj = {}                                   # dependente -> [dependências]
    for e in g.get("edges", []):
        adj.setdefault(e["from"], []).append(e["to"])
    nodes = {n["identity"]: n for n in g.get("nodes", [])}
    return nodes, adj


NODES, ADJ = _load_graph()


def _reachable(start):
    """Identidades de que 'start' depende (transitivamente), start incluído."""
    seen, stack = set(), [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(ADJ.get(cur, []))
    return seen


def _identity(a):
    lbl = a.get("labels", {})
    ann = a.get("annotations", {})
    if ann.get("identity"):
        return ann["identity"]
    inst = lbl.get("instance_name")
    if not inst:
        # alerta de nível de site (ex.: SiteUnreachable): identidade do site
        site = lbl.get("site", "?")
        return "ssle:%s:%s:-:%s" % (lbl.get("region", "pt"), site, site)
    return "ssle:%s:%s:%s:%s" % (
        lbl.get("region", "pt"), lbl.get("site", "?"),
        lbl.get("host", "?"), inst)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _correlate_site(site, alerts):
    """Escolhe a causa raiz e devolve o dicionário do incidente, ou None."""
    ids = {}
    for a in alerts:
        ids.setdefault(_identity(a), []).append(a)
    alerting = set(ids)

    cands = []
    for cand in alerting:
        explained = {m for m in alerting if cand in _reachable(m)}
        cand_down = any(x.get("labels", {}).get("alertname") in DOWN_ALERTS
                        for x in ids[cand])
        start = min((x.get("startsAt", "") for x in ids[cand]), default="~")
        cands.append((len(explained), 1 if cand_down else 0, start, cand))
    if not cands:
        return None
    # causa raiz: explica mais sintomas > está "down" > alerta mais antigo
    cands.sort(key=lambda t: (-t[0], -t[1], t[2]))
    best = cands[0][3]
    explained = {m for m in alerting if best in _reachable(m)}
    severities = [a.get("labels", {}).get("severity", "info") for a in alerts]
    sev = max(severities, key=lambda s: SEV_ORDER.get(s, 0))
    rc_node = NODES.get(best, {})
    return {
        "ts": _now(),
        "origin": "prometheus",
        "site": site,
        "severity": sev,
        "root_cause": best,
        "root_cause_instance": rc_node.get("instance_name"),
        "root_cause_role": rc_node.get("role"),
        "affected": sorted(explained),
        "alert_names": sorted({a.get("labels", {}).get("alertname", "?") for a in alerts}),
        "raw_alert_count": len(alerts),
        "incident_count": 1,
        "noise_reduction": round(len(alerts) / 1.0, 2),
    }


def _emit(incident):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as fh:
        fh.write(json.dumps(incident, ensure_ascii=False) + "\n")


def _recompute():
    by_site = {}
    for a in _active.values():
        by_site.setdefault(a.get("labels", {}).get("site", "?"), []).append(a)
    _metrics["active_alerts"] = len(_active)
    for site, alerts in by_site.items():
        inc = _correlate_site(site, alerts)
        if not inc:
            continue
        sig = (inc["root_cause"], tuple(inc["affected"]))
        if _last_sig.get(site) != sig:
            _last_sig[site] = sig
            _metrics["incidents_total"] += 1
            _metrics["last_noise_reduction"] = inc["noise_reduction"]
            _emit(inc)
    # sites que ficaram sem alertas -> fecha o incidente
    for site in list(_last_sig):
        if site not in by_site:
            _emit({"ts": _now(), "origin": "prometheus", "site": site,
                   "severity": "info", "status": "resolved",
                   "root_cause": _last_sig[site][0], "incident_count": 0})
            del _last_sig[site]


@app.route("/alerts", methods=["POST"])
def alerts():
    payload = request.get_json(force=True, silent=True) or {}
    with _lock:
        for a in payload.get("alerts", []):
            fp = a.get("fingerprint") or json.dumps(a.get("labels", {}), sort_keys=True)
            if a.get("status") == "resolved":
                _active.pop(fp, None)
            else:
                _active[fp] = a
        _recompute()
    return jsonify({"ok": True, "active": len(_active)})


@app.route("/metrics")
def metrics():
    lines = [
        "# HELP correlator_incidents_total Incidentes correlacionados (com causa raiz).",
        "# TYPE correlator_incidents_total counter",
        "correlator_incidents_total %d" % _metrics["incidents_total"],
        "# HELP correlator_active_alerts Alertas em bruto ativos no correlator.",
        "# TYPE correlator_active_alerts gauge",
        "correlator_active_alerts %d" % _metrics["active_alerts"],
        "# HELP correlator_last_noise_reduction Alertas em bruto por incidente (último).",
        "# TYPE correlator_last_noise_reduction gauge",
        "correlator_last_noise_reduction %s" % _metrics["last_noise_reduction"],
    ]
    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "nodes": len(NODES), "edges": sum(len(v) for v in ADJ.values())})


@app.route("/")
def index():
    with _lock:
        return jsonify({"active_alerts": list(_active.keys()),
                        "incidents_total": _metrics["incidents_total"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9095")))
