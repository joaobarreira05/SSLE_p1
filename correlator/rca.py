#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Núcleo da correlação para causa raiz (RCA) do Projeto 1 (SSLE) — só stdlib, testável sem Flask
(testes em correlator/test_rca.py).

Modelo: o grafo de dependências do inventário (build/graph.json). Um alerta é um SINTOMA num nó
(identidade ssle:<region>:<site>:<host>:<inst>). Um candidato C "explica" o sintoma em M se M depende
de C, direta ou transitivamente (ou se C == M). Além das arestas do inventário, cada nó depende
implicitamente do seu SITE — o pseudo-nó ssle:<region>:<site>:-:<site>, que é a identidade do alerta
SiteUnreachable (o site inteiro deixou de responder ao core).

Escolha das causas raiz = COBERTURA GULOSA (greedy set cover) dos sintomas ativos: escolhe o candidato
que explica mais sintomas ainda por explicar (desempate: tem um alerta "down" > alerta mais antigo),
retira esses sintomas e repete até não sobrar nenhum. Consequências:
  - a correlação ATRAVESSA SITES (sen-01@opo depende de ing-01@avr): o grafo não tem fronteiras;
  - duas falhas independentes dão DOIS incidentes (nenhum sintoma fica de fora de um incidente);
  - cada sintoma pertence a exatamente um incidente.

Estabilização (settle): uma causa raiz NOVA só é emitida quando o sintoma mais antigo do seu
incidente já está ativo há CORRELATOR_SETTLE segundos. Sem isto, se o sintoma do cliente (sensor em
opo) chegasse uns segundos antes do alerta do servidor (ing-01 em avr), sairia um incidente com causa
raiz no SENSOR — e a regra Wazuh 110210 trata "sensor é causa raiz" como candidato a quarentena.
Custo: o MTTD no SOC sobe até SETTLE segundos. É uma troca escolhida (precisão > rapidez).
"""
import json, time
from datetime import datetime, timezone

DOWN_ALERTS = {"ElementDown", "ServiceDown", "SiteUnreachable"}
SEV_ORDER = {"critical": 3, "warning": 2, "info": 1}


def site_identity(region, site):
    return "ssle:%s:%s:-:%s" % (region, site, site)


def _parts(identity):
    """ssle:<region>:<site>:<host>:<inst> -> dict (tolerante a identidades estranhas)."""
    p = identity.split(":")
    if len(p) == 5 and p[0] == "ssle":
        return {"region": p[1], "site": p[2], "host": p[3], "instance": p[4]}
    return {"region": "?", "site": "?", "host": "?", "instance": identity}


class Graph:
    def __init__(self, doc):
        self.nodes = {n["identity"]: n for n in doc.get("nodes", [])}
        self.adj = {}                                  # dependente -> {dependências}
        for e in doc.get("edges", []):
            self.adj.setdefault(e["from"], set()).add(e["to"])
        for ident in self.nodes:                       # dependência implícita do próprio site
            p = _parts(ident)
            self.adj.setdefault(ident, set()).add(site_identity(p["region"], p["site"]))

    @classmethod
    def load(cls, path):
        try:
            with open(path) as fh:
                return cls(json.load(fh))
        except (OSError, ValueError):
            return cls({})

    def depends_on(self, start):
        """Identidades de que 'start' depende (transitivamente), start incluído."""
        seen, stack = set(), [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self.adj.get(cur, ()))
        return seen

    def describe(self, identity):
        """(instância, papel) do nó; pseudo-nó de site -> (site, 'site')."""
        n = self.nodes.get(identity)
        if n:
            return n.get("instance_name"), n.get("role")
        p = _parts(identity)
        if p["host"] == "-":
            return p["site"], "site"
        return p["instance"], None


def alert_identity(a):
    lbl = a.get("labels", {})
    ann = a.get("annotations", {})
    if ann.get("identity"):
        return ann["identity"]
    inst = lbl.get("instance_name")
    if not inst:
        # alerta de nível de site (ex.: SiteUnreachable): identidade do site
        return site_identity(lbl.get("region", "pt"), lbl.get("site", "?"))
    return "ssle:%s:%s:%s:%s" % (lbl.get("region", "pt"), lbl.get("site", "?"), lbl.get("host", "?"), inst)


def root_causes(alerts, graph):
    """Cobertura gulosa: [(causa_raiz, {identidades explicadas}, [alertas])], por ordem de escolha."""
    by_id = {}
    for a in alerts:
        by_id.setdefault(alert_identity(a), []).append(a)
    deps = {m: graph.depends_on(m) for m in by_id}
    remaining = set(by_id)
    out = []
    while remaining:
        best = None
        for cand in by_id:                              # só nós COM alerta são candidatos
            explained = {m for m in remaining if cand in deps[m]}
            if not explained:
                continue
            down = any(x.get("labels", {}).get("alertname") in DOWN_ALERTS for x in by_id[cand])
            start = min((x.get("startsAt", "") for x in by_id[cand]), default="~")
            key = (-len(explained), 0 if down else 1, start, cand)
            if best is None or key < best[0]:
                best = (key, cand, explained)
        _, cand, explained = best
        out.append((cand, explained, [a for m in sorted(explained) for a in by_id[m]]))
        remaining -= explained
    return out


def _now_iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class Correlator:
    """Estado: alertas ativos (do webhook do Alertmanager) -> incidentes emitidos (1 linha JSON cada)."""

    def __init__(self, graph, emit, settle_s=30, clock=time.time):
        self.graph, self.emit, self.settle, self.clock = graph, emit, settle_s, clock
        self.active = {}        # fingerprint -> alerta
        self.arrived = {}       # fingerprint -> 1.º instante em que o vimos ativo
        self.open = {}          # causa raiz -> {"sig":…, "id":…}
        self.metrics = {"incidents_total": 0, "active_alerts": 0, "open_incidents": 0,
                        "pending_incidents": 0, "last_noise_reduction": 0.0}

    @staticmethod
    def _fp(a):
        return a.get("fingerprint") or json.dumps(a.get("labels", {}), sort_keys=True)

    def ingest(self, payload):
        now = self.clock()
        for a in payload.get("alerts", []):
            fp = self._fp(a)
            if a.get("status") == "resolved":
                self.active.pop(fp, None)
                self.arrived.pop(fp, None)
            else:
                self.active[fp] = a
                self.arrived.setdefault(fp, now)
        self.tick()

    def tick(self):
        now = self.clock()
        groups = root_causes(list(self.active.values()), self.graph)
        current, pending = set(), 0
        for root, explained, alerts in groups:
            oldest = min(self.arrived.get(self._fp(a), now) for a in alerts)
            if root not in self.open and now - oldest < self.settle:
                pending += 1                            # à espera de sintomas relacionados
                continue
            current.add(root)
            inc = self._incident(root, explained, alerts, now)
            sig = (tuple(inc["affected"]), inc["severity"])
            prev = self.open.get(root)
            if prev is None or prev["sig"] != sig:
                inc["incident_id"] = prev["id"] if prev else "%s@%d" % (root, int(now))
                inc["status"] = "updated" if prev else "open"
                self.open[root] = {"sig": sig, "id": inc["incident_id"], "site": inc["site"],
                                   "instance": inc["root_cause_instance"]}
                self.metrics["incidents_total"] += 0 if prev else 1
                self.metrics["last_noise_reduction"] = inc["noise_reduction"]
                self.emit(inc)
        for root in [r for r in self.open if r not in current]:
            o = self.open.pop(root)
            self.emit({"ts": _now_iso(now), "origin": "prometheus", "site": o["site"], "severity": "info",
                       "status": "resolved", "root_cause": root, "root_cause_instance": o["instance"],
                       "incident_id": o["id"], "incident_count": 0})
        self.metrics.update(active_alerts=len(self.active), open_incidents=len(self.open),
                            pending_incidents=pending)

    def _incident(self, root, explained, alerts, now):
        inst, role = self.graph.describe(root)
        sev = max((a.get("labels", {}).get("severity", "info") for a in alerts),
                  key=lambda s: SEV_ORDER.get(s, 0))
        sites = sorted({_parts(m)["site"] for m in explained})
        return {
            "ts": _now_iso(now),
            "origin": "prometheus",
            "site": _parts(root)["site"],               # site da CAUSA RAIZ (é onde se responde)
            "sites": sites,
            "cross_site": len(sites) > 1,
            "severity": sev,
            "root_cause": root,
            "root_cause_instance": inst,
            "root_cause_role": role,
            "affected": sorted(explained),
            "alert_names": sorted({a.get("labels", {}).get("alertname", "?") for a in alerts}),
            "raw_alert_count": len(alerts),
            "incident_count": 1,
            "noise_reduction": round(len(alerts) / 1.0, 2),
        }
