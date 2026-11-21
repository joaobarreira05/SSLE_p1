#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Root-cause correlation (RCA) core for Project 1 (SSLE) — stdlib only, testable without Flask
(tests in correlator/test_rca.py).

Model: the dependency graph from the inventory (build/graph.json). An alert is a SYMPTOM on a node
(identity ssle:<region>:<site>:<host>:<inst>). A candidate C "explains" the symptom on M if M depends
on C, directly or transitively (or if C == M). Besides inventory edges, each node implicitly depends
on its SITE — the pseudo-node ssle:<region>:<site>:-:<site>, which is the identity of the
SiteUnreachable alert (the entire site stopped responding to core).

Root cause selection = GREEDY SET COVER of active symptoms: picks the candidate that explains the most
unexplained symptoms (tiebreak: has a "down" alert > oldest alert), removes those symptoms and repeats
until none remain. Consequences:
  - correlation CROSSES SITES (sen-01@opo depends on ing-01@avr): the graph has no boundaries;
  - two independent failures yield TWO incidents (no symptom is left out of an incident);
  - each symptom belongs to exactly one incident.

Settle: a NEW root cause is only emitted when the oldest symptom in its incident has been active for
CORRELATOR_SETTLE seconds. Without this, if the client symptom (sensor in opo) arrived a few seconds
before the server alert (ing-01 in avr), an incident with root cause on the SENSOR would be emitted —
and Wazuh rule 110210 treats "sensor is root cause" as a quarantine candidate.
Cost: SOC MTTD rises by up to SETTLE seconds. This is a chosen trade-off (precision > speed).
"""
import json, time
from datetime import datetime, timezone

DOWN_ALERTS = {"ElementDown", "ServiceDown", "SiteUnreachable"}
SEV_ORDER = {"critical": 3, "warning": 2, "info": 1}


def site_identity(region, site):
    return "ssle:%s:%s:-:%s" % (region, site, site)


def _parts(identity):
    """ssle:<region>:<site>:<host>:<inst> -> dict (tolerant of unknown identities)."""
    p = identity.split(":")
    if len(p) == 5 and p[0] == "ssle":
        return {"region": p[1], "site": p[2], "host": p[3], "instance": p[4]}
    return {"region": "?", "site": "?", "host": "?", "instance": identity}


class Graph:
    def __init__(self, doc):
        self.nodes = {n["identity"]: n for n in doc.get("nodes", [])}
        self.adj = {}
        for e in doc.get("edges", []):
            self.adj.setdefault(e["from"], set()).add(e["to"])
        for ident in self.nodes:
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
        """Identities that 'start' depends on (transitively), start included."""
        seen, stack = set(), [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self.adj.get(cur, ()))
        return seen

    def ip(self, identity):
        """Node IP from the inventory (None for site pseudo-nodes or unknown identities)."""
        return (self.nodes.get(identity) or {}).get("ip")

    def describe(self, identity):
        """(instance, role) of the node; site pseudo-node -> (site, 'site')."""
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
        return site_identity(lbl.get("region", "pt"), lbl.get("site", "?"))
    return "ssle:%s:%s:%s:%s" % (lbl.get("region", "pt"), lbl.get("site", "?"), lbl.get("host", "?"), inst)


def root_causes(alerts, graph):
    """Greedy set cover: [(root_cause, {explained identities}, [alerts])], in selection order."""
    by_id = {}
    for a in alerts:
        by_id.setdefault(alert_identity(a), []).append(a)
    deps = {m: graph.depends_on(m) for m in by_id}
    remaining = set(by_id)
    out = []
    while remaining:
        best = None
        for cand in by_id:
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
    """State: active alerts (from Alertmanager webhook) -> emitted incidents (1 JSON line each)."""

    def __init__(self, graph, emit, settle_s=30, clock=time.time):
        self.graph, self.emit, self.settle, self.clock = graph, emit, settle_s, clock
        self.active = {}
        self.arrived = {}
        self.open = {}
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
                pending += 1
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
            self.emit(dict({"ts": _now_iso(now), "origin": "prometheus", "site": o["site"], "severity": "info",
                            "status": "resolved", "root_cause": root, "root_cause_instance": o["instance"],
                            "incident_id": o["id"], "incident_count": 0}, **self._ip_fields(root)))
        self.metrics.update(active_alerts=len(self.active), open_incidents=len(self.open),
                            pending_incidents=pending)

    def _ip_fields(self, root):
        ip = self.graph.ip(root)
        return {"root_cause_ip": ip, "srcip": ip} if ip else {}

    def _incident(self, root, explained, alerts, now):
        inst, role = self.graph.describe(root)
        sev = max((a.get("labels", {}).get("severity", "info") for a in alerts),
                  key=lambda s: SEV_ORDER.get(s, 0))
        sites = sorted({_parts(m)["site"] for m in explained})
        return dict({
            "ts": _now_iso(now),
            "origin": "prometheus",
            "site": _parts(root)["site"],
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
        }, **self._ip_fields(root))
