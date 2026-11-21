#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Correlator (RCA) for Project 1 (SSLE) — HTTP layer.

Receives alerts from Alertmanager (webhook), passes them to the rca.py core (root cause via
greedy set cover on the dependency graph, ACROSS sites) and writes ONE JSON line per
opened/updated/resolved incident to /var/log/ssle/incidents.json (read by the Wazuh agent on
core/obs — siem/shared/core/agent.conf). Exposes metrics at /metrics for the global Prometheus.

A ticker calls the core every TICK s: without it, an incident waiting for the settle window
(CORRELATOR_SETTLE) would only be emitted on the next webhook (Alertmanager resends every
group_interval = 30 s).

Depends only on Flask (stdlib + flask). Text metrics, no prometheus_client.
"""
import json, os, sys, threading, time
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rca import Graph, Correlator  # noqa: E402

GRAPH_PATH = os.environ.get("CORRELATOR_GRAPH", "/opt/correlator/graph.json")
LOG_PATH = os.environ.get("CORRELATOR_LOG", "/var/log/ssle/incidents.json")
SETTLE_S = int(os.environ.get("CORRELATOR_SETTLE", "30"))
TICK_S = 5

app = Flask(__name__)
_lock = threading.Lock()
GRAPH = Graph.load(GRAPH_PATH)


def _emit(incident):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as fh:
        fh.write(json.dumps(incident, ensure_ascii=False) + "\n")


CORR = Correlator(GRAPH, _emit, settle_s=SETTLE_S)


def _ticker():
    while True:
        time.sleep(TICK_S)
        with _lock:
            CORR.tick()


@app.route("/alerts", methods=["POST"])
def alerts():
    payload = request.get_json(force=True, silent=True) or {}
    with _lock:
        CORR.ingest(payload)
        return jsonify({"ok": True, "active": len(CORR.active)})


@app.route("/metrics")
def metrics():
    with _lock:
        m = dict(CORR.metrics)
    lines = [
        "# HELP correlator_incidents_total Correlated incidents (with root cause) opened since start.",
        "# TYPE correlator_incidents_total counter",
        "correlator_incidents_total %d" % m["incidents_total"],
        "# HELP correlator_active_alerts Raw alerts currently active in the correlator.",
        "# TYPE correlator_active_alerts gauge",
        "correlator_active_alerts %d" % m["active_alerts"],
        "# HELP correlator_open_incidents Incidents open (emitted and not yet resolved).",
        "# TYPE correlator_open_incidents gauge",
        "correlator_open_incidents %d" % m["open_incidents"],
        "# HELP correlator_pending_incidents Incidents waiting for the settle window.",
        "# TYPE correlator_pending_incidents gauge",
        "correlator_pending_incidents %d" % m["pending_incidents"],
        "# HELP correlator_last_noise_reduction Raw alerts per incident (last emitted).",
        "# TYPE correlator_last_noise_reduction gauge",
        "correlator_last_noise_reduction %s" % m["last_noise_reduction"],
    ]
    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "nodes": len(GRAPH.nodes), "settle_s": SETTLE_S,
                    "edges": sum(len(v) for v in GRAPH.adj.values())})


@app.route("/")
def index():
    with _lock:
        return jsonify({"active_alerts": list(CORR.active.keys()),
                        "open_incidents": CORR.open and {k: v["id"] for k, v in CORR.open.items()},
                        "incidents_total": CORR.metrics["incidents_total"]})


threading.Thread(target=_ticker, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9095")))
