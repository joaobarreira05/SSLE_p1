#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serviço genérico do lab (reaproveita o padrão Flask da aula 2), parametrizado
por variáveis de ambiente. Expõe o padrão RED em /metrics e a saúde das suas
dependências (ssle_dependency_up), que é o sinal do alerta ServiceDegraded.

  SSLE_ROLE      ingestion | sensor | web | analytics
  SSLE_INSTANCE  ex.: ing-01
  SSLE_SITE      ex.: avr
  SSLE_DEPS      "sto-01=10.10.1.40:9100,reg-01=..."  (TCP check)
  PORT           8000
"""
import os, socket, threading, time
from collections import defaultdict
from flask import Flask, Response, request

ROLE = os.environ.get("SSLE_ROLE", "service")
INSTANCE = os.environ.get("SSLE_INSTANCE", "svc-00")
SITE = os.environ.get("SSLE_SITE", "?")
DEPS = [d for d in os.environ.get("SSLE_DEPS", "").split(",") if d.strip()]

app = Flask(__name__)
_lock = threading.Lock()
_req = defaultdict(int)          # code -> contagem
_dep_up = {}                     # dep -> 0/1


def _parse_deps():
    out = []
    for d in DEPS:
        name, _, hp = d.partition("=")
        host, _, port = hp.partition(":")
        out.append((name.strip(), host.strip(), int(port or "9100")))
    return out


def _probe_loop():
    deps = _parse_deps()
    for name, _, _ in deps:
        _dep_up[name] = 1
    while True:
        for name, host, port in deps:
            ok = 0
            try:
                with socket.create_connection((host, port), timeout=2):
                    ok = 1
            except OSError:
                ok = 0
            with _lock:
                _dep_up[name] = ok
        time.sleep(5)


@app.route("/")
def root():
    with _lock:
        _req["200"] += 1
    return "ok %s@%s\n" % (INSTANCE, SITE)


@app.route("/work")
def work():
    # endpoint deliberadamente caro (para a PoC de DoS, aula 7)
    t0 = time.time()
    x = 0
    for i in range(200000):
        x += i * i
    with _lock:
        _req["200"] += 1
    return "done in %.3fs\n" % (time.time() - t0)


@app.route("/metrics")
def metrics():
    with _lock:
        lines = [
            "# HELP http_requests_total Pedidos HTTP por código.",
            "# TYPE http_requests_total counter",
        ]
        for code, n in sorted(_req.items()):
            lines.append('http_requests_total{code="%s"} %d' % (code, n))
        lines += [
            "# HELP ssle_dependency_up Dependência alcançável (1) ou não (0).",
            "# TYPE ssle_dependency_up gauge",
        ]
        for dep, up in sorted(_dep_up.items()):
            lines.append('ssle_dependency_up{dep="%s"} %d' % (dep, up))
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    return "ok\n"


if DEPS:
    threading.Thread(target=_probe_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
