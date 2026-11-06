#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serviço genérico do lab (reaproveita o padrão Flask da aula 2), parametrizado
por variáveis de ambiente. Expõe o padrão RED em /metrics (Rate, Errors,
Duration) e a saúde das suas dependências (ssle_dependency_up), que é o sinal
do alerta ServiceDegraded.

  SSLE_ROLE      ingestion | sensor | web | analytics
  SSLE_INSTANCE  ex.: ing-01
  SSLE_SITE      ex.: avr
  SSLE_DEPS      "sto-01=10.10.1.40:9100,reg-01=..."  (TCP check)
  SSLE_UPSTREAM  só sensores: URL de ingestão, ex.: http://10.10.1.30:8000/ingest
  SSLE_INTERVAL  só sensores: período médio entre leituras, em s (default 5; ±20 % de jitter)
  PORT           8000

Porquê o modo sensor: é o tráfego LEGÍTIMO da frota IoT (aula 2). Dá à deteção
de anomalias uma linha de base real (sem ele, o ing-01 está a zero e o primeiro
pico só "se compara consigo próprio") e mede o impacto de um ataque do ponto de
vista do cliente (latência/erros das leituras), que é o que conta para o MTTR.
"""
import bisect, json, math, os, random, socket, threading, time
import urllib.request
from collections import defaultdict
from flask import Flask, Response, g, request

ROLE = os.environ.get("SSLE_ROLE", "service")
INSTANCE = os.environ.get("SSLE_INSTANCE", "svc-00")
SITE = os.environ.get("SSLE_SITE", "?")
DEPS = [d for d in os.environ.get("SSLE_DEPS", "").split(",") if d.strip()]
UPSTREAM = os.environ.get("SSLE_UPSTREAM", "")
INTERVAL = float(os.environ.get("SSLE_INTERVAL", "5"))

# Fronteiras dos histogramas (s). Iguais no servidor e no sensor para comparar.
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
# Pedidos que NÃO contam como carga do serviço (auto-observação).
UNCOUNTED = {"/metrics", "/healthz"}

app = Flask(__name__)
_lock = threading.Lock()
# Contadores pré-inicializados a 0: a série existe desde o arranque, por isso a
# linha de base começa a acumular antes do primeiro pedido (boa prática Prometheus).
_req = defaultdict(int, {"200": 0})   # code -> contagem
_dep_up = {}                          # dep -> 0/1
_ingested = 0                         # leituras aceites (só ingestion)
_sent = defaultdict(int, {"ok": 0, "error": 0})   # só sensor


class Histogram:
    """Histograma cumulativo mínimo no formato de exposição do Prometheus."""

    def __init__(self):
        self.counts = [0] * (len(BUCKETS) + 1)   # último = +Inf
        self.total = 0.0
        self.n = 0

    def observe(self, v):
        self.counts[bisect.bisect_left(BUCKETS, v)] += 1
        self.total += v
        self.n += 1

    def lines(self, name, labels=""):
        sep = "," if labels else ""
        out, acc = [], 0
        for le, c in zip([str(b) for b in BUCKETS] + ["+Inf"], self.counts):
            acc += c
            out.append('%s_bucket{%s%sle="%s"} %d' % (name, labels, sep, le, acc))
        lbl = "{%s}" % labels if labels else ""
        out.append("%s_sum%s %.6f" % (name, lbl, self.total))
        out.append("%s_count%s %d" % (name, lbl, self.n))
        return out


_dur = Histogram()        # latência servida (D de RED)
_up_dur = Histogram()     # latência vista pelo sensor ao enviar (impacto no cliente)


# ── RED: medir todos os pedidos num só sítio ─────────────────────────────────
@app.before_request
def _t0():
    g.t0 = time.perf_counter()


@app.after_request
def _count(resp):
    if request.path not in UNCOUNTED:
        dt = time.perf_counter() - getattr(g, "t0", time.perf_counter())
        with _lock:
            _req[str(resp.status_code)] += 1
            _dur.observe(dt)
    return resp


# ── dependências (TCP) ───────────────────────────────────────────────────────
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


# ── modo sensor: telemetria legítima para a ingestão ─────────────────────────
def _sensor_loop():
    seq = 0
    while True:
        seq += 1
        reading = {
            "sensor": INSTANCE, "site": SITE, "seq": seq, "ts": time.time(),
            # temperatura plausível: ciclo lento + ruído
            "temp_c": round(20 + 4 * math.sin(seq / 60.0) + random.uniform(-0.4, 0.4), 2),
        }
        t0 = time.perf_counter()
        result = "ok"
        try:
            req = urllib.request.Request(
                UPSTREAM, data=json.dumps(reading).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
        except Exception:
            result = "error"
        with _lock:
            _sent[result] += 1
            _up_dur.observe(time.perf_counter() - t0)
        time.sleep(INTERVAL * random.uniform(0.8, 1.2))


# ── rotas ────────────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return "ok %s@%s\n" % (INSTANCE, SITE)


@app.route("/ingest", methods=["POST"])
def ingest():
    global _ingested
    data = request.get_json(silent=True) or {}
    if "temp_c" not in data:
        return "leitura inválida\n", 400
    with _lock:
        _ingested += 1
    return "stored\n", 201


@app.route("/work")
def work():
    # endpoint deliberadamente caro (para a PoC de DoS, aula 7)
    t0 = time.time()
    x = 0
    for i in range(200000):
        x += i * i
    return "done in %.3fs\n" % (time.time() - t0)


@app.route("/metrics")
def metrics():
    with _lock:
        lines = [
            "# HELP http_requests_total Pedidos HTTP servidos, por código (sem /metrics e /healthz).",
            "# TYPE http_requests_total counter",
        ]
        for code, n in sorted(_req.items()):
            lines.append('http_requests_total{code="%s"} %d' % (code, n))
        lines += [
            "# HELP http_request_duration_seconds Latência servida (D de RED).",
            "# TYPE http_request_duration_seconds histogram",
        ] + _dur.lines("http_request_duration_seconds")
        lines += [
            "# HELP ssle_dependency_up Dependência alcançável (1) ou não (0).",
            "# TYPE ssle_dependency_up gauge",
        ]
        for dep, up in sorted(_dep_up.items()):
            lines.append('ssle_dependency_up{dep="%s"} %d' % (dep, up))
        if ROLE == "ingestion":
            lines += [
                "# HELP ssle_ingest_readings_total Leituras de sensores aceites.",
                "# TYPE ssle_ingest_readings_total counter",
                "ssle_ingest_readings_total %d" % _ingested,
            ]
        if UPSTREAM:
            lines += [
                "# HELP ssle_sensor_readings_total Leituras enviadas pelo sensor, por resultado.",
                "# TYPE ssle_sensor_readings_total counter",
            ]
            for res, n in sorted(_sent.items()):
                lines.append('ssle_sensor_readings_total{result="%s"} %d' % (res, n))
            lines += [
                "# HELP ssle_sensor_upstream_duration_seconds Latência do envio vista pelo sensor.",
                "# TYPE ssle_sensor_upstream_duration_seconds histogram",
            ] + _up_dur.lines("ssle_sensor_upstream_duration_seconds")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    return "ok\n"


if DEPS:
    threading.Thread(target=_probe_loop, daemon=True).start()
if UPSTREAM:
    threading.Thread(target=_sensor_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), threaded=True)
