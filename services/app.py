#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generic lab service, parameterised by environment variables. Exposes the RED
pattern at /metrics (Rate, Errors, Duration) and the health of its dependencies
(ssle_dependency_up), which is the signal for the ServiceDegraded alert.

  SSLE_ROLE      ingestion | sensor | web | analytics
  SSLE_INSTANCE  e.g. ing-01
  SSLE_SITE      e.g. avr
  SSLE_DEPS      "sto-01=10.10.1.40:9100,reg-01=..."  (TCP check)
  SSLE_UPSTREAM  sensors only: ingestion URL, e.g. http://10.10.1.30:8000/ingest
  SSLE_INTERVAL  sensors only: mean reading interval in s (default 5; ±20 % jitter)
  SSLE_REGISTRY  DYNAMIC elements only (outside inventory): site reg-01 URL, e.g.
                 http://10.10.2.20:5050 — registers and renews the lease every 10 s (registry/)
  SSLE_REGISTRY_TOKEN_FILE  site write token (default /etc/ssle/registry.token)
  SSLE_IP        IP used for registration (the registry verifies it belongs to the site subnet)
  SSLE_ACCESS_LOG  optional: access log in Apache "combined" format (what the Wazuh web-accesslog
                 decoder recognises; werkzeug's format is not), rotated at 10 MiB × 2 — the Wazuh
                 agent reads it (T1)
  PORT           8000

Why sensor mode: it is the LEGITIMATE IoT fleet traffic. It gives anomaly detection a real
baseline (without it, ing-01 sits at zero and the first spike only "compares with itself") and
measures the impact of an attack from the client's perspective (reading latency/errors), which is
what matters for MTTR.
"""
import bisect, json, logging, logging.handlers, math, os, random, socket, threading, time
import urllib.request
from collections import defaultdict
from flask import Flask, Response, g, request

ROLE = os.environ.get("SSLE_ROLE", "service")
INSTANCE = os.environ.get("SSLE_INSTANCE", "svc-00")
SITE = os.environ.get("SSLE_SITE", "?")
DEPS = [d for d in os.environ.get("SSLE_DEPS", "").split(",") if d.strip()]
UPSTREAM = os.environ.get("SSLE_UPSTREAM", "")
INTERVAL = float(os.environ.get("SSLE_INTERVAL", "5"))
REGISTRY = os.environ.get("SSLE_REGISTRY", "").rstrip("/")
REGISTRY_TOKEN_FILE = os.environ.get("SSLE_REGISTRY_TOKEN_FILE", "/etc/ssle/registry.token")
MY_IP = os.environ.get("SSLE_IP", "")
ACCESS_LOG = os.environ.get("SSLE_ACCESS_LOG", "")

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
UNCOUNTED = {"/metrics", "/healthz"}

app = Flask(__name__)
_access = None
if ACCESS_LOG:
    _access = logging.getLogger("ssle.access")
    _access.propagate = False
    _access.setLevel(logging.INFO)
    _h = logging.handlers.RotatingFileHandler(ACCESS_LOG, maxBytes=10 << 20, backupCount=2)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _access.addHandler(_h)
_lock = threading.Lock()
_req = defaultdict(int, {"200": 0})
_dep_up = {}
_ingested = 0
_sent = defaultdict(int, {"ok": 0, "error": 0})


class Histogram:
    """Minimal cumulative histogram in Prometheus exposition format."""

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


_dur = Histogram()
_up_dur = Histogram()


# ── RED ──────────────────────────────────────────────────────────────────────
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
        if _access:
            _access.info('%s - - [%s] "%s %s %s" %d %s "-" "%s"', request.remote_addr,
                         time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime()), request.method,
                         request.path, request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"), resp.status_code,
                         resp.calculate_content_length() or "-", request.user_agent.string or "-")
    return resp


# ── dependencies (TCP) ───────────────────────────────────────────────────────
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


# ── sensor mode: legitimate telemetry to ingestion ───────────────────────────
def _sensor_loop():
    seq = 0
    while True:
        seq += 1
        reading = {
            "sensor": INSTANCE, "site": SITE, "seq": seq, "ts": time.time(),
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


# ── dynamic registration on the site reg-01 (TTL lease; heartbeat every 10 s) ──
def _registry_loop():
    try:
        with open(REGISTRY_TOKEN_FILE) as fh:
            token = fh.read().strip()
    except OSError:
        token = ""
    body = json.dumps({"name": INSTANCE, "role": ROLE, "site": SITE, "ip": MY_IP}).encode()
    while True:
        try:
            req = urllib.request.Request(
                REGISTRY + "/register", data=body, method="POST",
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
            with urllib.request.urlopen(req, timeout=3) as r:
                r.read()
        except Exception:
            pass
        time.sleep(10)


# ── routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return "ok %s@%s\n" % (INSTANCE, SITE)


@app.route("/ingest", methods=["POST"])
def ingest():
    global _ingested
    data = request.get_json(silent=True) or {}
    if "temp_c" not in data:
        return "invalid reading\n", 400
    with _lock:
        _ingested += 1
    return "stored\n", 201


@app.route("/work")
def work():
    t0 = time.time()
    x = 0
    for i in range(200000):
        x += i * i
    return "done in %.3fs\n" % (time.time() - t0)


@app.route("/metrics")
def metrics():
    with _lock:
        lines = [
            "# HELP http_requests_total HTTP requests served, by code (excluding /metrics and /healthz).",
            "# TYPE http_requests_total counter",
        ]
        for code, n in sorted(_req.items()):
            lines.append('http_requests_total{code="%s"} %d' % (code, n))
        lines += [
            "# HELP http_request_duration_seconds Served latency (D of RED).",
            "# TYPE http_request_duration_seconds histogram",
        ] + _dur.lines("http_request_duration_seconds")
        lines += [
            "# HELP ssle_dependency_up Dependency reachable (1) or not (0).",
            "# TYPE ssle_dependency_up gauge",
        ]
        for dep, up in sorted(_dep_up.items()):
            lines.append('ssle_dependency_up{dep="%s"} %d' % (dep, up))
        if ROLE == "ingestion":
            lines += [
                "# HELP ssle_ingest_readings_total Sensor readings accepted.",
                "# TYPE ssle_ingest_readings_total counter",
                "ssle_ingest_readings_total %d" % _ingested,
            ]
        if UPSTREAM:
            lines += [
                "# HELP ssle_sensor_readings_total Readings sent by the sensor, by result.",
                "# TYPE ssle_sensor_readings_total counter",
            ]
            for res, n in sorted(_sent.items()):
                lines.append('ssle_sensor_readings_total{result="%s"} %d' % (res, n))
            lines += [
                "# HELP ssle_sensor_upstream_duration_seconds Upstream send latency as seen by the sensor.",
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
if REGISTRY and MY_IP:
    threading.Thread(target=_registry_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host=os.environ.get("BIND", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")), threaded=True)
