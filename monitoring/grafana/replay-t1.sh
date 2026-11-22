#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# REPLAY of the T1 evidence (staging, 06/11) on the ssle-t1 dashboard → PNG figures for the report.
#
#   bash monitoring/grafana/replay-t1.sh [run=1]     → report/figures/t1-replay-run<N>-*.png
#
# 1) converts threats/t1-ddos/evidence/run-*/ (Prometheus JSON responses at 5 s) to OpenMetrics;
# 2) backfills a local TSDB (promtool tsdb create-blocks-from openmetrics) served by a
#    Prometheus 2.53.5 on 127.0.0.1 (no scraping);
# 3) Grafana 11.6.1 on 127.0.0.1 with the SAME datasources/dashboards as the lab (all → that Prometheus);
# 4) headless screenshots (chromium, temporary profile) of the window T0−2 min … T0+7 min.
#
# ⚠️ It is a replay, not a new measurement: the series are the saved ones; the sensor p95 and readings were
# expression results and get sen-01 labels here (the only staging sensor); the robust z is recomputed
# over the saved window (< 1 h of baseline); ClientLatencySLO did not exist yet on 06/11, so it does not
# appear in the rule state. The figures say "replay staging 06/11" in the caption.
# For live figures from the lab see shot-live.sh.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="${1:-1}"; EV="$ROOT/threats/t1-ddos/evidence"
T="$ROOT/build/tools"; G="$T/grafana"; W="$(mktemp -d)"; FIG="$ROOT/report/figures"
PROM=127.0.0.1:19091; GPORT=13001
mkdir -p "$FIG"
PIDS=()
cleanup() { local p; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT

echo "[replay] 1) evidence → OpenMetrics"
python3 -I - "$EV" > "$W/t1.om" <<'PY'
import glob, json, os, sys
ev = sys.argv[1]
SEN = {"region": "pt", "site": "opo", "host": "mac-m2", "instance_name": "sen-01", "role": "sensor",
       "service": "sensor", "team": "ops-opo"}
fam = {}                                     # name -> {labels(tuple) -> {ts: v}}
def add(name, labels, values):
    s = fam.setdefault(name, {}).setdefault(tuple(sorted(labels.items())), {})
    for ts, v in values:
        if v not in ("NaN", "+Inf", "-Inf"):
            s[float(ts)] = float(v)
for run in sorted(glob.glob(os.path.join(ev, "run-*"))):
    for f in glob.glob(os.path.join(run, "*.json")):
        base = os.path.basename(f)[:-5]
        if base == "summary":
            continue
        doc = json.load(open(f))
        if not isinstance(doc, dict):
            continue                         # e.g. alerts-before.json (Alertmanager list)
        for s in doc.get("data", {}).get("result", []):
            m = dict(s["metric"])
            name = m.pop("__name__", None)
            if base == "p95-sensor":
                name, m = "instance:ssle_sensor_upstream_duration_seconds:p95_1m", dict(SEN)
            elif base == "sensor-readings":
                name, m = "ssle_sensor_readings_total", dict(SEN, result=m["result"])
            if not name:
                continue                     # z-meanstd/z-robust: the dashboard recomputes them
            add(name, m, s["values"])
def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')
for name, series in sorted(fam.items()):
    print("# TYPE %s gauge" % name)
    for labels, pts in sorted(series.items()):
        lbl = ",".join('%s="%s"' % (k, esc(v)) for k, v in labels)
        for ts in sorted(pts):
            print("%s{%s} %r %.3f" % (name, lbl, pts[ts], ts))
print("# EOF")
PY
echo "      $(grep -c '^# TYPE' "$W/t1.om") families, $(grep -vc '^#' "$W/t1.om") samples"

echo "[replay] 2) backfill + Prometheus on $PROM"
"$T/promtool-2" tsdb create-blocks-from openmetrics "$W/t1.om" "$W/tsdb" >/dev/null
printf 'global: {scrape_interval: 15s}\n' > "$W/prom.yml"
# 15 s lookback: the backfill brings no "staleness markers", so with the default 5 min a resolved
# alert would keep showing for 5 more minutes (in the lab Prometheus writes them; samples here are at 5 s)
"$T/prometheus-2" --config.file="$W/prom.yml" --storage.tsdb.path="$W/tsdb" --storage.tsdb.retention.time=10y \
  --query.lookback-delta=15s --web.listen-address="$PROM" > "$W/prom.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 30); do curl -sf "http://$PROM/-/ready" >/dev/null && break; sleep 0.5; done

echo "[replay] 3) Grafana on 127.0.0.1:$GPORT (anonymous read-only, only in this local replay)"
mkdir -p "$W/prov/datasources" "$W/prov/dashboards" "$W/prov/plugins" "$W/prov/alerting" "$W/gdata"
python3 "$ROOT/infra/inventory.py" grafana --host t490 \
  | sed -E "s#url: 'http://[0-9.]+:9090'#url: 'http://$PROM'#; s#localhost:9090#$PROM#; s#localhost:9093#127.0.0.1:19093#" \
  > "$W/prov/datasources/ssle.yml"
sed "s#/var/lib/grafana/dashboards/ssle#$ROOT/monitoring/grafana/dashboards#" "$ROOT/monitoring/grafana/providers/ssle.yml" \
  > "$W/prov/dashboards/ssle.yml"
cat > "$W/grafana.ini" <<INI
[server]
http_addr = 127.0.0.1
http_port = $GPORT
[paths]
data = $W/gdata
logs = $W/gdata/log
plugins = $W/gdata/plugins
provisioning = $W/prov
[auth.anonymous]
enabled = true
org_role = Viewer
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[news]
news_feed_enabled = false
INI
"$G/bin/grafana" server --homepath "$G" --config "$W/grafana.ini" > "$W/grafana.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$GPORT/api/health" >/dev/null && break; sleep 1; done
sleep 3

# shellcheck disable=SC1090
. "$EV/run-$RUN/times.env"
FROM=$(( (${T0%.*} - 120) * 1000 )); TO=$(( (${T0%.*} + 420) * 1000 ))
shot() {  # shot <file> <width> <height> <path+query>
  TZ=Europe/Lisbon chromium --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$W/chrome" \
    --window-size="$2,$3" --virtual-time-budget=25000 --screenshot="$1" \
    "http://127.0.0.1:$GPORT$4&from=$FROM&to=$TO&theme=light" >/dev/null 2>&1
  echo "      $(basename "$1") ($(du -h "$1" | cut -f1))"
}
echo "[replay] 4) screenshots (run-$RUN, T0=$(TZ=Europe/Lisbon date -d "@${T0%.*}" '+%d/%m %H:%M:%S'))"
shot "$FIG/t1-replay-run$RUN-dashboard.png" 1600 990 "/d/ssle-t1/?orgId=1&kiosk"
shot "$FIG/t1-replay-run$RUN-latency.png" 1100 480 "/d-solo/ssle-t1/?orgId=1&panelId=3"
shot "$FIG/t1-replay-run$RUN-rules.png" 1100 360 "/d-solo/ssle-t1/?orgId=1&panelId=4"
echo "RESULT: figures in report/figures/ (replay of the staging evidence, run-$RUN)"
