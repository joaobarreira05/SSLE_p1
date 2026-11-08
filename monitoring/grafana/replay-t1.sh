#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# REPLAY da evidência da T1 (staging, 06/11) no dashboard ssle-t1 → figuras PNG para o relatório.
#
#   bash monitoring/grafana/replay-t1.sh [run=1]     → report/figures/t1-replay-run<N>-*.png
#
# 1) converte threats/t1-ddos/evidence/run-*/ (respostas JSON do Prometheus a 5 s) em OpenMetrics;
# 2) backfill num TSDB local (promtool tsdb create-blocks-from openmetrics) servido por um
#    Prometheus 2.53.5 em 127.0.0.1 (sem scrape);
# 3) Grafana 11.6.1 em 127.0.0.1 com as MESMAS datasources/dashboards do lab (todas → esse Prometheus);
# 4) screenshots headless (chromium, perfil temporário) da janela T0−2 min … T0+7 min.
#
# ⚠️ É um replay, não uma medição nova: as séries são as guardadas; o p95 do sensor e as leituras eram
# resultados de expressões e recebem aqui as labels do sen-01 (o único sensor do staging); o z robusto é
# recalculado sobre a janela guardada (< 1 h de baseline); o ClientLatencySLO ainda não existia a 06/11,
# por isso não aparece no estado das regras. As figuras dizem "replay staging 06/11" na legenda.
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

echo "[replay] 1) evidência → OpenMetrics"
python3 -I - "$EV" > "$W/t1.om" <<'PY'
import glob, json, os, sys
ev = sys.argv[1]
SEN = {"region": "pt", "site": "opo", "host": "mac-m2", "instance_name": "sen-01", "role": "sensor",
       "service": "sensor", "team": "ops-opo"}
fam = {}                                     # nome -> {labels(tuple) -> {ts: v}}
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
            continue                         # p.ex. alerts-before.json (lista do Alertmanager)
        for s in doc.get("data", {}).get("result", []):
            m = dict(s["metric"])
            name = m.pop("__name__", None)
            if base == "p95-sensor":
                name, m = "instance:ssle_sensor_upstream_duration_seconds:p95_1m", dict(SEN)
            elif base == "sensor-readings":
                name, m = "ssle_sensor_readings_total", dict(SEN, result=m["result"])
            if not name:
                continue                     # z-meanstd/z-robust: o dashboard recalcula-os
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
echo "      $(grep -c '^# TYPE' "$W/t1.om") famílias, $(grep -vc '^#' "$W/t1.om") amostras"

echo "[replay] 2) backfill + Prometheus em $PROM"
"$T/promtool-2" tsdb create-blocks-from openmetrics "$W/t1.om" "$W/tsdb" >/dev/null
printf 'global: {scrape_interval: 15s}\n' > "$W/prom.yml"
# lookback de 15 s: o backfill não traz "staleness markers", por isso com os 5 min por omissão um alerta
# resolvido continuaria a aparecer mais 5 min (no lab o Prometheus escreve-os; as amostras aqui são a 5 s)
"$T/prometheus-2" --config.file="$W/prom.yml" --storage.tsdb.path="$W/tsdb" --storage.tsdb.retention.time=10y \
  --query.lookback-delta=15s --web.listen-address="$PROM" > "$W/prom.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 30); do curl -sf "http://$PROM/-/ready" >/dev/null && break; sleep 0.5; done

echo "[replay] 3) Grafana em 127.0.0.1:$GPORT (anónimo só-leitura, só neste replay local)"
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
shot() {  # shot <ficheiro> <largura> <altura> <caminho+query>
  TZ=Europe/Lisbon chromium --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$W/chrome" \
    --window-size="$2,$3" --virtual-time-budget=25000 --screenshot="$1" \
    "http://127.0.0.1:$GPORT$4&from=$FROM&to=$TO&theme=light" >/dev/null 2>&1
  echo "      $(basename "$1") ($(du -h "$1" | cut -f1))"
}
echo "[replay] 4) screenshots (run-$RUN, T0=$(TZ=Europe/Lisbon date -d "@${T0%.*}" '+%d/%m %H:%M:%S'))"
shot "$FIG/t1-replay-run$RUN-dashboard.png" 1600 1300 "/d/ssle-t1/?orgId=1&kiosk"
shot "$FIG/t1-replay-run$RUN-latencia.png" 1100 480 "/d-solo/ssle-t1/?orgId=1&panelId=3"
shot "$FIG/t1-replay-run$RUN-regras.png" 1100 360 "/d-solo/ssle-t1/?orgId=1&panelId=4"
echo "RESULTADO: figuras em report/figures/ (replay da evidência de staging, run-$RUN)"
