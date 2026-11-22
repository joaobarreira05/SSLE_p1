#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Screenshots of the LIVE lab dashboards for the report, with no access to the lab's Grafana:
# a local Grafana 11.6.1 on 127.0.0.1 with the SAME dashboards (monitoring/grafana/dashboards/)
# and the SAME datasources (generated from the inventory), pointing at the lab's Prometheus servers
# (global on core/obs, prom-01 on each site). Only the time window changes between figures.
#
#   bash monitoring/grafana/shot-live.sh <out.png> <dashboard-uid> <from_epoch> <to_epoch> [width=1600] [height=1300]
#
# Anonymous read-only access is enabled ONLY on this local instance (127.0.0.1, temporary dir).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:?usage: shot-live.sh <out.png> <dashboard-uid> <from_epoch> <to_epoch> [width] [height]}"
UID_="${2:?}"; FROM="${3:?}"; TO="${4:?}"; WIDTH="${5:-1600}"; HEIGHT="${6:-1300}"
G="$ROOT/build/tools/grafana"; W="$(mktemp -d)"; GPORT="${GRAFANA_PORT:-13002}"
OBS_IP="${OBS_IP:-10.10.0.10}"
[ -x "$G/bin/grafana" ] || { echo "missing $G (see monitoring/grafana/README.md)"; exit 2; }
trap 'kill $GP 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT

mkdir -p "$W/prov/datasources" "$W/prov/dashboards" "$W/prov/plugins" "$W/prov/alerting" "$W/gdata"
python3 "$ROOT/infra/inventory.py" grafana --host t490 \
  | sed -E "s#localhost:9090#$OBS_IP:9090#; s#localhost:9093#$OBS_IP:9093#" \
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
"$G/bin/grafana" server --homepath "$G" --config "$W/grafana.ini" > "$W/grafana.log" 2>&1 & GP=$!
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$GPORT/api/health" >/dev/null && break; sleep 1; done
sleep 3

TZ=Europe/Lisbon chromium --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$W/chrome" \
  --window-size="$WIDTH,$HEIGHT" --virtual-time-budget=30000 --screenshot="$OUT" \
  "http://127.0.0.1:$GPORT/d/$UID_/?orgId=1&kiosk&from=$((FROM * 1000))&to=$((TO * 1000))&theme=light" >/dev/null 2>&1
echo "$(basename "$OUT") ($(du -h "$OUT" | cut -f1)) — $UID_, $(TZ=Europe/Lisbon date -d "@$FROM" '+%d/%m %H:%M')–$(TZ=Europe/Lisbon date -d "@$TO" '+%H:%M')"
