#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Validates Grafana-as-code with a REAL Grafana 11.6.1 on 127.0.0.1 (no root, no lab):
#   provisioning of the datasources (generated from the inventory) and of the dashboards (provider + JSON),
#   and fails if Grafana logs errors while loading them.
#   bash monitoring/grafana/it-local.sh      (Grafana comes from build/tools/grafana — see README)
# The datasources point at 127.0.0.1:19091 (a local Prometheus, if any) — only the provisioning is
# validated here; in the lab the data comes from the global and from each site's prom-01.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
G="$ROOT/build/tools/grafana"; W="$(mktemp -d)"; PORT="${GRAFANA_PORT:-13000}"
[ -x "$G/bin/grafana" ] || { echo "missing $G (download the 11.6.1 tarball with sha256 — see monitoring/grafana/README.md)"; exit 2; }
PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
trap 'kill $GP 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT
mkdir -p "$W/prov/datasources" "$W/prov/dashboards" "$W/prov/plugins" "$W/prov/alerting" "$W/data"
python3 "$ROOT/infra/inventory.py" grafana --host t490 \
  | sed -E "s#url: 'http://[0-9.]+:9090'#url: 'http://127.0.0.1:19091'#; s#localhost:9090#127.0.0.1:19091#; s#localhost:9093#127.0.0.1:19093#" \
  > "$W/prov/datasources/ssle.yml"
sed "s#/var/lib/grafana/dashboards/ssle#$ROOT/monitoring/grafana/dashboards#" "$ROOT/monitoring/grafana/providers/ssle.yml" \
  > "$W/prov/dashboards/ssle.yml"
cat > "$W/grafana.ini" <<INI
[server]
http_addr = 127.0.0.1
http_port = $PORT
[paths]
data = $W/data
logs = $W/data/log
plugins = $W/data/plugins
provisioning = $W/prov
[security]
admin_user = admin
admin_password = $PASS
[auth.anonymous]
enabled = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[news]
news_feed_enabled = false
[log]
mode = console
level = info
INI
"$G/bin/grafana" server --homepath "$G" --config "$W/grafana.ini" > "$W/grafana.log" 2>&1 & GP=$!
api() { curl -sf -u "admin:$PASS" "http://127.0.0.1:$PORT$1"; }
for _ in $(seq 1 60); do api /api/health >/dev/null 2>&1 && break; sleep 1; done
echo "[grafana] $(api /api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); print("version", d["version"], "· db", d["database"])')"
sleep 3
api /api/datasources | python3 -c '
import json,sys
ds=json.load(sys.stdin); print("  datasources: " + ", ".join(sorted(d["uid"] for d in ds)))
assert {"prom-global","prom-avr","prom-opo","prom-lis","alertmanager"} <= {d["uid"] for d in ds}'
api '/api/search?type=dash-db' | python3 -c '
import json,sys
r=json.load(sys.stdin); print("  dashboards: " + ", ".join("%s/%s" % (d.get("folderTitle","-"), d["uid"]) for d in r))
assert {"ssle-soc","ssle-t1"} <= {d["uid"] for d in r}'
for uid in ssle-soc ssle-t1; do
  api "/api/dashboards/uid/$uid" | python3 -c '
import json,sys
d=json.load(sys.stdin)["dashboard"]; ps=d["panels"]
print("  %s: %d panels (%s)" % (d["uid"], len(ps), ", ".join(sorted({p["type"] for p in ps}))))'
done
errs=$(grep -iE 'level=(error|crit)' "$W/grafana.log" | grep -iE 'provision|dashboard|datasource' || true)
if [ -n "$errs" ]; then echo "  ✗ Grafana errors:"; sed 's/^/      /' <<<"$errs"; exit 1; fi
echo "RESULT: Grafana provisioning error-free ✅"
