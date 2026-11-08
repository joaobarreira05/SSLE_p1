#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Valida o Grafana-como-código com um Grafana 11.6.1 REAL em 127.0.0.1 (sem root, sem lab):
#   provisioning das datasources (geradas do inventário) e dos dashboards (provider + JSON),
#   e falha se o Grafana registar erros a carregá-los.
#   bash monitoring/grafana/it-local.sh      (o Grafana vem de build/tools/grafana — ver README)
# As datasources apontam para 127.0.0.1:19091 (um Prometheus local, se houver) — aqui só se valida
# o provisioning; os dados no lab vêm do global e dos prom-01 de cada site.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
G="$ROOT/build/tools/grafana"; W="$(mktemp -d)"; PORT="${GRAFANA_PORT:-13000}"
[ -x "$G/bin/grafana" ] || { echo "falta $G (descarregar o tarball 11.6.1 com sha256 — ver monitoring/grafana/README.md)"; exit 2; }
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
echo "[grafana] $(api /api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); print("versão", d["version"], "· db", d["database"])')"
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
print("  %s: %d painéis (%s)" % (d["uid"], len(ps), ", ".join(sorted({p["type"] for p in ps}))))'
done
errs=$(grep -iE 'level=(error|crit)' "$W/grafana.log" | grep -iE 'provision|dashboard|datasource' || true)
if [ -n "$errs" ]; then echo "  ✗ erros do Grafana:"; sed 's/^/      /' <<<"$errs"; exit 1; fi
echo "RESULTADO: provisioning do Grafana sem erros ✅"
