#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Teste de INTEGRAÇÃO do R2 sem o lab (só 127.0.0.1, sem root):
#   registry REAL (registry/app.py, site opo do inventário, TTL 10 s)
#   + services/app.py REAL a fazer de sensor DINÂMICO sen-07 (regista-se e renova o lease)
#   + Prometheus 2.53.5 REAL com o prometheus.yml do site opo renderizado pelo inventário.
# Prova: (1) escrita sem token → 403; (2) o sen-07 aparece nos alvos do Prometheus com job="node"
# e labels de identidade, sem mexer no inventário; (3) quando o sen-07 morre, sai sozinho (TTL).
#   bash registry/it-local.sh        (precisa de: bash tools/fetch-tools.sh; uv para o Flask)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/build/tools"; W="$(mktemp -d)"; PIDS=()
REG=127.0.0.1:15050; PROM=127.0.0.1:19090
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT
PY=(uv run -q --with flask python3)
targets() { curl -s "http://$PROM/api/v1/targets" | python3 -c '
import json,sys
for t in json.load(sys.stdin)["data"]["activeTargets"]:
    l=t["labels"]
    if l.get("registered")=="dynamic": print(l["job"], l["instance_name"], l["site"], l["role"], t["scrapeUrl"])'; }

python3 "$ROOT/infra/inventory.py" render --out "$W/build" --host t490 >/dev/null
(umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$W/token")

echo "[it] registry do site opo em $REG (TTL 10 s)"
BIND=127.0.0.1 PORT=15050 SSLE_REGISTRY_TTL=10 SSLE_REGISTRY_CONFIG="$W/build/targets/opo/registry.json" \
  SSLE_REGISTRY_TOKEN_FILE="$W/token" "${PY[@]}" "$ROOT/registry/app.py" >"$W/reg.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 30); do curl -sf "http://$REG/healthz" >/dev/null && break; sleep 0.5; done

echo "[it] (1) escrita sem token:"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "http://$REG/register" -H 'Content-Type: application/json' \
       -d '{"name":"sen-09","role":"sensor","ip":"10.10.2.59"}')
echo "      HTTP $code"; [ "$code" = 403 ]

echo "[it] Prometheus 2.53.5 em $PROM com o prometheus.yml do site opo (SD a cada 3 s)"
python3 "$ROOT/infra/inventory.py" siteprom --site opo --host t490 \
  | sed -e "s#10.10.2.20:5050#$REG#g" -e "s#refresh_interval: 15s#refresh_interval: 3s#" \
        -e "s#/etc/prometheus/rules/\*.yml#$ROOT/monitoring/site/rules/*.yml#" \
        -e "s#/etc/prometheus/targets/#$W/build/targets/opo/#g" > "$W/prom.yml"
"$T/prometheus-2" --config.file="$W/prom.yml" --web.listen-address="$PROM" --storage.tsdb.path="$W/tsdb" \
  >"$W/prom.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 30); do curl -sf "http://$PROM/-/ready" >/dev/null && break; sleep 0.5; done

echo "[it] (2) arranca o sen-07 (services/app.py) — NÃO está no inventário"
BIND=127.0.0.1 PORT=18000 SSLE_ROLE=sensor SSLE_INSTANCE=sen-07 SSLE_SITE=opo SSLE_IP=10.10.2.57 \
  SSLE_REGISTRY="http://$REG" SSLE_REGISTRY_TOKEN_FILE="$W/token" "${PY[@]}" "$ROOT/services/app.py" \
  >"$W/sen.log" 2>&1 & SEN=$!; PIDS+=($SEN)
found=""
for _ in $(seq 1 40); do found=$(targets); [ "$(grep -c . <<<"$found")" -ge 2 ] && break; sleep 1; done
echo "$found" | sed 's/^/      /'
grep -q '^node sen-07 opo sensor http://10.10.2.57:9100/metrics$' <<<"$found"
grep -q '^services sen-07 opo sensor http://10.10.2.57:8000/metrics$' <<<"$found"
curl -s "http://$REG/metrics" | grep -E '^(site_info|ssle_registry_instances|ssle_registry_rejections_total.*auth)' | sed 's/^/      /'

echo "[it] (3) o sen-07 morre → o lease expira (10 s) e sai dos alvos"
kill "$SEN"; t0=$(date +%s)
for _ in $(seq 1 40); do [ -z "$(targets)" ] && break; sleep 1; done
[ -z "$(targets)" ] || { echo "  ✗ o sen-07 continua nos alvos"; exit 1; }
echo "      saiu dos alvos $(( $(date +%s) - t0 )) s depois de morrer"
echo "RESULTADO: R2 — registo dinâmico → descoberta pelo Prometheus → expiração ✅"
