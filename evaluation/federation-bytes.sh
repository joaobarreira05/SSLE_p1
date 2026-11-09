#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# F4 / R5 (bónus): quanta banda poupa a federação SÓ de agregados? Medido sem o lab:
#   bash evaluation/federation-bytes.sh            # → evaluation/federation-bytes.md (tabela + método)
#
# Um Prometheus 2.53.5 REAL (build/tools) com as regras de site REAIS (monitoring/site/rules) faz scrape de N
# "elementos" (N = 10, 25, 50). Cada elemento é um conjunto de labels distinto (o do inventário: region, site,
# host, instance_name, role…) sobre dois exporters REAIS em 127.0.0.1: um node_exporter (Docker, só leitura,
# sem rede para fora) e o serviço Flask do projeto (services/app.py). Depois compara-se, por pedido do global:
#   · /federate com o match[] do monitoring/global/prometheus.yml   (o que o projeto envia entre sites)
#   · /federate com {__name__=~".+"}                               (o que um Prometheus central SEM hierarquia
#                                                                    teria de puxar: todas as séries)
# em séries, bytes em texto e bytes com gzip (o Prometheus comprime se o cliente aceitar).
# Limite honesto: todos os "elementos" de um N partilham os mesmos dois exporters (mesmos valores); o número
# de séries e os bytes por série são os reais, a variedade de valores não.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROMBIN="$ROOT/build/tools/prometheus-2"
[ -x "$PROMBIN" ] || bash "$ROOT/tools/fetch-tools.sh"
NE_IMAGE="${NE_IMAGE:-prom/node-exporter:v1.8.2}"
NE=127.0.0.1:19100; SVC=127.0.0.1:18000; PROM=127.0.0.1:19190
T="$(mktemp -d)"; OUT="$ROOT/evaluation/federation-bytes.md"
cleanup() { [ -n "${PP:-}" ] && kill "$PP" 2>/dev/null; [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null
            docker rm -f ssle-f4-ne >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT

echo "[f4] exporters reais: node_exporter ($NE_IMAGE) e o serviço Flask do projeto"
docker rm -f ssle-f4-ne >/dev/null 2>&1 || true
docker run -d --name ssle-f4-ne -p "$NE:9100" --read-only "$NE_IMAGE" >/dev/null
SSLE_ROLE=ingestion BIND=127.0.0.1 PORT=18000 uv run -q --with flask python3 "$ROOT/services/app.py" >"$T/svc.log" 2>&1 & SP=$!
for _ in $(seq 1 60); do curl -sf "http://$NE/metrics" >/dev/null && curl -sf "http://$SVC/metrics" >/dev/null && break; sleep 1; done
for _ in $(seq 1 30); do curl -s -o /dev/null "http://$SVC/work"; done      # algum tráfego para os histogramas

measure() {  # measure <match[]=…>… → "séries bytes_texto bytes_gzip"
  local args=() m body
  for m in "$@"; do args+=(--data-urlencode "$m"); done
  body="$(curl -s -G "http://$PROM/federate" "${args[@]}")"
  local series; series=$(grep -vc '^#' <<<"$body" || true)
  local raw; raw=$(printf '%s' "$body" | wc -c)
  local gz; gz=$(printf '%s' "$body" | gzip -c | wc -c)
  echo "$series $raw $gz"
}
# o match[] do monitoring/global/prometheus.yml (o que o projeto federa) e "tudo" (sem hierarquia)
AGG=('match[]={__name__=~"site.*:.*"}' 'match[]=up' 'match[]=ALERTS{alertstate="firing"}')
ALL=('match[]={__name__=~".+"}')

{
  echo "# F4 — banda da federação: só agregados vs todas as séries"
  echo
  echo "> Gerado por \`bash evaluation/federation-bytes.sh\` em $(date -u +%Y-%m-%dT%H:%MZ). Prometheus $("$PROMBIN" --version 2>&1 | head -1 | awk '{print $3}'),"
  echo "> regras de site reais, exporters reais (node_exporter + serviço Flask), N elementos por site. Método e limites"
  echo "> no cabeçalho do script. Um pedido do global a cada 15 s = 4 pedidos/min por site."
  echo
  echo "| N elementos | séries (agregados) | séries (todas) | bytes/pedido agregados (texto · gzip) | bytes/pedido todas (texto · gzip) | poupança (gzip) | kB/min por site, agregados (gzip) |"
  echo "|---|---|---|---|---|---|---|"
} > "$T/table.md"

for N in 10 25 50; do
  { echo "global: {scrape_interval: 5s, evaluation_interval: 5s}"
    echo "rule_files: ['$ROOT/monitoring/site/rules/*.yml']"
    echo "scrape_configs:"
    for job in node services; do
      echo "- job_name: $job"
      echo "  static_configs:"
      for i in $(seq -w 1 "$N"); do
        tgt=$NE; [ "$job" = services ] && tgt=$SVC
        echo "  - targets: ['$tgt']"
        echo "    labels: {region: pt, site: opo, host: t490, instance_name: e$i, role: sensor, team: ops-opo, project: site-opo$( [ "$job" = services ] && echo ', service: sensor')}"
      done
    done
  } > "$T/prom-$N.yml"
  rm -rf "$T/data"
  "$PROMBIN" --config.file="$T/prom-$N.yml" --storage.tsdb.path="$T/data" --web.listen-address="$PROM" \
    --log.level=warn >"$T/prom-$N.log" 2>&1 & PP=$!
  for _ in $(seq 1 30); do curl -sf "http://$PROM/-/ready" >/dev/null && break; sleep 1; done
  sleep 25   # ≥ 4 scrapes + avaliações: os rate()[5m] das recording rules já têm 2 amostras
  read -r sa ra ga <<<"$(measure "${AGG[@]}")"
  read -r st rt gt <<<"$(measure "${ALL[@]}")"
  kill "$PP"; wait "$PP" 2>/dev/null || true; PP=""
  printf '| %s | %s | %s | %s · %s | %s · %s | %s %% | %.1f |\n' "$N" "$sa" "$st" "$ra" "$ga" "$rt" "$gt" \
    "$(awk -v a="$ga" -v b="$gt" 'BEGIN{printf "%.1f", 100*(1-a/b)}')" "$(awk -v g="$ga" 'BEGIN{print g*4/1000}')" >> "$T/table.md"
  echo "[f4] N=$N: agregados $sa séries / ${ga} B gzip · todas $st séries / ${gt} B gzip"
done
cat >> "$T/table.md" <<'EOF'

**Leitura.** As séries federadas são `2N + 5`: os **5** agregados de site (`site:*`, constantes com N) mais o
`up` de cada alvo (2 por elemento: node + serviço), que se manteve de propósito porque a análise de causa raiz
no global precisa de saber **qual** elemento caiu. Sem hierarquia, o central puxaria ~820 séries por elemento
(o node_exporter inteiro + os histogramas do serviço). A poupança fica acima de 99 % em todos os N e
**aumenta** com N, porque o lado agregado cresce 2 séries por elemento e o lado "tudo" cresce ~820.
EOF
cp "$T/table.md" "$OUT"
echo; cat "$OUT"
