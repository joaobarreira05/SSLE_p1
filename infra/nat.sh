#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NAT das redes do lab: LIGADO só para provisionar (apt/pip precisam da Internet), DESLIGADO nas PoCs.
#   bash infra/nat.sh status        # mostra ipv4.nat de cada rede do inventário
#   bash infra/nat.sh off           # PoCs: sem saída para a Internet e com o IP de origem REAL entre sites
#   bash infra/nat.sh on            # voltar a provisionar
# Porquê: com ipv4.nat=true o Incus faz masquerade de tudo o que sai da sub-rede — incluindo para OUTRAS
# redes do lab —, por isso o ing-01 via o atacante e os sensores como o mesmo IP (o gateway) e uma resposta
# por origem cortaria a frota legítima (threats/t1-ddos/post-mortem.md). Desligar o NAT não mexe na firewall
# do host: o host continua a encaminhar entre as bridges (rotas diretamente ligadas); só deixa de traduzir.
# Também cumpre a regra das aulas 7–9: durante as PoCs nenhum teste sai do lab, nem por engano.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; PROFILE="${SSLE_PROFILE:-staging}"
CMD="${1:-status}"
args=(render --out "$BUILD"); [ "$PROFILE" = staging ] && args+=(--staging)
python3 "$ROOT/infra/inventory.py" "${args[@]}" >/dev/null
case "$CMD" in
  status|on|off) ;;
  *) echo "uso: nat.sh status|on|off"; exit 2 ;;
esac
while IFS=$'\t' read -r bridge subnet _ _ <&3; do
  [ -z "$bridge" ] && continue
  incus network show "$bridge" >/dev/null 2>&1 || { echo "  · $bridge não existe (deploy?)"; continue; }
  case "$CMD" in
    on)  incus network set "$bridge" ipv4.nat=true </dev/null ;;
    off) incus network set "$bridge" ipv4.nat=false </dev/null ;;
  esac
  printf '  %-10s %-14s ipv4.nat=%s\n' "$bridge" "$subnet" "$(incus network get "$bridge" ipv4.nat </dev/null)"
done 3< "$BUILD/networks.tsv"
[ "$CMD" = off ] && echo "NAT desligado: sem Internet nos contentores; IPs de origem reais entre sites." || true
