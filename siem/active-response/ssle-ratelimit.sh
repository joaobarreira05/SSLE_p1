#!/usr/bin/env bash
# Active-response proporcional: em vez de bloquear, LIMITA o débito da origem (tc/nft).
# Esqueleto — adaptar à interface do alvo. Reversível (delete remove a limitação).
set -euo pipefail
LOG=/var/ossec/logs/active-responses.log
read -r INPUT || true
cmd=$(echo "$INPUT" | jq -r '.command // empty')
ip=$(echo "$INPUT" | jq -r '.parameters.alert.data.srcip // empty')
ts=$(date -Is)
[ -n "$ip" ] || exit 0
case "$cmd" in
  add)    echo "$ts RATELIMIT add $ip (aplicar nft/tc)" >>"$LOG" ;;
  delete) echo "$ts RATELIMIT del $ip" >>"$LOG" ;;
esac
