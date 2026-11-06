#!/usr/bin/env bash
# Wazuh custom active-response. Põe em QUARENTENA (incus pause) o elemento que é
# causa raiz, via o remote 'incus' RESTRITO aos projetos dos sites (core/responder).
# Protocolo: recebe JSON no stdin com .command = add|delete e o alerta.
# Proporcional, reversível e registado. Valida argumentos (só site-* e só pause/resume).
set -euo pipefail
LOG=/var/ossec/logs/active-responses.log
read -r INPUT || true
cmd=$(echo "$INPUT" | jq -r '.command // empty')
site=$(echo "$INPUT" | jq -r '.parameters.alert.data.site // .parameters.alert.site // empty')
inst=$(echo "$INPUT" | jq -r '.parameters.alert.data.root_cause_instance // empty')
ts=$(date -Is)
proj="site-$site"
case "$site" in avr|opo|lis) : ;; *) echo "$ts quarantine: site inválido '$site'" >>"$LOG"; exit 1;; esac
[ -n "$inst" ] || { echo "$ts quarantine: sem instância" >>"$LOG"; exit 1; }
case "$cmd" in
  add)    incus pause  "$inst" --project "$proj" t490: 2>>"$LOG" && echo "$ts QUARENTENA add $proj/$inst" >>"$LOG" ;;
  delete) incus resume "$inst" --project "$proj" t490: 2>>"$LOG" && echo "$ts QUARENTENA del $proj/$inst" >>"$LOG" ;;
  *) echo "$ts quarantine: comando '$cmd' não suportado" >>"$LOG"; exit 1 ;;
esac
