#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Wazuh custom active-response (corre no core/responder, defined-agent). Põe em QUARENTENA (incus pause:
# congela o contentor e PRESERVA o estado para a forense — não apaga nada) um SENSOR comprometido, via o
# remote "t490" com certificado RESTRITO aos projetos site-* (o core nem é visível com ele).
#   110210  correlator: causa raiz = sensor  → alvo por site + root_cause_instance
#   110900  meta-correlação                   → alvo por srcip (o alerta vem do relay/web, não do sensor)
# O alvo é SEMPRE resolvido no mapa da frota gerado do inventário (infra/inventory.py wazuh-agents →
# /var/ossec/etc/ssle-fleet.tsv), nunca usado tal como vem no alerta: só se age sobre um elemento que
# existe, que é role-sensor e que vive num projeto site-*. Tudo o resto é recusado e registado.
# Reversível: "delete" (fim do <timeout>, 600 s) faz incus resume. Protocolo Wazuh 4.x com check_keys.
# Ensaiar sem Incus (incus falso no PATH):  bash siem/active-response/test-ar.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LOG="${SSLE_AR_LOG:-/var/ossec/logs/active-responses.log}"
FLEET="${SSLE_FLEET:-/var/ossec/etc/ssle-fleet.tsv}"   # agente  projeto  instância  ip  grupos
REMOTE="${SSLE_INCUS_REMOTE:-t490}"
DRYRUN_FLAG="${SSLE_AR_DRYRUN_FLAG:-/var/ossec/etc/ssle-ar.dryrun}"
log() { echo "$(date -Is) ssle-quarantine: $*" >>"$LOG"; }

read -r INPUT || true
cmd=$(jq -r '.command // empty' <<<"$INPUT")
rule=$(jq -r '.parameters.alert.rule.id // empty' <<<"$INPUT")
inst=$(jq -r '.parameters.alert.data.root_cause_instance // empty' <<<"$INPUT")
site=$(jq -r '.parameters.alert.data.site // empty' <<<"$INPUT")
ip=$(jq -r '.parameters.alert.data.srcip // empty' <<<"$INPUT")

[ -r "$FLEET" ] || { log "rule=$rule: sem mapa da frota ($FLEET) — nada feito (falha fechada)"; exit 1; }
row=""
if [ -n "$inst" ] && [ -n "$site" ]; then row=$(awk -F'\t' -v n="$site-$inst" '$1 == n' "$FLEET"); fi
if [ -z "$row" ] && [ -n "$ip" ]; then row=$(awk -F'\t' -v a="$ip" '$4 == a' "$FLEET"); fi
if [ -z "$row" ] || [ "$(wc -l <<<"$row")" -ne 1 ]; then
  log "rule=$rule: alvo desconhecido/ambíguo (site='$site' inst='$inst' ip='$ip') — nada feito"; exit 0
fi
IFS=$'\t' read -r agent proj target tip groups <<<"$row"
case ",$groups," in *,role-sensor,*) ;; *) log "rule=$rule: $agent não é sensor ($groups) — RECUSADO"; exit 0 ;; esac
case "$proj" in site-avr|site-opo|site-lis) ;; *) log "rule=$rule: projeto '$proj' fora dos sites — RECUSADO"; exit 0 ;; esac
[[ "$target" =~ ^[a-z]{3}-[0-9]{2}$ ]] || { log "rule=$rule: nome de instância inválido '$target' — RECUSADO"; exit 0; }

if [ "$cmd" = add ]; then
  printf '{"version":1,"origin":{"name":"ssle-quarantine","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' "$agent"
  RESP=null; read -r RESP || true
  [ "$(jq -r '.command // empty' <<<"$RESP" 2>/dev/null)" = continue ] || { log "rule=$rule: $agent já em quarentena (abort)"; exit 0; }
fi

if [ -e "$DRYRUN_FLAG" ]; then log "DRY-RUN rule=$rule $cmd: faria incus $cmd $REMOTE:$target --project $proj ($tip)"; exit 0; fi
case "$cmd" in
  add)
    if incus pause "$REMOTE:$target" --project "$proj" 2>>"$LOG"; then log "QUARENTENA add rule=$rule $proj/$target ($tip)"
    else log "QUARENTENA add FALHOU rule=$rule $proj/$target"; exit 1; fi ;;
  delete)
    if incus resume "$REMOTE:$target" --project "$proj" 2>>"$LOG"; then log "QUARENTENA del rule=$rule $proj/$target ($tip)"
    else log "QUARENTENA del FALHOU rule=$rule $proj/$target"; exit 1; fi ;;
  *) log "comando '$cmd' não suportado"; exit 1 ;;
esac
