#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Wazuh custom active-response (corre NO serviço: ing-01 / web-01). Resposta PROPORCIONAL à T1: em vez
# de bloquear, LIMITA o ritmo de ligações novas POR ORIGEM à porta do serviço (nft, tabela própria
# inet ssle_rl — não toca em mais nada da firewall). Os sensores legítimos enviam ~0,2 pedidos/s; o
# limite (20/s por origem) só morde quem inunda.
#   110100 (srcip conhecido)  → limita SÓ esse srcip              (location local)
#   110101 (volume total, DDoS distribuído) → limita TODAS as origens, cada uma com o seu balde (local)
#   110110 (correlator: causa raiz = este serviço, sem srcip) → idem (defined-agent; o script confirma
#          que o alvo é ele próprio)
# Porquê o modo "todas": o ignore=60 da 110100 é POR REGRA no manager (provado no it-agents.sh), por isso
# ela só apanha UMA origem por minuto; contra várias origens quem atua é a 110101/110110.
# Reversível: "delete" (o execd manda-o ao fim do <timeout>) tira a origem; além disso cada elemento do
# set expira sozinho (rede de segurança se o delete se perder). Tudo registado em active-responses.log.
# Protocolo Wazuh 4.x: JSON no stdin; num "add" pergunta check_keys ao execd e só segue com "continue".
# Ensaiar sem root (namespace próprio):  bash siem/active-response/test-ar.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LOG="${SSLE_AR_LOG:-/var/ossec/logs/active-responses.log}"
PORT="${SSLE_RL_PORT:-8000}"
RATE="${SSLE_RL_RATE:-20}"               # ligações novas por segundo, por origem
BURST="${SSLE_RL_BURST:-40}"
EXPIRE="${SSLE_RL_EXPIRE:-900s}"         # > timeout do AR (300 s): o delete normal chega primeiro
DRYRUN_FLAG="${SSLE_AR_DRYRUN_FLAG:-/var/ossec/etc/ssle-ar.dryrun}"
ME="${SSLE_AR_HOSTNAME:-$(hostname)}"
log() { echo "$(date -Is) ssle-ratelimit[$ME]: $*" >>"$LOG"; }

read -r INPUT || true
cmd=$(jq -r '.command // empty' <<<"$INPUT")
rule=$(jq -r '.parameters.alert.rule.id // empty' <<<"$INPUT")
ip=$(jq -r '.parameters.alert.data.srcip // empty' <<<"$INPUT")
target=$(jq -r '.parameters.alert.data.root_cause_instance // empty' <<<"$INPUT")

if [ "$rule" = 110110 ] || [ "$rule" = 110101 ] || [ -z "$ip" ]; then
  # 110110: o srcip é o da causa raiz (este serviço), não o do atacante; 110101: é só o do último pedido
  if [ -n "$target" ] && [ "$target" != "$ME" ]; then log "rule=$rule: alvo $target não sou eu — nada feito"; exit 0; fi
  key="0.0.0.0/0"; what="todas as origens (balde por origem)"
else
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { log "rule=$rule: srcip inválido '$ip' — recusado"; exit 0; }
  key="$ip"; what="origem $ip"
fi

if [ "$cmd" = add ]; then
  printf '{"version":1,"origin":{"name":"ssle-ratelimit","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' "$key"
  RESP=null; read -r RESP || true
  [ "$(jq -r '.command // empty' <<<"$RESP" 2>/dev/null)" = continue ] || { log "rule=$rule: $what já limitada (abort)"; exit 0; }
fi

ensure_table() {
  nft list table inet ssle_rl >/dev/null 2>&1 && return 0
  nft -f - <<EOF
table inet ssle_rl {
  set limited { type ipv4_addr; flags interval,timeout; }
  set buckets { type ipv4_addr; flags dynamic,timeout; timeout 60s; }
  chain input {
    type filter hook input priority filter - 5; policy accept;
    tcp dport $PORT ct state new ip saddr @limited update @buckets { ip saddr limit rate over $RATE/second burst $BURST packets } counter drop
  }
}
EOF
}

if [ -e "$DRYRUN_FLAG" ]; then log "DRY-RUN rule=$rule $cmd: limitaria $what a $RATE lig./s na porta $PORT"; exit 0; fi
case "$cmd" in
  add)
    ensure_table
    nft add element inet ssle_rl limited "{ $key timeout $EXPIRE }"
    log "RATELIMIT add rule=$rule $what → $RATE lig./s (burst $BURST) na porta $PORT" ;;
  delete)
    nft delete element inet ssle_rl limited "{ $key }" 2>/dev/null || true
    log "RATELIMIT del rule=$rule $what" ;;
  *) log "comando '$cmd' não suportado"; exit 1 ;;
esac
