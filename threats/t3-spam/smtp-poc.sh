#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Cliente SMTP mínimo da PoC da T3, em bash puro (/dev/tcp): corre num sensor ("bot") sem instalar nada.
#   smtp-poc.sh <ip_mail> <n_spam> <n_relay> [domínio]
# · n_spam  mensagens com a GTUBE (a cadeia de TESTE padrão do SpamAssassin, inofensiva) para aluno@<domínio>:
#           são aceites e o spamd marca-as (score 1000) → 110301/110304 e, a partir de 10, 110300;
# · n_relay tentativas de relay para fora (x@external.example) → o MTA recusa (554) → 3301 → 110302.
# Benigno e limitado: volume pequeno e fixo, só para o mail-01 do lab, que nunca entrega para fora.
# Imprime um resumo dos códigos SMTP recebidos (a evidência do lado do cliente).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
IP="${1:?uso: smtp-poc.sh <ip_mail> <n_spam> <n_relay> [domínio]}"; NSPAM="${2:-0}"; NRELAY="${3:-0}"
DOM="${4:-lis.ssle.lab}"
GTUBE='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
declare -A CODES=()

reply() {  # lê uma resposta SMTP (pode ter várias linhas "250-…"); devolve o código
  local line
  while IFS= read -r -t 15 line <&3; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^([0-9]{3})\  ]] && { echo "${BASH_REMATCH[1]}"; return 0; }
  done
  echo "000"
}
send() { printf '%s\r\n' "$1" >&3; }

session() {  # session <rcpt> <assunto> <corpo>
  local code
  # sonda com timeout: com a origem bloqueada (DROP) o connect do /dev/tcp ficaria pendurado ~2 min
  if ! timeout 5 bash -c ": <>/dev/tcp/$IP/25" 2>/dev/null || ! exec 3<>"/dev/tcp/$IP/25" 2>/dev/null; then
    CODES[sem-ligação]=$(( ${CODES[sem-ligação]:-0} + 1 )); return
  fi
  code=$(reply); [ "$code" = 220 ] || { CODES[$code]=$(( ${CODES[$code]:-0} + 1 )); exec 3>&-; return; }
  send "EHLO $(hostname)"; reply >/dev/null
  send "MAIL FROM:<bot@$(hostname).lab>"; reply >/dev/null
  send "RCPT TO:<$1>"; code=$(reply)
  if [ "$code" = 250 ]; then
    send "DATA"; reply >/dev/null
    send "Subject: $2"; send ""; send "$3"; send "."
    code=$(reply)
  fi
  CODES[$code]=$(( ${CODES[$code]:-0} + 1 ))
  send "QUIT"; reply >/dev/null; exec 3>&-
}

for i in $(seq 1 "$NSPAM"); do session "aluno@$DOM" "ssle t3 #$i" "$GTUBE"; done
for i in $(seq 1 "$NRELAY"); do session "x$i@external.example" "relay #$i" "teste de relay"; done
printf '[t3] %s spam + %s relay para %s →' "$NSPAM" "$NRELAY" "$IP"
for k in "${!CODES[@]}"; do printf ' %s×%s' "$k" "${CODES[$k]}"; done; echo
