#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Minimal SMTP client for the T3 PoC, in pure bash (/dev/tcp): runs on a sensor ("bot") without installing anything.
#   smtp-poc.sh <mail_ip> <n_spam> <n_relay> [domain]
# · n_spam  messages with GTUBE (SpamAssassin's standard, harmless TEST string) to aluno@<domain>:
#           they are accepted and spamd flags them (score 1000) → 110301/110304 and, from 10 on, 110300;
# · n_relay relay attempts to the outside (x@external.example) → the MTA refuses (554) → 3301 → 110302.
# Benign and limited: small, fixed volume, only to the lab's mail-01, which never delivers outside.
# Prints a summary of the SMTP codes received (the client-side evidence).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
IP="${1:?usage: smtp-poc.sh <mail_ip> <n_spam> <n_relay> [domain]}"; NSPAM="${2:-0}"; NRELAY="${3:-0}"
DOM="${4:-lis.ssle.lab}"
GTUBE='XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
declare -A CODES=()

reply() {  # reads an SMTP reply (may have several "250-…" lines); returns the code
  local line
  while IFS= read -r -t 15 line <&3; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^([0-9]{3})\  ]] && { echo "${BASH_REMATCH[1]}"; return 0; }
  done
  echo "000"
}
send() { printf '%s\r\n' "$1" >&3; }

session() {  # session <rcpt> <subject> <body>
  local code
  # probe with a timeout: with the origin blocked (DROP) the /dev/tcp connect would hang for ~2 min
  if ! timeout 5 bash -c ": <>/dev/tcp/$IP/25" 2>/dev/null || ! exec 3<>"/dev/tcp/$IP/25" 2>/dev/null; then
    CODES[no-connection]=$(( ${CODES[no-connection]:-0} + 1 )); return
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
for i in $(seq 1 "$NRELAY"); do session "x$i@external.example" "relay #$i" "relay test"; done
printf '[t3] %s spam + %s relay to %s →' "$NSPAM" "$NRELAY" "$IP"
for k in "${!CODES[@]}"; do printf ' %s×%s' "$k" "${CODES[$k]}"; done; echo
