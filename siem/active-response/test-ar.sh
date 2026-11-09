#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Ensaia os active-response SEM root e SEM lab (sai ≠ 0 se algum caso falhar):
#   bash siem/active-response/test-ar.sh
# · ssle-quarantine: "incus" FALSO no PATH (só regista os argumentos) + mapa da frota real do inventário;
#   prova que só os sensores dos site-* são pausados e que tudo o resto é recusado.
# · ssle-ratelimit: nft REAL num namespace de rede próprio (unshare -rn: root só lá dentro, a firewall do
#   host não é tocada), com um servidor HTTP em 127.0.0.1:8000; prova que o excesso de ligações de uma
#   origem é descartado e que o delete repõe tudo.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AR="$ROOT/siem/active-response"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { printf '  ✓ %s\n' "$*"; }
bad() { printf '  ✗ %s\n' "$*"; FAIL=1; }
alert() {  # alert <add|delete> <rule> <json-data>
  printf '{"version":1,"command":"%s","parameters":{"alert":{"rule":{"id":"%s"},"data":%s}}}\n' "$1" "$2" "$3"
}
CONT='{"version":1,"origin":{"name":"wazuh-execd"},"command":"continue","parameters":{}}'
ABORT='{"version":1,"origin":{"name":"wazuh-execd"},"command":"abort","parameters":{}}'

echo "[ssle-quarantine] incus falso + mapa da frota do inventário"
mkdir -p "$T/bin"
cat > "$T/bin/incus" <<'EOF'
#!/bin/sh
echo "$*" >> "$INCUS_CALLS"
EOF
chmod +x "$T/bin/incus"
python3 "$ROOT/infra/inventory.py" wazuh-agents --host t490 > "$T/fleet.tsv"
q() {  # q <descrição> <esperado em INCUS_CALLS ou "-"> <linhas de stdin…>
  local d="$1" want="$2"; shift 2
  : > "$T/calls"
  printf '%s\n' "$@" | PATH="$T/bin:$PATH" INCUS_CALLS="$T/calls" SSLE_FLEET="$T/fleet.tsv" SSLE_AR_LOG="$T/q.log" \
    SSLE_AR_DRYRUN_FLAG="$T/dryrun" bash "$AR/ssle-quarantine.sh" > "$T/out" 2>&1
  local got; got="$(cat "$T/calls")"
  if [ "$want" = - ]; then [ -z "$got" ] && ok "$d (nada executado)" || bad "$d: executou '$got'"
  else [ "$got" = "$want" ] && ok "$d → incus $got" || bad "$d: esperava 'incus $want', veio '$got'"; fi
}
q "110210 sensor sen-01 (opo)" "pause t490:sen-01 --project site-opo" \
  "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01","srcip":"10.10.2.50"}')" "$CONT"
grep -q '"command":"check_keys".*"keys":\["opo-sen-01"\]' "$T/out" && ok "pediu check_keys ao execd (chave opo-sen-01)" \
  || bad "não pediu check_keys: $(cat "$T/out")"
q "110900 meta por srcip 10.10.2.51" "pause t490:sen-02 --project site-opo" \
  "$(alert add 110900 '{"srcip":"10.10.2.51"}')" "$CONT"
q "delete ao fim do timeout" "resume t490:sen-01 --project site-opo" \
  "$(alert delete 110210 '{"site":"opo","root_cause_instance":"sen-01"}')"
q "causa raiz no storage (sto-01) é RECUSADA" - "$(alert add 110210 '{"site":"avr","root_cause_instance":"sto-01"}')" "$CONT"
q "srcip do core (10.10.0.10) é RECUSADO" - "$(alert add 110900 '{"srcip":"10.10.0.10"}')" "$CONT"
q "nome injetado ('sen-01; reboot') não resolve" - \
  "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01; reboot"}')" "$CONT"
q "execd responde abort (já em quarentena)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')" "$ABORT"
q "execd não responde (falha fechada)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')"
touch "$T/dryrun"
q "modo dry-run (ssle-ar.dryrun)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')" "$CONT"
grep -q "DRY-RUN.*incus add t490:sen-01 --project site-opo" "$T/q.log" && ok "dry-run registou o que faria" || bad "dry-run sem registo"
rm -f "$T/dryrun"
echo "    active-responses.log (amostra):"; sed -n '1,3p;$p' "$T/q.log" | sed 's/^/      /'

echo "[ssle-ratelimit] nft real num namespace de rede próprio (unshare -rn)"
if ! command -v nft >/dev/null || ! unshare -rn true 2>/dev/null; then
  echo "  · sem nft ou sem user namespaces: salto (no lab corre no ing-01)"
else
  cat > "$T/rl.sh" <<'EOF'
set -uo pipefail
AR="$1"; T="$2"; CONT="$3"
export SSLE_AR_LOG="$T/rl.log" SSLE_AR_DRYRUN_FLAG="$T/none" SSLE_AR_HOSTNAME=ing-01 SSLE_RL_RATE=5 SSLE_RL_BURST=10
alert() { printf '{"version":1,"command":"%s","parameters":{"alert":{"rule":{"id":"%s"},"data":%s}}}\n' "$1" "$2" "$3"; }
rl() { printf '%s\n' "$@" | bash "$AR/ssle-ratelimit.sh" >/dev/null 2>&1; }
elems() { nft list set inet ssle_rl limited 2>/dev/null | tr -d '\n' | grep -o 'elements = {[^}]*}' || echo "(vazio)"; }
burst() {  # 40 ligações seguidas a 127.0.0.1:8000 → "aceites segundos" (as descartadas esperam 0,3 s cada)
  local n=0 t0; t0=$(date +%s.%N)
  for _ in $(seq 1 40); do curl -s -o /dev/null --max-time 0.3 http://127.0.0.1:8000/ && n=$((n+1)); done
  echo "$n $(awk -v a="$(date +%s.%N)" -v b="$t0" 'BEGIN{printf "%.2f", a-b}')"
}
ip link set lo up
python3 -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1 & srv=$!
for _ in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8000/ && break; sleep 0.1; done
echo "base=$(burst)"
rl "$(alert add 110100 '{"srcip":"127.0.0.1"}')" "$CONT"; echo "add_ip=$(elems)"
echo "limited=$(burst)"
rl "$(alert delete 110100 '{"srcip":"127.0.0.1"}')"; echo "del_ip=$(elems)"
echo "after_del=$(burst)"
rl "$(alert add 110110 '{"root_cause_instance":"web-01","srcip":"10.10.3.60"}')" "$CONT"; echo "other_target=$(elems)"
rl "$(alert add 110110 '{"root_cause_instance":"ing-01","srcip":"10.10.1.30"}')" "$CONT"; echo "all=$(elems)"
rl "$(alert delete 110110 '{"root_cause_instance":"ing-01"}')"
rl "$(alert add 110101 '{"srcip":"10.10.9.99"}')" "$CONT"; echo "ddos=$(elems)"
rl "$(alert add 110100 '{"srcip":"10.0.0.1; reboot"}')" "$CONT"; echo "inject=$(elems)"
kill $srv 2>/dev/null
EOF
  out="$(unshare -rn bash "$T/rl.sh" "$AR" "$T" "$CONT" 2>&1)"
  v() { sed -n "s/^$1=//p" <<<"$out"; }
  read -r base _ <<<"$(v base)"; read -r lim secs <<<"$(v limited)"; read -r after _ <<<"$(v after_del)"
  [ "$base" = 40 ] && ok "sem limite: 40/40 ligações aceites" || bad "sem limite: $base/40 (esperado 40)"
  grep -q '127.0.0.1' <<<"$(v add_ip)" && ok "110100 add → 127.0.0.1 no set (expira sozinho)" || bad "add_ip: $(v add_ip)"
  # teto teórico do token bucket: burst + rate × tempo decorrido (+1 de folga pelo arredondamento)
  max=$(awk -v s="${secs:-0}" 'BEGIN{printf "%d", 10 + 5*s + 1}')
  if [ -n "$lim" ] && [ "$lim" -lt 40 ] && [ "$lim" -le "$max" ]; then
    ok "com limite (5/s, burst 10): $lim/40 aceites em ${secs%.*} s (teto do balde: $max) — o excesso foi descartado"
  else bad "com limite: $lim/40 aceites em ${secs:-?} s (teto do balde: $max)"; fi
  [ "$(v del_ip)" = "(vazio)" ] && [ "$after" = 40 ] && ok "delete → set vazio e 40/40 outra vez" || bad "delete: $(v del_ip), $after/40"
  [ "$(v other_target)" = "(vazio)" ] && ok "110110 para web-01 no ing-01 → ignorado" || bad "other_target: $(v other_target)"
  grep -q '0.0.0.0/0' <<<"$(v all)" && ok "110110 para ing-01 → todas as origens (balde por origem)" || bad "all: $(v all)"
  { grep -q '0.0.0.0/0' <<<"$(v ddos)" && ! grep -q '10.10.9.99' <<<"$(v ddos)"; } \
    && ok "110101 (DDoS) → todas as origens, não só o IP do último pedido" || bad "ddos: $(v ddos)"
  grep -q 'reboot' <<<"$out$(cat "$T/rl.log" 2>/dev/null | grep -v 'recusado')" && bad "srcip injetado passou" \
    || ok "srcip injetado ('10.0.0.1; reboot') recusado"
  echo "    active-responses.log:"; sed 's/^/      /' "$T/rl.log"
fi
echo
[ $FAIL -eq 0 ] && echo "RESULTADO: active-response OK ✅" || echo "RESULTADO: há falhas ✗"
exit $FAIL
