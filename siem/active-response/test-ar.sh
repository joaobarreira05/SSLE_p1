#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Exercises the active responses WITHOUT root and WITHOUT the lab (exits ≠ 0 if any case fails):
#   bash siem/active-response/test-ar.sh
# · ssle-quarantine: FAKE "incus" on the PATH (only records its arguments) + the real fleet map from the
#   inventory; proves that only site-* sensors are paused and that everything else is refused.
# · ssle-ratelimit: REAL nft in its own network namespace (unshare -rn: root only inside it, the host
#   firewall is not touched), with an HTTP server on 127.0.0.1:8000; proves that the excess connections
#   from one origin are dropped and that the delete restores everything.
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

echo "[ssle-quarantine] fake incus + fleet map from the inventory"
mkdir -p "$T/bin"
cat > "$T/bin/incus" <<'EOF'
#!/bin/sh
echo "$*" >> "$INCUS_CALLS"
EOF
chmod +x "$T/bin/incus"
python3 "$ROOT/infra/inventory.py" wazuh-agents --host t490 > "$T/fleet.tsv"
q() {  # q <description> <expected in INCUS_CALLS or "-"> <stdin lines…>
  local d="$1" want="$2"; shift 2
  : > "$T/calls"
  printf '%s\n' "$@" | PATH="$T/bin:$PATH" INCUS_CALLS="$T/calls" SSLE_FLEET="$T/fleet.tsv" SSLE_AR_LOG="$T/q.log" \
    SSLE_AR_DRYRUN_FLAG="$T/dryrun" bash "$AR/ssle-quarantine.sh" > "$T/out" 2>&1
  local got; got="$(cat "$T/calls")"
  if [ "$want" = - ]; then [ -z "$got" ] && ok "$d (nothing run)" || bad "$d: ran '$got'"
  else [ "$got" = "$want" ] && ok "$d → incus $got" || bad "$d: expected 'incus $want', got '$got'"; fi
}
q "110210 sensor sen-01 (opo)" "pause t490:sen-01 --project site-opo" \
  "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01","srcip":"10.10.2.50"}')" "$CONT"
grep -q '"command":"check_keys".*"keys":\["opo-sen-01"\]' "$T/out" && ok "asked execd for check_keys (key opo-sen-01)" \
  || bad "did not ask for check_keys: $(cat "$T/out")"
q "110900 meta by srcip 10.10.2.51" "pause t490:sen-02 --project site-opo" \
  "$(alert add 110900 '{"srcip":"10.10.2.51"}')" "$CONT"
q "delete at the end of the timeout" "resume t490:sen-01 --project site-opo" \
  "$(alert delete 110210 '{"site":"opo","root_cause_instance":"sen-01"}')"
q "root cause on storage (sto-01) is REFUSED" - "$(alert add 110210 '{"site":"avr","root_cause_instance":"sto-01"}')" "$CONT"
q "core srcip (10.10.0.10) is REFUSED" - "$(alert add 110900 '{"srcip":"10.10.0.10"}')" "$CONT"
q "injected name ('sen-01; reboot') does not resolve" - \
  "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01; reboot"}')" "$CONT"
q "execd answers abort (already quarantined)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')" "$ABORT"
q "execd does not answer (fail closed)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')"
touch "$T/dryrun"
q "dry-run mode (ssle-ar.dryrun)" - "$(alert add 110210 '{"site":"opo","root_cause_instance":"sen-01"}')" "$CONT"
grep -q "DRY-RUN.*incus add t490:sen-01 --project site-opo" "$T/q.log" && ok "dry-run logged what it would do" || bad "dry-run left no log"
rm -f "$T/dryrun"
echo "    active-responses.log (sample):"; sed -n '1,3p;$p' "$T/q.log" | sed 's/^/      /'

echo "[ssle-ratelimit] real nft in its own network namespace (unshare -rn)"
if ! command -v nft >/dev/null || ! unshare -rn true 2>/dev/null; then
  echo "  · no nft or no user namespaces: skipped (in the lab it runs on ing-01)"
else
  cat > "$T/rl.sh" <<'EOF'
set -uo pipefail
AR="$1"; T="$2"; CONT="$3"
export SSLE_AR_LOG="$T/rl.log" SSLE_AR_DRYRUN_FLAG="$T/none" SSLE_AR_HOSTNAME=ing-01 SSLE_RL_RATE=5 SSLE_RL_BURST=10
alert() { printf '{"version":1,"command":"%s","parameters":{"alert":{"rule":{"id":"%s"},"data":%s}}}\n' "$1" "$2" "$3"; }
rl() { printf '%s\n' "$@" | bash "$AR/ssle-ratelimit.sh" >/dev/null 2>&1; }
elems() { { nft list set inet ssle_rl limited; nft list set inet ssle_rl limited_all; } 2>/dev/null | tr -d '\n' \
          | grep -o 'elements = {[^}]*}' | tr '\n' ' ' | grep . || echo "(empty)"; }
burst() {  # 40 back-to-back connections to 127.0.0.1:8000 → "accepted seconds" (dropped ones wait 0.3 s each)
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
# regression (22/11): "all" while an origin is already limited — 0.0.0.0/0 overlapped it in the same interval set
rl "$(alert add 110110 '{"root_cause_instance":"ing-01","srcip":"10.10.1.30"}')" "$CONT"; echo "overlap=$(elems)"
rl "$(alert delete 110110 '{"root_cause_instance":"ing-01"}')"
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
  [ "$base" = 40 ] && ok "no limit: 40/40 connections accepted" || bad "no limit: $base/40 (expected 40)"
  grep -q '127.0.0.1' <<<"$(v add_ip)" && ok "110100 add → 127.0.0.1 in the set (expires on its own)" || bad "add_ip: $(v add_ip)"
  # theoretical token-bucket ceiling: burst + rate × elapsed time (+1 slack for rounding)
  max=$(awk -v s="${secs:-0}" 'BEGIN{printf "%d", 10 + 5*s + 1}')
  if [ -n "$lim" ] && [ "$lim" -lt 40 ] && [ "$lim" -le "$max" ]; then
    ok "with limit (5/s, burst 10): $lim/40 accepted in ${secs%.*} s (bucket ceiling: $max) — the excess was dropped"
  else bad "with limit: $lim/40 accepted in ${secs:-?} s (bucket ceiling: $max)"; fi
  { grep -q '127.0.0.1' <<<"$(v overlap)" && grep -q '0.0.0.0/0' <<<"$(v overlap)" && grep -q 'RATELIMIT add rule=110110' "$T/rl.log"; } \
    && ok "110110 with an origin already limited → all origins too (no interval overlap)" || bad "overlap: $(v overlap)"
  [ "$(v del_ip)" = "(empty)" ] && [ "$after" = 40 ] && ok "delete → empty sets and 40/40 again" || bad "delete: $(v del_ip), $after/40"
  [ "$(v other_target)" = "(empty)" ] && ok "110110 for web-01 on ing-01 → ignored" || bad "other_target: $(v other_target)"
  grep -q '0.0.0.0/0' <<<"$(v all)" && ok "110110 for ing-01 → all origins (bucket per origin)" || bad "all: $(v all)"
  { grep -q '0.0.0.0/0' <<<"$(v ddos)" && ! grep -q '10.10.9.99' <<<"$(v ddos)"; } \
    && ok "110101 (DDoS) → all origins, not just the IP of the last request" || bad "ddos: $(v ddos)"
  grep -q 'reboot' <<<"$out$(cat "$T/rl.log" 2>/dev/null | grep -v 'refused')" && bad "injected srcip got through" \
    || ok "injected srcip ('10.0.0.1; reboot') refused"
  echo "    active-responses.log:"; sed 's/^/      /' "$T/rl.log"
fi
echo
[ $FAIL -eq 0 ] && echo "RESULT: active-response OK ✅" || echo "RESULT: failures ✗"
exit $FAIL
