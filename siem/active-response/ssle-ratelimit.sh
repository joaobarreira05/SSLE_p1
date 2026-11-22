#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Wazuh custom active-response (runs ON the service: ing-01 / web-01). PROPORTIONAL response to T1:
# instead of blocking, it LIMITS the rate of new connections PER ORIGIN to the service port (nft, own
# table inet ssle_rl — touches nothing else in the firewall). Legitimate sensors send ~0.2 requests/s;
# the limit (20/s per origin) only bites whoever floods.
#   110100 (known srcip)  → limits ONLY that srcip                          (location local)
#   110101 (total volume, distributed DDoS) → limits ALL origins, each with its own bucket (local)
#   110110 (correlator: root cause = this service, no srcip) → same (defined-agent; the script checks
#          that the target is itself)
# Why the "all" mode: the ignore=60 of 110100 is PER RULE on the manager (proved in it-agents.sh), so it
# only catches ONE origin per minute; against several origins 110101/110110 are the ones that act.
# The "all" mode lives in its OWN set (limited_all): in the per-origin interval set, 0.0.0.0/0 overlaps the
# origin 110100 has already put there, nft refuses it ("interval overlaps") and, before 22/11, the "all" mode
# never engaged in the lab (silent: execd kept the key as active and answered "abort" from then on).
# Both sets jump (goto) to the same rl chain, so each packet goes through its origin's bucket only once.
# Reversible: "delete" (sent by execd at the end of the <timeout>) removes the origin; in addition, each
# set element expires on its own (safety net if the delete is lost). Everything logged in active-responses.log,
# including nft failures.
# Wazuh 4.x protocol: JSON on stdin; on "add" it asks execd check_keys and only proceeds on "continue".
# Try it without root (own namespace):  bash siem/active-response/test-ar.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LOG="${SSLE_AR_LOG:-/var/ossec/logs/active-responses.log}"
PORT="${SSLE_RL_PORT:-8000}"
RATE="${SSLE_RL_RATE:-20}"               # new connections per second, per origin
BURST="${SSLE_RL_BURST:-40}"
EXPIRE="${SSLE_RL_EXPIRE:-900s}"         # > AR timeout (300 s): the normal delete arrives first
DRYRUN_FLAG="${SSLE_AR_DRYRUN_FLAG:-/var/ossec/etc/ssle-ar.dryrun}"
ME="${SSLE_AR_HOSTNAME:-$(hostname)}"
log() { echo "$(date -Is) ssle-ratelimit[$ME]: $*" >>"$LOG"; }

read -r INPUT || true
cmd=$(jq -r '.command // empty' <<<"$INPUT")
rule=$(jq -r '.parameters.alert.rule.id // empty' <<<"$INPUT")
ip=$(jq -r '.parameters.alert.data.srcip // empty' <<<"$INPUT")
target=$(jq -r '.parameters.alert.data.root_cause_instance // empty' <<<"$INPUT")

if [ "$rule" = 110110 ] || [ "$rule" = 110101 ] || [ -z "$ip" ]; then
  # 110110: the srcip is the root cause's (this service), not the attacker's; 110101: only the last request's
  if [ -n "$target" ] && [ "$target" != "$ME" ]; then log "rule=$rule: target $target is not me — nothing done"; exit 0; fi
  key="0.0.0.0/0"; what="all origins (bucket per origin)"; set=limited_all
else
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { log "rule=$rule: invalid srcip '$ip' — refused"; exit 0; }
  key="$ip"; what="origin $ip"; set=limited
fi

if [ "$cmd" = add ]; then
  printf '{"version":1,"origin":{"name":"ssle-ratelimit","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' "$key"
  RESP=null; read -r RESP || true
  [ "$(jq -r '.command // empty' <<<"$RESP" 2>/dev/null)" = continue ] || { log "rule=$rule: $what already limited (abort)"; exit 0; }
fi

ensure_table() {
  nft list set inet ssle_rl limited_all >/dev/null 2>&1 && return 0
  # table from before 22/11 (no limited_all): recreate it with the current layout
  nft list table inet ssle_rl >/dev/null 2>&1 && { nft delete table inet ssle_rl; log "ssle_rl table recreated (new layout)"; }
  nft -f - <<EOF
table inet ssle_rl {
  set limited { type ipv4_addr; flags interval,timeout; }
  set limited_all { type ipv4_addr; flags interval,timeout; }
  set buckets { type ipv4_addr; flags dynamic,timeout; timeout 60s; }
  chain input {
    type filter hook input priority filter - 5; policy accept;
    tcp dport $PORT ct state new ip saddr @limited goto rl
    tcp dport $PORT ct state new ip saddr @limited_all goto rl
  }
  chain rl {
    update @buckets { ip saddr limit rate over $RATE/second burst $BURST packets } counter drop
  }
}
EOF
}

if [ -e "$DRYRUN_FLAG" ]; then log "DRY-RUN rule=$rule $cmd: would limit $what to $RATE conn/s on port $PORT"; exit 0; fi
case "$cmd" in
  add)
    if ! err=$(ensure_table 2>&1 && nft add element inet ssle_rl "$set" "{ $key timeout $EXPIRE }" 2>&1); then
      log "RATELIMIT add FAILED rule=$rule $what: $(tr '\n' ' ' <<<"$err")"; exit 1
    fi
    log "RATELIMIT add rule=$rule $what → $RATE conn/s (burst $BURST) on port $PORT" ;;
  delete)
    nft delete element inet ssle_rl "$set" "{ $key }" 2>/dev/null || true
    log "RATELIMIT del rule=$rule $what" ;;
  *) log "unsupported command '$cmd'"; exit 1 ;;
esac
