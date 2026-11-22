#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Wazuh custom active-response (runs on core/responder, defined-agent). QUARANTINES (incus pause: freezes
# the container and PRESERVES its state for forensics — deletes nothing) a compromised SENSOR, through the
# "t490" remote whose certificate is RESTRICTED to the site-* projects (the core is not even visible with it).
#   110210  correlator: root cause = sensor  → target by site + root_cause_instance
#   110900  meta-correlation                 → target by srcip (the alert comes from the relay/web, not the sensor)
# The target is ALWAYS resolved in the fleet map generated from the inventory (infra/inventory.py
# wazuh-agents → /var/ossec/etc/ssle-fleet.tsv), never used as it comes in the alert: it only acts on an
# element that exists, is role-sensor and lives in a site-* project. Everything else is refused and logged.
# Reversible: "delete" (end of the <timeout>, 600 s) runs incus resume. Wazuh 4.x protocol with check_keys.
# Try it without Incus (fake incus on the PATH):  bash siem/active-response/test-ar.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
LOG="${SSLE_AR_LOG:-/var/ossec/logs/active-responses.log}"
FLEET="${SSLE_FLEET:-/var/ossec/etc/ssle-fleet.tsv}"   # agent  project  instance  ip  groups
REMOTE="${SSLE_INCUS_REMOTE:-t490}"
DRYRUN_FLAG="${SSLE_AR_DRYRUN_FLAG:-/var/ossec/etc/ssle-ar.dryrun}"
log() { echo "$(date -Is) ssle-quarantine: $*" >>"$LOG"; }

read -r INPUT || true
cmd=$(jq -r '.command // empty' <<<"$INPUT")
rule=$(jq -r '.parameters.alert.rule.id // empty' <<<"$INPUT")
inst=$(jq -r '.parameters.alert.data.root_cause_instance // empty' <<<"$INPUT")
site=$(jq -r '.parameters.alert.data.site // empty' <<<"$INPUT")
ip=$(jq -r '.parameters.alert.data.srcip // empty' <<<"$INPUT")

[ -r "$FLEET" ] || { log "rule=$rule: no fleet map ($FLEET) — nothing done (fail closed)"; exit 1; }
row=""
if [ -n "$inst" ] && [ -n "$site" ]; then row=$(awk -F'\t' -v n="$site-$inst" '$1 == n' "$FLEET"); fi
if [ -z "$row" ] && [ -n "$ip" ]; then row=$(awk -F'\t' -v a="$ip" '$4 == a' "$FLEET"); fi
if [ -z "$row" ] || [ "$(wc -l <<<"$row")" -ne 1 ]; then
  log "rule=$rule: unknown/ambiguous target (site='$site' inst='$inst' ip='$ip') — nothing done"; exit 0
fi
IFS=$'\t' read -r agent proj target tip groups <<<"$row"
case ",$groups," in *,role-sensor,*) ;; *) log "rule=$rule: $agent is not a sensor ($groups) — REFUSED"; exit 0 ;; esac
case "$proj" in site-avr|site-opo|site-lis) ;; *) log "rule=$rule: project '$proj' outside the sites — REFUSED"; exit 0 ;; esac
[[ "$target" =~ ^[a-z]{3}-[0-9]{2}$ ]] || { log "rule=$rule: invalid instance name '$target' — REFUSED"; exit 0; }

if [ "$cmd" = add ]; then
  printf '{"version":1,"origin":{"name":"ssle-quarantine","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' "$agent"
  RESP=null; read -r RESP || true
  [ "$(jq -r '.command // empty' <<<"$RESP" 2>/dev/null)" = continue ] || { log "rule=$rule: $agent already quarantined (abort)"; exit 0; }
fi

if [ -e "$DRYRUN_FLAG" ]; then log "DRY-RUN rule=$rule $cmd: would run incus $cmd $REMOTE:$target --project $proj ($tip)"; exit 0; fi
case "$cmd" in
  add)
    if incus pause "$REMOTE:$target" --project "$proj" 2>>"$LOG"; then log "QUARANTINE add rule=$rule $proj/$target ($tip)"
    else log "QUARANTINE add FAILED rule=$rule $proj/$target"; exit 1; fi ;;
  delete)
    if incus resume "$REMOTE:$target" --project "$proj" 2>>"$LOG"; then log "QUARANTINE del rule=$rule $proj/$target ($tip)"
    else log "QUARANTINE del FAILED rule=$rule $proj/$target"; exit 1; fi ;;
  *) log "unsupported command '$cmd'"; exit 1 ;;
esac
