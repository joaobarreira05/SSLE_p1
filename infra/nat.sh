#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NAT of the lab networks: ON only for provisioning (apt/pip need the Internet), OFF during the PoCs.
#   bash infra/nat.sh status        # shows ipv4.nat of each inventory network
#   bash infra/nat.sh off           # PoCs: no Internet egress and the REAL source IP between sites
#   bash infra/nat.sh on            # back to provisioning
# Why: with ipv4.nat=true Incus masquerades everything leaving the subnet — including towards OTHER
# lab networks —, so ing-01 saw the attacker and the sensors as the same IP (the gateway) and a
# per-origin response would cut off the legitimate fleet (threats/t1-ddos/post-mortem.md). Turning NAT off
# does not touch the host firewall: the host keeps routing between the bridges (directly connected
# routes); it just stops translating. It also enforces the rule from lectures 7–9: during the PoCs no
# test leaves the lab, not even by mistake.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; PROFILE="${SSLE_PROFILE:-staging}"
CMD="${1:-status}"
args=(render --out "$BUILD"); [ "$PROFILE" = staging ] && args+=(--staging)
python3 "$ROOT/infra/inventory.py" "${args[@]}" >/dev/null
case "$CMD" in
  status|on|off) ;;
  *) echo "usage: nat.sh status|on|off"; exit 2 ;;
esac
while IFS=$'\t' read -r bridge subnet _ _ <&3; do
  [ -z "$bridge" ] && continue
  incus network show "$bridge" >/dev/null 2>&1 || { echo "  · $bridge does not exist (deploy?)"; continue; }
  case "$CMD" in
    on)  incus network set "$bridge" ipv4.nat=true </dev/null ;;
    off) incus network set "$bridge" ipv4.nat=false </dev/null ;;
  esac
  printf '  %-10s %-14s ipv4.nat=%s\n' "$bridge" "$subnet" "$(incus network get "$bridge" ipv4.nat </dev/null)"
done 3< "$BUILD/networks.tsv"
[ "$CMD" = off ] && echo "NAT off: no Internet in the containers; real source IPs between sites." || true
