#!/usr/bin/env bash
# MTTD/MTTR of a PoC: compares the stimulus instant with the 1st alert and the recovery.
# Usage: note T0 (stimulus) and run; reads the timestamps from incidents.json.
set -euo pipefail
T0="${1:?usage: measure.sh <stimulus_epoch>}"
first=$(incus exec obs --project core -- sh -c 'head -1 /var/log/ssle/incidents.json' </dev/null | jq -r '.ts')
[ -n "$first" ] && echo "MTTD ~= $(( $(date -d "$first" +%s) - T0 )) s (stimulus -> 1st incident)"
echo "MTTR: measure from the stimulus until the impact metric is back to normal (see Grafana/query)."
