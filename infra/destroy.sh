#!/usr/bin/env bash
# Tears down what the deploy created (for the given profile). Asks for confirmation (SSLE_YES=1 skips it).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; PROFILE="${SSLE_PROFILE:-staging}"
# ALWAYS renders for the requested profile: a build/ from another profile would delete the wrong list
args=(render --out "$BUILD"); [ "$PROFILE" = staging ] && args+=(--staging)
python3 "$ROOT/infra/inventory.py" "${args[@]}" >/dev/null
echo "About to DELETE the containers/networks/projects of profile '$PROFILE':"
cut -f1,2 "$BUILD/containers.tsv" | sed 's/\t/ @ /'
if [ "${SSLE_YES:-0}" != 1 ]; then read -r -p "Confirm? (type 'yes'): " a; [ "$a" = yes ] || { echo "cancelled"; exit 1; }; fi
while IFS=$'\t' read -r name proj rest <&3; do incus delete -f "$name" --project "$proj" 2>/dev/null && echo "deleted $proj/$name" || true; done 3< "$BUILD/containers.tsv"
while IFS=$'\t' read -r bridge rest <&3; do incus network delete "$bridge" 2>/dev/null && echo "network $bridge deleted" || true; done 3< "$BUILD/networks.tsv"
for p in $(cut -f2 "$BUILD/containers.tsv" | sort -u); do incus project delete "$p" 2>/dev/null && echo "project $p deleted" || true; done
echo "done."
