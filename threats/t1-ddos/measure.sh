#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Threat 1 (DoS) — ONE measured run: fixed stimulus → detection → recovery.
#
#   bash threats/t1-ddos/measure.sh <run_name> [duration_s=120] [concurrency=20]
#
# 1) records T0, runs the LIMITED, fixed-duration stimulus (run.sh, lecture 7), records T1;
# 2) waits SETTLE s (recovery + alert resolution) and records TE;
# 3) calls analyze.py, which takes the metrics from the SOURCES (ALERTS series, sensor metrics,
#    the correlator's incidents.json) — no manual stopwatch.
# Evidence: $EVROOT/<run_name>/ (default threats/t1-ddos/evidence/run-<n>/), plus results.csv/results.md
# with every run in $EVROOT. Runs that already have a summary.json are NOT re-queried (--keep): once
# Prometheus retention has passed, re-querying would overwrite the evidence with empty series.
# ORIGINS="host site-opo/sen-02 …" runs the distributed variant (see run.sh).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C          # decimal point in printf/awk, whatever the host locale
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N="${1:?usage: measure.sh <run_name> [duration_s] [concurrency]}"
DUR="${2:-120}"; CONC="${3:-20}"
ING_IP="${ING_IP:-10.10.1.30}"           # target: avr/ing-01
SETTLE="${SETTLE:-300}"
EVROOT="${EVROOT:-$HERE/evidence}"
case "$N" in [0-9]*) EV="$EVROOT/run-$N" ;; *) EV="$EVROOT/$N" ;; esac
mkdir -p "$EV"
# With NAT between sites ing-01 sees the attacker and the sensors as the gateway: warn (infra/nat.sh off)
if [ "$(incus network get net-avr ipv4.nat 2>/dev/null </dev/null || true)" = true ]; then
  echo "[t1/$N] ⚠️ NAT on for net-avr: the attack origin cannot be attributed (run 'bash infra/nat.sh off')"
fi

T0=$(date +%s.%N)
bash "$HERE/run.sh" "$ING_IP" "$DUR" "$CONC" | tee "$EV/run.log"
T1=$(date +%s.%N)
echo "[t1/$N] stimulus ended; waiting ${SETTLE}s for recovery…"
# Capture active-response evidence (nft + AR log) while the response is active
sleep 10   # give Wazuh time to deliver the AR
incus exec ing-01 --project site-avr -- nft list table inet ssle_rl > "$EV/nft-ssle-rl.txt" 2>&1 || true
incus exec ing-01 --project site-avr -- cat /var/ossec/logs/active-responses.log 2>/dev/null > "$EV/ar.log" || true
echo "[t1/$N] AR evidence captured → $EV/nft-ssle-rl.txt, $EV/ar.log"
sleep $((SETTLE - 10))
TE=$(date +%s.%N)
num="${N//[!0-9]/}"
printf 'N=%s\nT0=%s\nT1=%s\nTE=%s\nDUR=%s\nCONC=%s\nORIGINS="%s"\n' "${num:-0}" "$T0" "$T1" "$TE" "$DUR" "$CONC" "${ORIGINS:-host}" > "$EV/times.env"
# Only the T490 runs (run-4 onwards); the staging ones (1-3) live in another Prometheus
runs=()
for d in "$EVROOT"/*/; do
  d="${d%/}"; [ -f "$d/times.env" ] || continue
  r="${d##*run-}"; [ "$r" != "$d" ] && [ "$r" -lt 4 ] 2>/dev/null && continue
  runs+=("$d")
done
python3 -I "$HERE/analyze.py" --keep "${runs[@]}"
