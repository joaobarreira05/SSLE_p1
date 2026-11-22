#!/usr/bin/env bash
# Benign, limited load against the expensive endpoint of ing-01 (/work). Lab only.
#   run.sh <ing-01_ip> [duration_s=120] [concurrency=20]
# ORIGINS (optional, space-separated): where the clients run — "host" (the hypervisor, the default)
# and/or "<project>/<container>" (e.g. "site-opo/sen-02"). Each origin runs <concurrency> clients:
# the distributed variant (DDoS) with several origins on different sites.
set -euo pipefail
IP="${1:?usage: run.sh <ing-01_ip> [duration_s] [concurrency]}"
DUR="${2:-120}"; CONC="${3:-20}"
ORIGINS="${ORIGINS:-host}"
echo "[t1] load on http://$IP:8000/work  dur=${DUR}s conc=${CONC} per origin  origins=[$ORIGINS]  (T0=$(date +%T))"
end=$(( $(date +%s) + DUR ))
loop="end=$end; while [ \"\$(date +%s)\" -lt \"\$end\" ]; do curl -s -o /dev/null http://$IP:8000/work || true; done"
for o in $ORIGINS; do
  for _ in $(seq 1 "$CONC"); do
    if [ "$o" = host ]; then
      sh -c "$loop" &
    else
      incus exec "${o#*/}" --project "${o%%/*}" -- sh -c "$loop" </dev/null &
    fi
  done
done
wait
echo "[t1] end of stimulus (T1=$(date +%T))"
