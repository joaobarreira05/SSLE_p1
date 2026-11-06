#!/usr/bin/env bash
# Carga benigna e limitada contra o endpoint caro do ing-01 (/work). Só no lab.
set -euo pipefail
IP="${1:?uso: run.sh <ip_ing-01> [duracao_s] [concorrencia]}"
DUR="${2:-120}"; CONC="${3:-20}"
echo "[t1] carga a http://$IP:8000/work  dur=${DUR}s conc=${CONC}  (T0=$(date +%T))"
end=$(( $(date +%s) + DUR ))
for c in $(seq 1 "$CONC"); do
  ( while [ "$(date +%s)" -lt "$end" ]; do curl -s -o /dev/null "http://$IP:8000/work" || true; done ) &
done
wait
echo "[t1] fim do estímulo (T1=$(date +%T))"
