#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Ameaça 1 (DoS) — UMA execução medida: estímulo fixo → deteção → recuperação.
#
#   bash threats/t1-ddos/measure.sh <n_execução> [duração_s=120] [concorrência=20]
#
# 1) regista T0, corre o estímulo LIMITADO e com duração fixa (run.sh, aula 7), regista T1;
# 2) espera SETTLE s (recuperação + resolução dos alertas) e regista TE;
# 3) chama analyze.py, que tira as métricas das FONTES (série ALERTS, métricas do sensor,
#    incidents.json do correlator) — nada de cronómetro à mão.
# Evidência: threats/t1-ddos/evidence/run-<n>/ (+ results.csv/results.md com todas as execuções).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C          # ponto decimal em printf/awk, seja qual for o locale do host
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N="${1:?uso: measure.sh <n_execução> [duração_s] [concorrência]}"
DUR="${2:-120}"; CONC="${3:-20}"
ING_IP="${ING_IP:-10.10.1.30}"           # alvo: avr/ing-01
SETTLE="${SETTLE:-300}"
EV="$HERE/evidence/run-$N"; mkdir -p "$EV"

T0=$(date +%s.%N)
bash "$HERE/run.sh" "$ING_IP" "$DUR" "$CONC" | tee "$EV/run.log"
T1=$(date +%s.%N)
echo "[t1/run-$N] estímulo terminou; a aguardar ${SETTLE}s pela recuperação…"
sleep "$SETTLE"
TE=$(date +%s.%N)
printf 'N=%s\nT0=%s\nT1=%s\nTE=%s\nDUR=%s\nCONC=%s\n' "$N" "$T0" "$T1" "$TE" "$DUR" "$CONC" > "$EV/times.env"
python3 -I "$HERE/analyze.py" "$HERE"/evidence/run-*
