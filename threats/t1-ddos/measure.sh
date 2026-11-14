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
# Com NAT entre sites o ing-01 vê o atacante e os sensores como o gateway: avisar (infra/nat.sh off)
if [ "$(incus network get net-avr ipv4.nat 2>/dev/null </dev/null || true)" = true ]; then
  echo "[t1/run-$N] ⚠️ NAT ligado na net-avr: a origem do ataque não é atribuível (correr 'bash infra/nat.sh off')"
fi

T0=$(date +%s.%N)
bash "$HERE/run.sh" "$ING_IP" "$DUR" "$CONC" | tee "$EV/run.log"
T1=$(date +%s.%N)
echo "[t1/run-$N] estímulo terminou; a aguardar ${SETTLE}s pela recuperação…"
# Capturar evidência de active-response (nft + log AR) enquanto a resposta está ativa
sleep 10   # dar tempo ao Wazuh para entregar a AR
incus exec ing-01 --project site-avr -- nft list table inet ssle_rl 2>&1 > "$EV/nft-ssle-rl.txt" || true
incus exec ing-01 --project site-avr -- cat /var/ossec/logs/active-responses.log 2>/dev/null > "$EV/ar.log" || true
echo "[t1/run-$N] evidência AR capturada → $EV/nft-ssle-rl.txt, $EV/ar.log"
sleep $((SETTLE - 10))
TE=$(date +%s.%N)
printf 'N=%s\nT0=%s\nT1=%s\nTE=%s\nDUR=%s\nCONC=%s\n' "$N" "$T0" "$T1" "$TE" "$DUR" "$CONC" > "$EV/times.env"
# Só analisa os runs do T490 (≥4); os de staging (1-3) estão noutro Prometheus
t490_runs=()
for d in "$HERE"/evidence/run-*; do
  r="${d##*run-}"; [ "$r" -ge 4 ] 2>/dev/null && t490_runs+=("$d")
done
python3 -I "$HERE/analyze.py" "${t490_runs[@]}"
