#!/usr/bin/env bash
# Demo de deteção->correlação->causa raiz: pára o sto-01 e segue o incidente.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBS_IP="$(cut -f3 "$ROOT/build/obs.tsv")"
INC() { incus exec obs --project core -- cat /var/log/ssle/incidents.json 2>/dev/null </dev/null; }
incus exec obs --project core -- sh -c ': > /var/log/ssle/incidents.json; systemctl restart ssle-correlator prometheus-alertmanager' </dev/null
sleep 3 || true
echo ">>> T0 $(date +%T): parar sto-01"; incus stop sto-01 --project site-avr </dev/null
for i in $(seq 1 24); do
  sleep 5 || true
  am=$(curl -s "http://$OBS_IP:9093/api/v2/alerts" | jq -r '[.[]|select(.status.state=="active")|.labels.alertname]|sort|join("+")')
  n=$(INC | grep -c . || true)
  echo "  [$((i*5))s] alertmanager:${am:-—}  incidentes:${n:-0}"
  [ "${n:-0}" -ge 1 ] && [ "$am" = "ElementDown+ServiceDegraded" ] && break
done
echo "=== incidente ==="; INC | tail -1 | jq .
echo ">>> recuperar"; incus start sto-01 --project site-avr </dev/null
