#!/usr/bin/env bash
# MTTD/MTTR de uma PoC: compara o instante do estímulo com o 1.o alerta e a recuperação.
# Uso: anota T0 (estímulo) e corre; lê os timestamps do incidents.json.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T0="${1:?uso: measure.sh <epoch_do_estimulo>}"
first=$(incus exec obs --project core -- sh -c 'head -1 /var/log/ssle/incidents.json' </dev/null | jq -r '.ts')
[ -n "$first" ] && echo "MTTD ~= $(( $(date -d "$first" +%s) - T0 )) s (estímulo -> 1.o incidente)"
echo "MTTR: medir do estímulo até a métrica de impacto voltar ao normal (ver Grafana/consulta)."
