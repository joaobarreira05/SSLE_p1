#!/usr/bin/env bash
# Desmonta o que o deploy criou (para o profile dado). Pede confirmação (SSLE_YES=1 salta).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"; PROFILE="${SSLE_PROFILE:-staging}"
[ -f "$BUILD/containers.tsv" ] || python3 "$ROOT/infra/inventory.py" render --out "$BUILD" $([ "$PROFILE" = staging ] && echo --staging) >/dev/null
echo "Vai APAGAR os contentores/redes/projetos do profile '$PROFILE':"
cut -f1,2 "$BUILD/containers.tsv" | sed 's/\t/ @ /'
if [ "${SSLE_YES:-0}" != 1 ]; then read -r -p "Confirmar? (escreve 'sim'): " a; [ "$a" = sim ] || { echo "cancelado"; exit 1; }; fi
while IFS=$'\t' read -r name proj rest <&3; do incus delete -f "$name" --project "$proj" 2>/dev/null && echo "apagado $proj/$name" || true; done 3< "$BUILD/containers.tsv"
while IFS=$'\t' read -r bridge rest <&3; do incus network delete "$bridge" 2>/dev/null && echo "rede $bridge apagada" || true; done 3< "$BUILD/networks.tsv"
for p in $(cut -f2 "$BUILD/containers.tsv" | sort -u); do incus project delete "$p" 2>/dev/null && echo "projeto $p apagado" || true; done
echo "feito."
