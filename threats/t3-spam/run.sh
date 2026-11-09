#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PoC da T3 no lab (T490): um elemento ("bot") envia spam de TESTE (GTUBE) ao mail-01 e tenta usá-lo como
# relay. Benigno e limitado (volume fixo; o mail-01 nunca entrega para fora). Só no lab.
#   bash threats/t3-spam/run.sh <instância> <projeto> [ip_mail] [n_spam] [n_relay]
#   ex.: bash threats/t3-spam/run.sh sen-01 site-opo 10.10.3.70 11 5
# Esperado no Wazuh: 110304 por mensagem, 110300 (vaga) a partir da 10.ª, 110302 ao 5.º relay → firewall-drop
# no mail-01; se o mesmo sensor for causa raiz no correlator, 110900 (meta) → quarentena.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
INST="${1:?uso: run.sh <instância> <projeto> [ip_mail] [n_spam] [n_relay]}"; PROJ="${2:?projeto}"
MAIL="${3:-10.10.3.70}"; NSPAM="${4:-11}"; NRELAY="${5:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
incus file push "$HERE/smtp-poc.sh" "$INST/tmp/smtp-poc.sh" --project "$PROJ" --quiet
echo "[t3] T0=$(date +%T) $PROJ/$INST → $MAIL: $NSPAM GTUBE + $NRELAY relay"
incus exec "$INST" --project "$PROJ" -- bash /tmp/smtp-poc.sh "$MAIL" "$NSPAM" "$NRELAY" </dev/null
echo "[t3] T1=$(date +%T). Reverter o bloqueio antes do timeout (600 s), no mail-01:"
echo "      incus exec mail-01 --project site-lis -- iptables -D INPUT -s <ip_do_bot> -j DROP"
