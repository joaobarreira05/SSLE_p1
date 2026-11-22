#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# T3 PoC in the lab (T490): an element ("bot") sends TEST spam (GTUBE) to mail-01 and tries to use it as a
# relay. Benign and limited (fixed volume; mail-01 never delivers outside). Lab only.
#   bash threats/t3-spam/run.sh <instance> <project> [mail_ip] [n_spam] [n_relay]
#   e.g.: bash threats/t3-spam/run.sh sen-01 site-opo 10.10.3.70 11 5
# Expected in Wazuh: 110304 per message, 110300 (wave) from the 10th on, 110302 at the 5th relay → firewall-drop
# on mail-01; if the same sensor is a root cause in the correlator, 110900 (meta) → quarantine.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
INST="${1:?usage: run.sh <instance> <project> [mail_ip] [n_spam] [n_relay]}"; PROJ="${2:?project}"
MAIL="${3:-10.10.3.70}"; NSPAM="${4:-11}"; NRELAY="${5:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
incus file push "$HERE/smtp-poc.sh" "$INST/tmp/smtp-poc.sh" --project "$PROJ" --quiet
echo "[t3] T0=$(date +%T) $PROJ/$INST → $MAIL: $NSPAM GTUBE + $NRELAY relay"
incus exec "$INST" --project "$PROJ" -- bash /tmp/smtp-poc.sh "$MAIL" "$NSPAM" "$NRELAY" </dev/null
echo "[t3] T1=$(date +%T). To revert the block before the timeout (600 s), on mail-01:"
echo "      incus exec mail-01 --project site-lis -- iptables -D INPUT -s <bot_ip> -j DROP"
