#!/usr/bin/env bash
# Benign emulation of botnet indicators on a sensor. Reversible. Lab only.
set -euo pipefail
SEN="${1:?usage: run.sh <sensor> <project> [beacon_ip]}"; PROJ="${2:?project}"; BEACON="${3:-10.10.1.30}"
cx() { incus exec "$SEN" --project "$PROJ" -- "$@" </dev/null; }
echo "[t2] (1) persistence marker in /etc/cron.d"
cx sh -c 'echo "* * * * * root : ssle-benign-marker" > /etc/cron.d/ssle-marker'
echo "[t2] (2) benign beaconing: 40 requests 3 s apart (2 min) to http://$BEACON:8000/ (endpoint 200)"
# 2 min, not 30 s: OutboundAnomaly (robust z over the 1-min outbound connection rate, for: 1m) needs to
# see the new rhythm for ≥ 2 evaluations (monitoring/tests/outbound_test.yml)
cx sh -c "for i in \$(seq 1 40); do (command -v curl >/dev/null && curl -s -o /dev/null http://$BEACON:8000/ || true); sleep 3; done" || true
echo "[t2] (3) simulated failed logins (auth log: 8 = the frequency of 5763 → 110200)"
# -t sshd: without the tag the program_name would be "root" and the Wazuh sshd decoder would never catch it
cx sh -c 'command -v logger >/dev/null && for i in $(seq 1 8); do logger -t sshd -p auth.info "Failed password for root from 10.10.99.66 port 2222 ssh2"; done || true'
echo "[t2] indicators injected. Revert: rm /etc/cron.d/ssle-marker ; or restore a snapshot."
