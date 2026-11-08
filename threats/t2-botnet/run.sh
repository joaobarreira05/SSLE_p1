#!/usr/bin/env bash
# Emulação benigna de indicadores de botnet num sensor. Reversível. Só no lab.
set -euo pipefail
SEN="${1:?uso: run.sh <sensor> <projeto> [beacon_ip]}"; PROJ="${2:?projeto}"; BEACON="${3:-10.10.1.30}"
cx() { incus exec "$SEN" --project "$PROJ" -- "$@" </dev/null; }
echo "[t2] (1) marcador de persistência em /etc/cron.d"
cx sh -c 'echo "* * * * * root : ssle-benign-marker" > /etc/cron.d/ssle-marker'
echo "[t2] (2) beaconing benigno (10x) para http://$BEACON:8000/ (endpoint 200)"
cx sh -c "for i in \$(seq 1 10); do (command -v curl >/dev/null && curl -s -o /dev/null http://$BEACON:8000/ || true); sleep 3; done" || true
echo "[t2] (3) logins falhados simulados (log de auth: 8 = o frequency da 5763 → 110200)"
# -t sshd: sem a etiqueta o program_name seria "root" e o decoder sshd do Wazuh nunca a apanhava
cx sh -c 'command -v logger >/dev/null && for i in $(seq 1 8); do logger -t sshd -p auth.info "Failed password for root from 10.10.99.66 port 2222 ssh2"; done || true'
echo "[t2] indicadores injetados. Reverter: rm /etc/cron.d/ssle-marker ; ou restaurar snapshot."
