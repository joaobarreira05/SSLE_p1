#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Validates the SIEM-as-code against the REAL wazuh-analysisd, without the lab:
#   bash siem/tests/run-logtest.sh            # starts a throwaway manager, runs the cases, removes it
#   SSLE_LOGTEST_KEEP=1 bash siem/tests/run-logtest.sh   # keeps the container (faster iteration)
#
# 1) docker container wazuh/wazuh-manager (same 4.14 line as the T490's wazuh-install.sh) with
#    --network none (talks to nothing) and --memory 1g;
# 2) copies siem/rules, siem/decoders and siem/lists to /var/ossec/etc and adds to ossec.conf the
#    RENDERED siem/manager/ossec-ssle.conf fragment (white_list, CDB list, commands, active-response),
#    through the same path as the deploy (infra/inventory.py wazuh-manager), with fictitious agent IDs;
# 3) restarts the manager and FAILS if analysisd/execd complain (rules, decoders, lists or AR);
# 4) runs siem/tests/cases.json through the logtest socket (siem/tests/logtest_cases.py).
# ⚠️ Run this BEFORE putting rules on the T490 manager: an invalid rule makes analysisd
#    reject the whole local_rules.xml (it happened with 110002 — see siem/tests/README.md).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.10}"
NAME="${SSLE_LOGTEST_NAME:-ssle-logtest}"
PY=/var/ossec/framework/python/bin/python3
command -v docker >/dev/null || { echo "needs docker (only for this test)"; exit 2; }

wait_socket() {
  for _ in $(seq 1 45); do
    docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null && return 0
    sleep 2
  done
  echo "  ✗ the logtest socket did not appear"; return 1
}

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "[logtest] starting $IMAGE (network: none)"
  docker run -d --name "$NAME" --network none --memory 1g "$IMAGE" >/dev/null
  wait_socket
fi
cleanup() { [ "${SSLE_LOGTEST_KEEP:-0}" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[logtest] loading siem/ into the manager ($(docker exec "$NAME" /var/ossec/bin/wazuh-control info -v 2>/dev/null || echo '?'))"
docker exec "$NAME" sh -c 'rm -f /var/ossec/etc/decoders/ssle_*.xml /var/ossec/etc/lists/ssle-*'
docker cp "$ROOT/siem/rules/local_rules.xml" "$NAME:/var/ossec/etc/rules/local_rules.xml"
for f in "$ROOT"/siem/decoders/*.xml; do docker cp "$f" "$NAME:/var/ossec/etc/decoders/$(basename "$f")"; done
for f in "$ROOT"/siem/lists/*; do docker cp "$f" "$NAME:/var/ossec/etc/lists/$(basename "$f")"; done
# manager fragment: fictitious IDs for the response target agents (on the T490 they come from client.keys)
tmp="$(mktemp -d)"
printf '001 core-responder\n002 avr-ing-01\n003 lis-web-01\n' > "$tmp/agents"
python3 "$ROOT/infra/inventory.py" wazuh-manager --host t490 --agents "$tmp/agents" > "$tmp/ossec-ssle.conf"
# merge (not just append) — see siem/manager/apply.py; twice to prove it is idempotent
docker cp "$NAME:/var/ossec/etc/ossec.conf" "$tmp/ossec.conf"
python3 "$ROOT/siem/manager/apply.py" "$tmp/ossec.conf" "$tmp/ossec-ssle.conf" > "$tmp/once"
python3 "$ROOT/siem/manager/apply.py" "$tmp/once" "$tmp/ossec-ssle.conf" > "$tmp/twice"
cmp -s "$tmp/once" "$tmp/twice" || { echo "  ✗ siem/manager/apply.py is not idempotent"; diff "$tmp/once" "$tmp/twice" | head; exit 1; }
docker cp "$tmp/once" "$NAME:/var/ossec/etc/ossec.conf"; rm -rf "$tmp"
docker exec "$NAME" sh -c '
  chown root:wazuh /var/ossec/etc/ossec.conf && chmod 660 /var/ossec/etc/ossec.conf
  chown -R wazuh:wazuh /var/ossec/etc/rules /var/ossec/etc/decoders /var/ossec/etc/lists
  : > /var/ossec/logs/ossec.log
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true'
wait_socket
sleep 2
errs=$(docker exec "$NAME" sh -c "grep -E 'wazuh-(analysisd|execd|remoted): (ERROR|CRITICAL|WARNING)' /var/ossec/logs/ossec.log" || true)
if [ -n "$errs" ]; then
  echo "  ✗ the manager rejected/complained about siem/:"; sed 's/^/      /' <<<"$errs"; exit 1
fi
ar=$(docker exec "$NAME" sh -c 'cat /var/ossec/etc/shared/ar.conf 2>/dev/null' || true)
for c in ssle-quarantine ssle-ratelimit; do
  grep -q "^$c" <<<"$ar" || { echo "  ✗ the manager did not publish command $c in ar.conf:"; sed 's/^/      /' <<<"$ar"; exit 1; }
done
echo "  ✓ rules, decoders, lists and responses (ossec-ssle.conf) loaded with no errors or warnings"
echo "    ar.conf: $(tr '\n' ' ' <<<"$ar")"
if [ -f "$ROOT/siem/tests/cases.json" ]; then
  docker cp "$ROOT/siem/tests/logtest_cases.py" "$NAME:/tmp/logtest_cases.py"
  docker cp "$ROOT/siem/tests/cases.json" "$NAME:/tmp/cases.json"
  echo "[logtest] cases (siem/tests/cases.json)"
  docker exec "$NAME" "$PY" /tmp/logtest_cases.py /tmp/cases.json
else
  echo "  · no siem/tests/cases.json: only the loading was validated"
fi
