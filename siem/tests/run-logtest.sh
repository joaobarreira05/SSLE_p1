#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Valida o SIEM-como-código contra o wazuh-analysisd REAL, sem o lab:
#   bash siem/tests/run-logtest.sh            # sobe um manager descartável, corre os casos, apaga-o
#   SSLE_LOGTEST_KEEP=1 bash siem/tests/run-logtest.sh   # mantém o contentor (iterar mais depressa)
#
# 1) contentor docker wazuh/wazuh-manager (mesma linha 4.14 do wazuh-install.sh do T490) com
#    --network none (não fala com nada) e --memory 1g;
# 2) copia siem/rules, siem/decoders e siem/lists para /var/ossec/etc e acrescenta ao ossec.conf o
#    fragmento siem/manager/ossec-ssle.conf RENDERIZADO (white_list, lista CDB, commands, active-response),
#    pelo mesmo caminho do deploy (infra/inventory.py wazuh-manager), com IDs de agente fictícios;
# 3) reinicia o manager e FALHA se o analysisd/execd se queixarem (regras, decoders, listas ou AR);
# 4) corre siem/tests/cases.json pelo socket do logtest (siem/tests/logtest_cases.py).
# ⚠️ Correr isto ANTES de pôr regras no manager do T490: uma regra inválida faz o analysisd
#    recusar o local_rules.xml inteiro (aconteceu com a 110002 — ver siem/tests/README.md).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.10}"
NAME="${SSLE_LOGTEST_NAME:-ssle-logtest}"
PY=/var/ossec/framework/python/bin/python3
command -v docker >/dev/null || { echo "precisa de docker (só para este teste)"; exit 2; }

wait_socket() {
  for _ in $(seq 1 45); do
    docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null && return 0
    sleep 2
  done
  echo "  ✗ o socket do logtest não apareceu"; return 1
}

if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "[logtest] a arrancar $IMAGE (rede: none)"
  docker run -d --name "$NAME" --network none --memory 1g "$IMAGE" >/dev/null
  wait_socket
fi
cleanup() { [ "${SSLE_LOGTEST_KEEP:-0}" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[logtest] a carregar siem/ no manager ($(docker exec "$NAME" /var/ossec/bin/wazuh-control info -v 2>/dev/null || echo '?'))"
docker exec "$NAME" sh -c 'rm -f /var/ossec/etc/decoders/ssle_*.xml /var/ossec/etc/lists/ssle-*'
docker cp "$ROOT/siem/rules/local_rules.xml" "$NAME:/var/ossec/etc/rules/local_rules.xml"
for f in "$ROOT"/siem/decoders/*.xml; do docker cp "$f" "$NAME:/var/ossec/etc/decoders/$(basename "$f")"; done
for f in "$ROOT"/siem/lists/*; do docker cp "$f" "$NAME:/var/ossec/etc/lists/$(basename "$f")"; done
# fragmento do manager: IDs fictícios para os agentes-alvo das respostas (no T490 vêm do client.keys)
tmp="$(mktemp -d)"
printf '001 core-responder\n002 avr-ing-01\n003 lis-web-01\n' > "$tmp/agents"
python3 "$ROOT/infra/inventory.py" wazuh-manager --host t490 --agents "$tmp/agents" > "$tmp/ossec-ssle.conf"
# fundir (não só acrescentar) — ver siem/manager/apply.py; 2× para provar que é idempotente
docker cp "$NAME:/var/ossec/etc/ossec.conf" "$tmp/ossec.conf"
python3 "$ROOT/siem/manager/apply.py" "$tmp/ossec.conf" "$tmp/ossec-ssle.conf" > "$tmp/once"
python3 "$ROOT/siem/manager/apply.py" "$tmp/once" "$tmp/ossec-ssle.conf" > "$tmp/twice"
cmp -s "$tmp/once" "$tmp/twice" || { echo "  ✗ siem/manager/apply.py não é idempotente"; diff "$tmp/once" "$tmp/twice" | head; exit 1; }
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
  echo "  ✗ o manager rejeitou/queixou-se do siem/:"; sed 's/^/      /' <<<"$errs"; exit 1
fi
ar=$(docker exec "$NAME" sh -c 'cat /var/ossec/etc/shared/ar.conf 2>/dev/null' || true)
for c in ssle-quarantine ssle-ratelimit; do
  grep -q "^$c" <<<"$ar" || { echo "  ✗ o manager não publicou o comando $c no ar.conf:"; sed 's/^/      /' <<<"$ar"; exit 1; }
done
echo "  ✓ regras, decoders, listas e respostas (ossec-ssle.conf) carregados sem erros nem avisos"
echo "    ar.conf: $(tr '\n' ' ' <<<"$ar")"
if [ -f "$ROOT/siem/tests/cases.json" ]; then
  docker cp "$ROOT/siem/tests/logtest_cases.py" "$NAME:/tmp/logtest_cases.py"
  docker cp "$ROOT/siem/tests/cases.json" "$NAME:/tmp/cases.json"
  echo "[logtest] casos (siem/tests/cases.json)"
  docker exec "$NAME" "$PY" /tmp/logtest_cases.py /tmp/cases.json
else
  echo "  · sem siem/tests/cases.json: só validei o carregamento"
fi
