#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Aplica o SIEM-como-código ao MANAGER (corre DENTRO do core/wazuh, como root). Chamado pelo
# infra/deploy.sh (perfil full) e pelo siem/tests/it-agents.sh — o mesmo código nos dois sítios.
#
#   configure-manager.sh [pacote]          # pacote = /tmp/ssle-siem (default), com:
#     rules/ decoders/ lists/              → /var/ossec/etc/…
#     shared/<grupo>/agent.conf            → /var/ossec/etc/shared/<grupo>/ (validado com verify-agent-conf)
#     groups.txt                           → grupos a criar ANTES das inscrições (agent_groups -a)
#     ossec-ssle.conf                      → fundido no ossec.conf por apply.py (white_list, CDB, respostas)
#     apply.py
# Falha fechada: guarda o ossec.conf/regras ATUAIS; se o manager se queixar depois do restart, repõe-nos,
# reinicia e sai ≠ 0 (fica o último estado bom, nunca um SIEM meio-configurado sem regras).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
PKG="${1:-/tmp/ssle-siem}"
O=/var/ossec
PY="$O/framework/python/bin/python3"
[ -x "$PY" ] || PY=python3
say() { echo "[manager] $*"; }
BK="$O/etc/ssle-last-good"

rm -rf "$BK"; mkdir -p "$BK"
cp -a "$O/etc/ossec.conf" "$O/etc/rules/local_rules.xml" "$BK/" 2>/dev/null || true
cp -a "$O"/etc/decoders/ssle_*.xml "$O"/etc/lists/ssle-* "$BK/" 2>/dev/null || true

rm -f "$O"/etc/decoders/ssle_*.xml "$O"/etc/lists/ssle-*
install -o wazuh -g wazuh -m 660 "$PKG/rules/local_rules.xml" "$O/etc/rules/local_rules.xml"
for f in "$PKG"/decoders/*.xml; do install -o wazuh -g wazuh -m 660 "$f" "$O/etc/decoders/"; done
for f in "$PKG"/lists/*; do install -o wazuh -g wazuh -m 660 "$f" "$O/etc/lists/"; done

# grupos (antes das inscrições: o authd recusa um agente com um grupo que não existe)
while read -r g; do
  [ -z "$g" ] && continue
  [ -d "$O/etc/shared/$g" ] || "$O/bin/agent_groups" -a -g "$g" -q >/dev/null
done < "$PKG/groups.txt"
for d in "$PKG"/shared/*/; do
  g="$(basename "$d")"
  [ -d "$O/etc/shared/$g" ] || "$O/bin/agent_groups" -a -g "$g" -q >/dev/null
  "$O/bin/verify-agent-conf" -f "$d/agent.conf" >/dev/null 2>&1 \
    || { say "✗ shared/$g/agent.conf inválido:"; "$O/bin/verify-agent-conf" -f "$d/agent.conf" || true; exit 1; }
  install -o wazuh -g wazuh -m 660 "$d/agent.conf" "$O/etc/shared/$g/agent.conf"
done
say "grupos: $(tr '\n' ' ' < "$PKG/groups.txt")"

"$PY" "$PKG/apply.py" "$O/etc/ossec.conf" "$PKG/ossec-ssle.conf" > "$O/etc/ossec.conf.new"
install -o root -g wazuh -m 660 "$O/etc/ossec.conf.new" "$O/etc/ossec.conf"; rm -f "$O/etc/ossec.conf.new"

restart() {
  : > "$O/logs/ossec.log"
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then systemctl restart wazuh-manager
  else "$O/bin/wazuh-control" restart >/dev/null 2>&1 || true; fi
  for _ in $(seq 1 60); do [ -S "$O/queue/sockets/logtest" ] && break; sleep 2; done
  sleep 3
}
restart
# avisos de config vêm do analysisd/execd/authd; do remoted só contam erros (durante o restart os agentes
# religam e aparece "WARNING: (1246): Unable to send file 'merged.mg'", que é transitório — visto no it-agents.sh)
errs=$(grep -E 'wazuh-(analysisd|execd|authd): (ERROR|CRITICAL|WARNING)|wazuh-remoted: (ERROR|CRITICAL)' "$O/logs/ossec.log" || true)
if [ -n "$errs" ]; then
  say "✗ o manager queixou-se — a repor o último estado bom:"; sed 's/^/    /' <<<"$errs"
  cp -a "$BK/ossec.conf" "$O/etc/ossec.conf"; cp -a "$BK/local_rules.xml" "$O/etc/rules/local_rules.xml"
  rm -f "$O"/etc/decoders/ssle_*.xml "$O"/etc/lists/ssle-*
  cp -a "$BK"/ssle_*.xml "$O/etc/decoders/" 2>/dev/null || true; cp -a "$BK"/ssle-* "$O/etc/lists/" 2>/dev/null || true
  restart; exit 1
fi
say "✓ regras, decoders, listas, grupos e respostas aplicados (sem erros nem avisos)"
