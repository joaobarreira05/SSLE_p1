#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Instala e inscreve o agente Wazuh num elemento (corre DENTRO do contentor Debian, como root).
# Chamado pelo infra/deploy.sh (perfil full, via incus exec) e pelo siem/tests/it-agents.sh (via docker
# exec) — o mesmo código nos dois sítios, para o teste valer pelo deploy.
#
#   install-agent.sh <manager_ip> <nome_agente> <grupos> <papel> <site> <instância> [host]
#   ex.: install-agent.sh 10.10.0.30 opo-sen-01 site-opo,role-sensor sensor opo sen-01 t490
#
# Pacotes extra por papel: rsyslog (auth.log/mail.log: o Debian trixie só tem journald), jq (respostas),
# nftables (ssle-ratelimit nos serviços expostos). Respostas próprias: se existirem em /tmp/ssle-ar/*.sh,
# vão para /var/ossec/active-response/bin (root:wazuh 750). Reentrante: se o agente já está instalado e
# inscrito, só reaplica a configuração local e reinicia.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
MANAGER="${1:?manager_ip}"; NAME="${2:?nome}"; GROUPS_="${3:?grupos}"; ROLE="${4:?papel}"
SITE="${5:?site}"; INST="${6:?instância}"; HOSTL="${7:-t490}"
VER="${WAZUH_AGENT_VERSION:-4.14.10-1}"          # = versão do manager (o agente nunca pode ser mais novo)
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -qq -o Dpkg::Use-Pty=0 --no-install-recommends)
say() { echo "[agent:$NAME] $*"; }

extra=(jq)
case "$ROLE" in
  sensor) extra+=(rsyslog iproute2) ;;         # iproute2: o "ss" do comando da 533 (agent.conf role-sensor)
  mail) extra+=(rsyslog iptables) ;;           # iptables: o firewall-drop do Wazuh (110302)
  ingestion|web) extra+=(nftables) ;;
esac
need=()
for p in ca-certificates curl gnupg "${extra[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || need+=("$p"); done
if [ ${#need[@]} -gt 0 ]; then apt-get update -qq && "${APT[@]}" install "${need[@]}" >/dev/null; fi

if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  if [ ! -s /usr/share/keyrings/wazuh.gpg ]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    chmod 644 /usr/share/keyrings/wazuh.gpg
  fi
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  # variáveis de deployment do pacote: o postinst escreve o manager e a inscrição (authd, porta 1515) com grupos
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$NAME" WAZUH_AGENT_GROUP="$GROUPS_" \
    "${APT[@]}" install "wazuh-agent=$VER" >/dev/null
  apt-mark hold wazuh-agent >/dev/null          # um apt upgrade não pode pôr o agente à frente do manager
  say "wazuh-agent $VER instalado (manager $MANAGER, grupos $GROUPS_)"
fi

# identidade = a do Prometheus (R1): labels no ossec.conf do próprio agente, entre marcadores (idempotente)
conf=/var/ossec/etc/ossec.conf
sed -i '/<!-- SSLE:BEGIN -->/,/<!-- SSLE:END -->/d' "$conf"
cat >> "$conf" <<EOF
<!-- SSLE:BEGIN -->
<ossec_config>
  <labels>
    <label key="region">pt</label>
    <label key="site">$SITE</label>
    <label key="host">$HOSTL</label>
    <label key="role">$ROLE</label>
    <label key="instance">$INST</label>
  </labels>
</ossec_config>
<!-- SSLE:END -->
EOF

# comandos vindos do manager (agent.conf do role-sensor: "netstat listening ports") só correm com isto
lio=/var/ossec/etc/local_internal_options.conf
if [ "$ROLE" = sensor ]; then
  grep -q '^logcollector.remote_commands=1' "$lio" 2>/dev/null || echo 'logcollector.remote_commands=1' >> "$lio"
fi

# respostas próprias
if compgen -G "/tmp/ssle-ar/*.sh" >/dev/null; then
  for f in /tmp/ssle-ar/*.sh; do
    install -o root -g wazuh -m 750 "$f" "/var/ossec/active-response/bin/$(basename "$f")"
  done
  say "respostas: $(cd /tmp/ssle-ar && echo *.sh)"
fi
if [ -s /tmp/ssle-fleet.tsv ]; then install -o root -g wazuh -m 640 /tmp/ssle-fleet.tsv /var/ossec/etc/ssle-fleet.tsv; fi
# o logcollector só lê o que chega DEPOIS de abrir o ficheiro, e o rsyslog só cria o auth.log/mail.log na
# 1.ª mensagem: sem o touch, as primeiras linhas perdem-se num restart do agente (visto no it-agents.sh)
mkdir -p /var/log/ssle
case "$ROLE" in
  sensor)
    touch /var/log/auth.log
    # o FIM em tempo real só vigia pastas que existem quando o agente arranca (110201)
    mkdir -p /etc/cron.d /etc/systemd/system; install -d -m 700 /root/.ssh ;;
  mail) touch /var/log/mail.log ;;
  ingestion|web) touch /var/log/ssle/access.log ;;
  observability) touch /var/log/ssle/incidents.json ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  case "$ROLE" in sensor|mail) systemctl enable --now rsyslog >/dev/null 2>&1 || true ;; esac
  systemctl daemon-reload; systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent
else   # contentor sem systemd (teste em Docker)
  case "$ROLE" in sensor|mail) pgrep -x rsyslogd >/dev/null || rsyslogd 2>/dev/null || true ;; esac
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || /var/ossec/bin/wazuh-control start >/dev/null
fi
say "agente a correr ($(/var/ossec/bin/wazuh-control status 2>/dev/null | grep -c 'is running') processos)"
