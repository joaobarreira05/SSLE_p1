#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Installs and enrols the Wazuh agent on an element (runs INSIDE the Debian container, as root).
# Called by infra/deploy.sh (full profile, via incus exec) and by siem/tests/it-agents.sh (via docker
# exec) — the same code in both places, so that the test stands for the deploy.
#
#   install-agent.sh <manager_ip> <agent_name> <groups> <role> <site> <instance> [host]
#   e.g.: install-agent.sh 10.10.0.30 opo-sen-01 site-opo,role-sensor sensor opo sen-01 t490
#
# Extra packages per role: rsyslog (auth.log/mail.log: Debian trixie only has journald), jq (responses),
# nftables (ssle-ratelimit on exposed services). Own responses: if present in /tmp/ssle-ar/*.sh, they go
# to /var/ossec/active-response/bin (root:wazuh 750). Re-entrant: if the agent is already installed and
# enrolled, it only reapplies the local configuration and restarts.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
MANAGER="${1:?manager_ip}"; NAME="${2:?name}"; GROUPS_="${3:?groups}"; ROLE="${4:?role}"
SITE="${5:?site}"; INST="${6:?instance}"; HOSTL="${7:-t490}"
VER="${WAZUH_AGENT_VERSION:-4.14.10-1}"          # = manager version (the agent can never be newer)
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -qq -o Dpkg::Use-Pty=0 --no-install-recommends)
say() { echo "[agent:$NAME] $*"; }

extra=(jq)
case "$ROLE" in
  sensor) extra+=(rsyslog iproute2) ;;         # iproute2: the "ss" of the 533 command (role-sensor agent.conf)
  mail) extra+=(rsyslog iptables) ;;           # iptables: Wazuh firewall-drop (110302)
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
  # package deployment variables: postinst writes the manager and the enrolment (authd, port 1515) with groups
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$NAME" WAZUH_AGENT_GROUP="$GROUPS_" \
    "${APT[@]}" install "wazuh-agent=$VER" >/dev/null
  apt-mark hold wazuh-agent >/dev/null          # an apt upgrade must not move the agent ahead of the manager
  say "wazuh-agent $VER installed (manager $MANAGER, groups $GROUPS_)"
fi

# identity = the Prometheus one (R1): labels in the agent's own ossec.conf, between markers (idempotent)
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

# The package's default ossec.conf also runs "netstat -tulpn" under the alias "netstat listening ports" (every
# 360 s). With two commands on one alias, check_diff compares one's output with the other's and 533 → 110202
# fires on every switch, with no port change at all (false positives measured on the T490 on 22/11). The only
# port check is the role-sensor agent.conf one, so the default block goes.
perl -0pi -e 's#\n[ \t]*<localfile>\s*<log_format>full_command</log_format>\s*<command>netstat -tulpn[^<]*</command>\s*<alias>netstat listening ports</alias>\s*<frequency>\d+</frequency>\s*</localfile>##g' "$conf"

# commands coming from the manager (role-sensor agent.conf: "netstat listening ports") only run with this
lio=/var/ossec/etc/local_internal_options.conf
if [ "$ROLE" = sensor ]; then
  grep -q '^logcollector.remote_commands=1' "$lio" 2>/dev/null || echo 'logcollector.remote_commands=1' >> "$lio"
fi

# own responses
if compgen -G "/tmp/ssle-ar/*.sh" >/dev/null; then
  for f in /tmp/ssle-ar/*.sh; do
    install -o root -g wazuh -m 750 "$f" "/var/ossec/active-response/bin/$(basename "$f")"
  done
  say "responses: $(cd /tmp/ssle-ar && echo *.sh)"
fi
if [ -s /tmp/ssle-fleet.tsv ]; then install -o root -g wazuh -m 640 /tmp/ssle-fleet.tsv /var/ossec/etc/ssle-fleet.tsv; fi
# logcollector only reads what arrives AFTER it opens the file, and rsyslog only creates auth.log/mail.log on
# the 1st message: without the touch, the first lines are lost on an agent restart (seen in it-agents.sh)
mkdir -p /var/log/ssle
case "$ROLE" in
  sensor)
    touch /var/log/auth.log
    # real-time FIM only watches directories that exist when the agent starts (110201)
    mkdir -p /etc/cron.d /etc/systemd/system; install -d -m 700 /root/.ssh ;;
  mail) touch /var/log/mail.log ;;
  ingestion|web) touch /var/log/ssle/access.log ;;
  observability) touch /var/log/ssle/incidents.json ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  case "$ROLE" in sensor|mail) systemctl enable --now rsyslog >/dev/null 2>&1 || true ;; esac
  systemctl daemon-reload; systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent
else   # container without systemd (Docker test)
  case "$ROLE" in sensor|mail) pgrep -x rsyslogd >/dev/null || rsyslogd 2>/dev/null || true ;; esac
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || /var/ossec/bin/wazuh-control start >/dev/null
fi
say "agent running ($(/var/ossec/bin/wazuh-control status 2>/dev/null | grep -c 'is running') processes)"
