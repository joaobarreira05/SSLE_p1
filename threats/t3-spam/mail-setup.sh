#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MTA of the lis site (mail-01): Postfix + SpamAssassin, as in lecture 8 (runs INSIDE the Debian container, root).
# Called by infra/deploy.sh (full profile) and by siem/tests/it-agents.sh — the same code in both.
#
#   mail-setup.sh "<mynetworks>" [domain]      e.g.: mail-setup.sh "127.0.0.0/8 10.10.3.0/24" lis.ssle.lab
#
# · relay ONLY for mynetworks: reject_unauth_destination → "554 5.7.1 Relay access denied" (rule 3301 →
#   110302). The package default is defer_unauth_destination, which answers 450 and would match 3303 — so
#   it is made explicit;
# · after-queue content filter: smtpd → pipe → spamc → spamd → sendmail (lecture 8 §4.5), user debian-spamd;
# · anvil: per-client message/connection limit (T3 prevention);
# · NOTHING leaves the lab: default_transport/relay_transport = error (the lab never sends mail outside).
# Re-entrant (postconf -e and sed are idempotent).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
MYNET="${1:?mynetworks}"; DOMAIN="${2:-lis.ssle.lab}"
export DEBIAN_FRONTEND=noninteractive
say() { echo "[mail] $*"; }

need=()
for p in postfix spamassassin spamd spamc rsyslog; do dpkg -s "$p" >/dev/null 2>&1 || need+=("$p"); done
if [ ${#need[@]} -gt 0 ]; then
  echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
  echo "postfix postfix/mailname string mail-01.$DOMAIN" | debconf-set-selections
  apt-get update -qq && apt-get install -y -qq -o Dpkg::Use-Pty=0 --no-install-recommends "${need[@]}" >/dev/null
fi

postconf -e "myhostname = mail-01.$DOMAIN" "mydomain = $DOMAIN" \
  'mydestination = $myhostname, $mydomain, localhost' \
  'inet_interfaces = all' 'inet_protocols = ipv4' \
  "mynetworks = $MYNET" \
  'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination' \
  'default_transport = error:the lab does not send mail outside' \
  'relay_transport = error:the lab does not send mail outside' \
  'smtpd_client_message_rate_limit = 60' 'smtpd_client_connection_rate_limit = 60' 'anvil_rate_time_unit = 60s'
mc=/etc/postfix/master.cf
grep -qE '^smtp +inet .*content_filter=spamassassin' "$mc" || \
  sed -i -E 's/^(smtp +inet +n +- +[yn] +- +- +smtpd)$/\1 -o content_filter=spamassassin/' "$mc"
grep -q '^spamassassin unix' "$mc" || cat >> "$mc" <<'EOF'
spamassassin unix - n n - - pipe flags=R user=debian-spamd argv=/usr/bin/spamc -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
EOF
id aluno >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin aluno     # local mailbox (mbox in /var/mail/aluno)
touch /var/log/mail.log

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl enable --now rsyslog >/dev/null 2>&1 || true
  # Postfix queue → Prometheus (node_exporter textfile collector), every 30 s
  mkdir -p /var/lib/prometheus/node-exporter
  cat > /etc/systemd/system/ssle-mailq.service <<'EOF'
[Unit]
Description=SSLE: Postfix queue size for node_exporter (textfile)
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'n=$$(postqueue -j 2>/dev/null | wc -l); printf "# HELP postfix_queue_messages Messages in the Postfix queue.\n# TYPE postfix_queue_messages gauge\npostfix_queue_messages %%s\n" "$$n" > /var/lib/prometheus/node-exporter/postfix.prom.tmp && mv /var/lib/prometheus/node-exporter/postfix.prom.tmp /var/lib/prometheus/node-exporter/postfix.prom'
EOF
  cat > /etc/systemd/system/ssle-mailq.timer <<'EOF'
[Unit]
Description=SSLE: Postfix queue every 30 s
[Timer]
OnBootSec=30
OnUnitActiveSec=30
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload; systemctl enable --now ssle-mailq.timer >/dev/null 2>&1
  systemctl enable spamd >/dev/null 2>&1; systemctl restart spamd
  systemctl enable postfix >/dev/null 2>&1; systemctl restart postfix
else   # container without systemd (Docker test): what the units would do
  pgrep -x rsyslogd >/dev/null || rsyslogd
  pgrep -f 'spamd child|/usr/sbin/spamd' >/dev/null || \
    spamd -d --create-prefs --max-children 2 --helper-home-dir --pidfile /run/spamd.pid
  /usr/lib/postfix/configure-instance.sh - >/dev/null 2>&1 || true   # Debian chroot (resolv.conf, …)
  postfix status >/dev/null 2>&1 && postfix reload >/dev/null 2>&1 || postfix start >/dev/null 2>&1
fi
for _ in $(seq 1 30); do (exec 3<>/dev/tcp/127.0.0.1/783) 2>/dev/null && break; sleep 1; done
(exec 3<>/dev/tcp/127.0.0.1/783) 2>/dev/null && say "spamd listening on 127.0.0.1:783" || { say "✗ spamd did not start"; exit 1; }
(exec 3<>/dev/tcp/127.0.0.1/25) 2>/dev/null && say "postfix listening on :25 (mynetworks = $MYNET; outbound delivery disabled)" \
  || { say "✗ postfix did not start"; exit 1; }
