#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SIEM INTEGRATION test without the lab: real Wazuh 4.14.10 manager + real wazuh-agent instances (Debian
# trixie) on their own Docker network, installed with THE SAME deploy scripts (siem/manager/
# configure-manager.sh and siem/agent/install-agent.sh). Proves end to end what logtest cannot reach:
# group enrolment, shared agent.conf, FIM (110201), remote command (110202), correlation ACROSS agents
# (110900), T3 on a real MTA (Postfix + spamd, threats/t3-spam/mail-setup.sh) and the responses running
# on the right agents (nft on ing-01, "incus pause" on the responder, firewall-drop on mail-01).
#
#   bash siem/tests/it-agents.sh             # ~6–10 min; exits ≠ 0 if any step fails
#   SSLE_IT_KEEP=1 bash siem/tests/it-agents.sh   # keeps the containers (for inspection)
#
# Network: Docker bridge with egress (the agents' apt needs packages.wazuh.com and deb.debian.org);
# NO port published on the host. The responder's "incus" is FAKE (only records its arguments).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MGR_IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.10}"
AG_IMAGE="${SSLE_IT_AGENT_IMAGE:-debian:trixie}"
P=ssle-it; NET=ssle-it
FAIL=0
ok()  { printf '  ✓ %s\n' "$*"; }
bad() { printf '  ✗ %s\n' "$*"; FAIL=1; }
step() { printf '\n[it] %s\n' "$*"; }
T="$(mktemp -d)"
# agent  container  hostname  groups  role  site  instance  docker-flags
AGENTS="core-obs $P-obs obs core,role-observability observability core obs -
core-responder $P-resp responder core,role-responder responder core responder -
avr-ing-01 $P-ing ing-01 site-avr,role-ingestion ingestion avr ing-01 --cap-add=NET_ADMIN
opo-sen-01 $P-sen sen-01 site-opo,role-sensor sensor opo sen-01 -
lis-mail-01 $P-mail mail-01 site-lis,role-mail mail lis mail-01 --cap-add=NET_ADMIN"
NAG=$(grep -c . <<<"$AGENTS")
cleanup() {
  rm -rf "$T"
  [ "${SSLE_IT_KEEP:-0}" = 1 ] && { echo "(SSLE_IT_KEEP=1: containers $P-* kept)"; return; }
  docker rm -f $P-mgr $P-obs $P-resp $P-ing $P-sen $P-mail >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
}
trap cleanup EXIT
mx() { docker exec $P-mgr "$@"; }

step "network and containers"
docker rm -f $P-mgr $P-obs $P-resp $P-ing $P-sen $P-mail >/dev/null 2>&1 || true
docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
docker run -d --name $P-mgr --hostname wazuh --network $NET --memory 1500m "$MGR_IMAGE" >/dev/null
while read -r _ c h _ _ _ _ flags; do
  # shellcheck disable=SC2046  # flags is one word ("-" = none)
  docker run -d --name "$c" --hostname "$h" --network $NET $( [ "$flags" = - ] || echo "$flags" ) "$AG_IMAGE" sleep infinity >/dev/null
done <<<"$AGENTS"
MGR_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-mgr)
for _ in $(seq 1 60); do mx test -S /var/ossec/queue/sockets/logtest 2>/dev/null && break; sleep 2; done
ok "manager $MGR_IMAGE at $MGR_IP (no host ports) + $NAG containers $AG_IMAGE"

bundle() {  # bundle <id-name file> → $T/siem (the package configure-manager.sh consumes)
  rm -rf "$T/siem"; mkdir -p "$T/siem"
  cp -r "$ROOT/siem/rules" "$ROOT/siem/decoders" "$ROOT/siem/lists" "$ROOT/siem/shared" "$T/siem/"
  cp "$ROOT/siem/manager/apply.py" "$T/siem/"
  python3 "$ROOT/infra/inventory.py" wazuh-agents --host t490 | cut -f5 | tr ',' '\n' | sort -u > "$T/siem/groups.txt"
  python3 "$ROOT/infra/inventory.py" wazuh-manager --host t490 --agents "$1" > "$T/siem/ossec-ssle.conf" 2>"$T/render.err"
}
configure() {
  mx rm -rf /tmp/ssle-siem; docker cp "$T/siem" $P-mgr:/tmp/ssle-siem
  docker cp "$ROOT/siem/manager/configure-manager.sh" $P-mgr:/tmp/configure-manager.sh
  mx bash /tmp/configure-manager.sh /tmp/ssle-siem
}

step "manager: 1st pass (no agents yet → 'defined-agent' responses are left out: fail closed)"
: > "$T/none"; bundle "$T/none"
sed 's/^/    /' "$T/render.err"
configure && ok "configure-manager.sh" || { bad "configure-manager.sh failed"; exit 1; }

step "agents: install-agent.sh (the same as the deploy) in parallel"
python3 "$ROOT/infra/inventory.py" wazuh-agents --host t490 > "$T/fleet.tsv"
printf '#!/bin/sh\necho "$*" >> /tmp/incus-calls\n' > "$T/incus"
while read -r name c h groups role site inst _; do
  docker cp "$ROOT/siem/agent/install-agent.sh" "$c:/tmp/install-agent.sh"
  docker exec "$c" mkdir -p /tmp/ssle-ar
  case "$role" in
    ingestion) docker cp "$ROOT/siem/active-response/ssle-ratelimit.sh" "$c:/tmp/ssle-ar/" ;;
    responder) docker cp "$ROOT/siem/active-response/ssle-quarantine.sh" "$c:/tmp/ssle-ar/"
               docker cp "$T/fleet.tsv" "$c:/tmp/ssle-fleet.tsv"
               docker cp "$T/incus" "$c:/usr/local/bin/incus"; docker exec "$c" chmod 755 /usr/local/bin/incus ;;
  esac
  [ "$role" = mail ] && docker cp "$ROOT/threats/t3-spam/mail-setup.sh" "$c:/tmp/mail-setup.sh"
  # mail: the MTA first (as in the deploy); mynetworks only loopback → the other containers are "outside"
  ( { { [ "$role" != mail ] || docker exec "$c" bash /tmp/mail-setup.sh "127.0.0.0/8"; } \
      && docker exec "$c" bash /tmp/install-agent.sh "$MGR_IP" "$name" "$groups" "$role" "$site" "$inst" t490; } \
      > "$T/install-$name.log" 2>&1; echo $? > "$T/rc-$name" ) &
done <<<"$AGENTS"
wait
while read -r name _; do
  if [ "$(cat "$T/rc-$name")" = 0 ]; then ok "$name: $(tail -1 "$T/install-$name.log")"
  else bad "$name: install-agent.sh failed"; tail -5 "$T/install-$name.log" | sed 's/^/      /'; fi
done <<<"$AGENTS"
[ $FAIL -eq 0 ] || exit 1

wait_active() {
  for _ in $(seq 1 60); do
    [ "$(mx /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active$')" -ge "$NAG" ] && return 0; sleep 3
  done; return 1
}
wait_active && ok "$NAG agents enrolled and Active" || { bad "agents did not become Active"; mx /var/ossec/bin/agent_control -l; exit 1; }

step "manager: 2nd pass with the real IDs (client.keys: only the id and name columns leave the container)"
mx sh -c "cut -d' ' -f1,2 /var/ossec/etc/client.keys" > "$T/agents"
sed 's/^/    /' "$T/agents"
bundle "$T/agents"
configure && ok "configure-manager.sh with responses for the enrolled agents" || { bad "2nd pass failed"; exit 1; }
wait_active && ok "agents reconnected after the manager restart" || bad "agents did not reconnect"
for g in site-opo role-sensor; do
  mx /var/ossec/bin/agent_groups -l -g "$g" 2>/dev/null | grep -q opo-sen-01 && ok "opo-sen-01 in group $g" || bad "opo-sen-01 not in group $g"
done
for _ in $(seq 1 40); do docker exec $P-sen grep -q 'netstat listening ports' /var/ossec/etc/shared/merged.mg 2>/dev/null && break; sleep 3; done
docker exec $P-sen grep -q 'netstat listening ports' /var/ossec/etc/shared/merged.mg && ok "sensor received the shared agent.conf (merged.mg)" \
  || bad "sensor without the role-sensor agent.conf"
# a 2nd command on the same alias (the package default netstat -tulpn) makes check_diff fire 110202 with no change
docker exec $P-sen grep -q 'netstat -tulpn' /var/ossec/etc/ossec.conf && bad "default netstat command still in ossec.conf (110202 false positives)" \
  || ok "only one command under the 'netstat listening ports' alias"

cat > "$T/find.py" <<'PY'
import json, sys
rule, agent, since = sys.argv[1], sys.argv[2], int(sys.argv[3])
hit = None
with open("/var/ossec/logs/alerts/alerts.json", encoding="utf-8", errors="replace") as fh:
    fh.seek(since)
    for line in fh:
        try: a = json.loads(line)
        except ValueError: continue
        if a.get("rule", {}).get("id") == rule and (agent == "-" or a.get("agent", {}).get("name") == agent):
            hit = a
if hit:
    d = hit.get("data", {}); s = hit.get("syscheck", {})
    print("%s L%s agent=%s labels=%s srcip=%s path=%s | %s" % (hit["rule"]["id"], hit["rule"]["level"], hit["agent"].get("name"),
          ",".join("%s=%s" % kv for kv in sorted(hit["agent"].get("labels", {}).items())) or "-",
          d.get("srcip", "-"), s.get("path", "-"), hit["rule"]["description"]))
    sys.exit(0)
sys.exit(1)
PY
docker cp "$T/find.py" $P-mgr:/tmp/find.py
mark() { mx sh -c 'stat -c %s /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0'; }
wait_in() {  # wait_in <container> <timeout_s> <description> <command…>
  local c="$1" to="$2" d="$3"; shift 3
  for _ in $(seq 1 $(( to / 2 ))); do docker exec "$c" sh -c "$*" >/dev/null 2>&1 && { ok "$d"; return 0; }; sleep 2; done
  bad "$d (did not happen within ${to}s)"; return 1
}
web() {  # web <ip> <n> → "combined" lines in the ing-01 access log (what the service writes with SSLE_ACCESS_LOG)
  docker exec $P-ing sh -c "for i in \$(seq 1 $2); do echo '$1 - - [08/Nov/2026:20:00:01 +0000] \"GET /work HTTP/1.1\" 200 15 \"-\" \"curl/8.14.1\"' >> /var/log/ssle/access.log; done"
}
incident() {  # incident <site> <inst> <role> <ip> → correlator line on obs
  docker exec $P-obs sh -c "echo '{\"origin\":\"prometheus\",\"status\":\"open\",\"severity\":\"critical\",\"site\":\"$1\",\"root_cause\":\"ssle:pt:$1:t490:$2\",\"root_cause_instance\":\"$2\",\"root_cause_role\":\"$3\",\"root_cause_ip\":\"$4\",\"srcip\":\"$4\",\"alert_names\":[\"OutboundAnomaly\"]}' >> /var/log/ssle/incidents.json"
}
# stimulus with retries: if an agent is in the middle of a merged.mg reload, logcollector reopens the
# files at the END and loses the lines written in between (seen: 7 s gap). Retrying does not mask the
# detection — the attempt in which it appeared is reported.
try_alert() {  # try_alert <rule> <agent> <s_per_attempt> <attempts> <description> <stimulus command…>
  local rule="$1" agent="$2" per="$3" n="$4" d="$5"; shift 5
  local m out k
  for k in $(seq 1 "$n"); do
    m=$(mark); "$@"
    for _ in $(seq 1 $(( per / 3 ))); do
      out=$(mx /var/ossec/framework/python/bin/python3 /tmp/find.py "$rule" "$agent" "$m" 2>/dev/null) && {
        ok "$d → $out$( [ "$k" -gt 1 ] && echo " (attempt $k)")"; return 0; }
      sleep 3
    done
  done
  bad "$d: rule $rule did not appear ($n × ${per}s, agent $agent)"; return 1
}
ssh_fail()  { docker exec $P-sen sh -c 'for i in $(seq 1 8); do logger -t sshd -p auth.info "Failed password for root from 10.10.99.66 port 2222 ssh2"; done'; }
marker()    { docker exec $P-sen sh -c 'echo "* * * * * root : ssle-benign-marker $(date +%s)" > /etc/cron.d/ssle-marker'; }
listener()  { docker exec -d $P-sen perl -MIO::Socket::INET -e 'my $s = IO::Socket::INET->new(LocalPort => 31337, Listen => 1, ReuseAddr => 1) or die; sleep 900'; }
sleep 20   # let the shared agent.conf reload settle on the agents

step "T2 on the sensor (opo-sen-01)"
try_alert 110200 opo-sen-01 30 3 "SSH brute force (logger -t sshd, as in threats/t2-botnet/run.sh)" ssh_fail
try_alert 110201 opo-sen-01 60 3 "real-time FIM: persistence marker in /etc/cron.d" marker
try_alert 110202 opo-sen-01 150 1 "new listening port (31337) via the agent.conf remote command" listener

step "T1 on ing-01: white_list first, then the response (the ignore=60 of 110100 is per rule)"
if try_alert 110100 avr-ing-01 30 2 "the DoS pattern coming from prom-01 (10.10.1.10, on the white_list)" web 10.10.1.10 120; then
  sleep 15
  docker exec $P-ing sh -c 'nft list set inet ssle_rl limited 2>/dev/null | grep -q 10.10.1.10' \
    && bad "white_list ignored: 10.10.1.10 was limited" || ok "white_list: 10.10.1.10 alerted but was NOT limited"
fi
sleep 62
try_alert 110100 avr-ing-01 30 2 "100 requests from the same origin in 10 s (10.10.9.10)" web 10.10.9.10 120
wait_in $P-ing 45 "response executed ON ing-01: 10.10.9.10 in the nft set inet ssle_rl limited" \
  "nft list set inet ssle_rl limited | grep -q 10.10.9.10"
docker exec $P-ing sh -c 'grep RATELIMIT /var/ossec/logs/active-responses.log | tail -1' | sed 's/^/      /'

step "T2 → quarantine (correlator on obs → 110210 → ssle-quarantine on the responder)"
try_alert 110210 core-obs 30 2 "correlator incident: sensor sen-01 is the root cause" incident opo sen-01 sensor 10.10.2.50
wait_in $P-resp 45 "response executed ON the responder: incus pause t490:sen-01 --project site-opo" \
  "grep -qx 'pause t490:sen-01 --project site-opo' /tmp/incus-calls"
docker exec $P-resp sh -c 'grep ssle-quarantine /var/ossec/logs/active-responses.log | tail -1' | sed 's/^/      /'

step "meta-correlation ACROSS agents (obs + ing-01): one botnet, two impacts"
try_alert 110210 core-obs 30 2 "sen-02 is the root cause (agent obs)" incident opo sen-02 sensor 10.10.2.51
sleep 50   # the ignore=60 of 110100 (it fired for 10.10.9.10 a moment ago)
try_alert 110900 avr-ing-01 30 2 "sen-02 is root cause (obs) AND DoS origin (ing-01)" web 10.10.2.51 110
wait_in $P-resp 45 "quarantine of sen-02" "grep -qx 'pause t490:sen-02 --project site-opo' /tmp/incus-calls"
echo "      calls to the (fake) incus on the responder:"; docker exec $P-resp cat /tmp/incus-calls | sed 's/^/        /'

step "T3 on mail-01 (real Postfix + spamd) + firewall-drop"
MAIL_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-mail)
OBS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-obs)
SEN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-sen)
for c in $P-obs $P-sen; do docker cp "$ROOT/threats/t3-spam/smtp-poc.sh" "$c:/tmp/smtp-poc.sh"; done
poc() { docker exec "$P-$1" bash /tmp/smtp-poc.sh "$MAIL_IP" "$2" "$3" | sed 's/^/      /'; }   # poc <client> <spam> <relay>
try_alert 110304 lis-mail-01 45 2 "GTUBE accepted and flagged by spamd (score 1000)" poc obs 1 0
try_alert 110300 lis-mail-01 60 1 "wave: 10 more GTUBE in 2 min" poc obs 10 0
try_alert 110302 lis-mail-01 45 1 "5 refused relays (554) from obs" poc obs 0 5
wait_in $P-mail 45 "firewall-drop executed ON mail-01: $OBS_IP blocked" "iptables -S | grep -q -- '-s $OBS_IP/32 -j DROP'"
echo "      client side, after the block:"; docker exec $P-obs bash /tmp/smtp-poc.sh "$MAIL_IP" 1 0 | sed 's/^/        /'

step "meta-correlation via relay (obs + mail-01): the compromised sensor tries to use the MTA"
try_alert 110210 core-obs 30 2 "sen-01 is the root cause (agent obs, srcip $SEN_IP)" incident opo sen-01 sensor "$SEN_IP"
sleep 50   # the ignore=60 of 110302 (it fired for obs a moment ago)
try_alert 110900 lis-mail-01 45 2 "sen-01 is root cause (obs) AND tries to relay on mail-01" poc sen 0 5
wait_in $P-mail 45 "firewall-drop ON mail-01 also via 110900: $SEN_IP blocked" "iptables -S | grep -q -- '-s $SEN_IP/32 -j DROP'"
echo "      the bot, client side, after the block:"; docker exec $P-sen bash /tmp/smtp-poc.sh "$MAIL_IP" 1 0 | sed 's/^/        /'

echo
[ $FAIL -eq 0 ] && echo "RESULT: SIEM integration OK ✅" || echo "RESULT: failures ✗"
exit $FAIL
