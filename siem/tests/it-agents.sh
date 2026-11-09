#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Teste de INTEGRAÇÃO do SIEM sem o lab: manager Wazuh 4.14.10 real + 4 agentes wazuh-agent reais (Debian
# trixie) numa rede Docker própria, instalados com OS MESMOS scripts do deploy (siem/manager/
# configure-manager.sh e siem/agent/install-agent.sh). Prova, ponta a ponta, o que o logtest não chega:
# inscrição por grupos, agent.conf partilhado, FIM (110201), comando remoto (110202), correlação ENTRE
# agentes (110900), a T3 num MTA real (Postfix + spamd, threats/t3-spam/mail-setup.sh) e as respostas a
# executar nos agentes certos (nft no ing-01, "incus pause" no responder, firewall-drop no mail-01).
#
#   bash siem/tests/it-agents.sh             # ~6–10 min; sai ≠ 0 se algum passo falhar
#   SSLE_IT_KEEP=1 bash siem/tests/it-agents.sh   # deixa os contentores (para inspecionar)
#
# Rede: bridge Docker com saída (o apt dos agentes precisa de packages.wazuh.com e deb.debian.org);
# NENHUMA porta publicada no host. O "incus" do responder é FALSO (só regista os argumentos).
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
# agente  contentor  hostname  grupos  papel  site  instância  flags-docker
AGENTS="core-obs $P-obs obs core,role-observability observability core obs -
core-responder $P-resp responder core,role-responder responder core responder -
avr-ing-01 $P-ing ing-01 site-avr,role-ingestion ingestion avr ing-01 --cap-add=NET_ADMIN
opo-sen-01 $P-sen sen-01 site-opo,role-sensor sensor opo sen-01 -
lis-mail-01 $P-mail mail-01 site-lis,role-mail mail lis mail-01 --cap-add=NET_ADMIN"
NAG=$(grep -c . <<<"$AGENTS")
cleanup() {
  rm -rf "$T"
  [ "${SSLE_IT_KEEP:-0}" = 1 ] && { echo "(SSLE_IT_KEEP=1: contentores $P-* mantidos)"; return; }
  docker rm -f $P-mgr $P-obs $P-resp $P-ing $P-sen $P-mail >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
}
trap cleanup EXIT
mx() { docker exec $P-mgr "$@"; }

step "rede e contentores"
docker rm -f $P-mgr $P-obs $P-resp $P-ing $P-sen $P-mail >/dev/null 2>&1 || true
docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
docker run -d --name $P-mgr --hostname wazuh --network $NET --memory 1500m "$MGR_IMAGE" >/dev/null
while read -r _ c h _ _ _ _ flags; do
  # shellcheck disable=SC2046  # flags é uma palavra ("-" = nenhuma)
  docker run -d --name "$c" --hostname "$h" --network $NET $( [ "$flags" = - ] || echo "$flags" ) "$AG_IMAGE" sleep infinity >/dev/null
done <<<"$AGENTS"
MGR_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-mgr)
for _ in $(seq 1 60); do mx test -S /var/ossec/queue/sockets/logtest 2>/dev/null && break; sleep 2; done
ok "manager $MGR_IMAGE em $MGR_IP (sem portas no host) + $NAG contentores $AG_IMAGE"

bundle() {  # bundle <ficheiro id-nome> → $T/siem (o pacote que o configure-manager.sh consome)
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

step "manager: 1.ª passagem (ainda sem agentes → as respostas 'defined-agent' ficam de fora: falha fechada)"
: > "$T/none"; bundle "$T/none"
sed 's/^/    /' "$T/render.err"
configure && ok "configure-manager.sh" || { bad "configure-manager.sh falhou"; exit 1; }

step "agentes: install-agent.sh (o mesmo do deploy) em paralelo"
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
  # mail: o MTA primeiro (como no deploy); mynetworks só o loopback → os outros contentores são "de fora"
  ( { { [ "$role" != mail ] || docker exec "$c" bash /tmp/mail-setup.sh "127.0.0.0/8"; } \
      && docker exec "$c" bash /tmp/install-agent.sh "$MGR_IP" "$name" "$groups" "$role" "$site" "$inst" t490; } \
      > "$T/install-$name.log" 2>&1; echo $? > "$T/rc-$name" ) &
done <<<"$AGENTS"
wait
while read -r name _; do
  if [ "$(cat "$T/rc-$name")" = 0 ]; then ok "$name: $(tail -1 "$T/install-$name.log")"
  else bad "$name: install-agent.sh falhou"; tail -5 "$T/install-$name.log" | sed 's/^/      /'; fi
done <<<"$AGENTS"
[ $FAIL -eq 0 ] || exit 1

wait_active() {
  for _ in $(seq 1 60); do
    [ "$(mx /var/ossec/bin/agent_control -l 2>/dev/null | grep -c 'Active$')" -ge "$NAG" ] && return 0; sleep 3
  done; return 1
}
wait_active && ok "$NAG agentes inscritos e Active" || { bad "agentes não ficaram Active"; mx /var/ossec/bin/agent_control -l; exit 1; }

step "manager: 2.ª passagem com os IDs reais (client.keys: só as colunas id e nome saem do contentor)"
mx sh -c "cut -d' ' -f1,2 /var/ossec/etc/client.keys" > "$T/agents"
sed 's/^/    /' "$T/agents"
bundle "$T/agents"
configure && ok "configure-manager.sh com respostas para os agentes inscritos" || { bad "2.ª passagem falhou"; exit 1; }
wait_active && ok "agentes religados depois do restart do manager" || bad "agentes não religaram"
for g in site-opo role-sensor; do
  mx /var/ossec/bin/agent_groups -l -g "$g" 2>/dev/null | grep -q opo-sen-01 && ok "opo-sen-01 no grupo $g" || bad "opo-sen-01 fora do grupo $g"
done
for _ in $(seq 1 40); do docker exec $P-sen grep -q 'netstat listening ports' /var/ossec/etc/shared/merged.mg 2>/dev/null && break; sleep 3; done
docker exec $P-sen grep -q 'netstat listening ports' /var/ossec/etc/shared/merged.mg && ok "sensor recebeu o agent.conf partilhado (merged.mg)" \
  || bad "sensor sem o agent.conf do role-sensor"

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
wait_in() {  # wait_in <contentor> <timeout_s> <descrição> <comando…>
  local c="$1" to="$2" d="$3"; shift 3
  for _ in $(seq 1 $(( to / 2 ))); do docker exec "$c" sh -c "$*" >/dev/null 2>&1 && { ok "$d"; return 0; }; sleep 2; done
  bad "$d (não aconteceu em ${to}s)"; return 1
}
web() {  # web <ip> <n> → linhas "combined" no log de acesso do ing-01 (o que o serviço escreve com SSLE_ACCESS_LOG)
  docker exec $P-ing sh -c "for i in \$(seq 1 $2); do echo '$1 - - [08/Nov/2026:20:00:01 +0000] \"GET /work HTTP/1.1\" 200 15 \"-\" \"curl/8.14.1\"' >> /var/log/ssle/access.log; done"
}
incident() {  # incident <site> <inst> <papel> <ip> → linha do correlator no obs
  docker exec $P-obs sh -c "echo '{\"origin\":\"prometheus\",\"status\":\"open\",\"severity\":\"critical\",\"site\":\"$1\",\"root_cause\":\"ssle:pt:$1:t490:$2\",\"root_cause_instance\":\"$2\",\"root_cause_role\":\"$3\",\"root_cause_ip\":\"$4\",\"srcip\":\"$4\"}' >> /var/log/ssle/incidents.json"
}
# estímulo com repetição: se um agente estiver a meio de uma recarga do merged.mg, o logcollector reabre os
# ficheiros no FIM e perde as linhas escritas entretanto (visto: 7 s de diferença). Repetir não mascara a
# deteção — diz-se em que tentativa apareceu.
try_alert() {  # try_alert <regra> <agente> <s_por_tentativa> <tentativas> <descrição> <comando de estímulo…>
  local rule="$1" agent="$2" per="$3" n="$4" d="$5"; shift 5
  local m out k
  for k in $(seq 1 "$n"); do
    m=$(mark); "$@"
    for _ in $(seq 1 $(( per / 3 ))); do
      out=$(mx /var/ossec/framework/python/bin/python3 /tmp/find.py "$rule" "$agent" "$m" 2>/dev/null) && {
        ok "$d → $out$( [ "$k" -gt 1 ] && echo " (tentativa $k)")"; return 0; }
      sleep 3
    done
  done
  bad "$d: a regra $rule não apareceu ($n × ${per}s, agente $agent)"; return 1
}
ssh_fail()  { docker exec $P-sen sh -c 'for i in $(seq 1 8); do logger -t sshd -p auth.info "Failed password for root from 10.10.99.66 port 2222 ssh2"; done'; }
marker()    { docker exec $P-sen sh -c 'echo "* * * * * root : ssle-benign-marker $(date +%s)" > /etc/cron.d/ssle-marker'; }
listener()  { docker exec -d $P-sen perl -MIO::Socket::INET -e 'my $s = IO::Socket::INET->new(LocalPort => 31337, Listen => 1, ReuseAddr => 1) or die; sleep 900'; }
sleep 20   # deixa assentar a recarga do agent.conf partilhado nos agentes

step "T2 no sensor (opo-sen-01)"
try_alert 110200 opo-sen-01 30 3 "força bruta SSH (logger -t sshd, como o threats/t2-botnet/run.sh)" ssh_fail
try_alert 110201 opo-sen-01 60 3 "FIM em tempo real: marcador de persistência em /etc/cron.d" marker
try_alert 110202 opo-sen-01 150 1 "porta nova à escuta (31337) via comando remoto do agent.conf" listener

step "T1 no ing-01: white_list primeiro, depois a resposta (o ignore=60 da 110100 é por regra)"
if try_alert 110100 avr-ing-01 30 2 "o padrão de DoS vindo do prom-01 (10.10.1.10, na white_list)" web 10.10.1.10 120; then
  sleep 15
  docker exec $P-ing sh -c 'nft list set inet ssle_rl limited 2>/dev/null | grep -q 10.10.1.10' \
    && bad "white_list ignorada: 10.10.1.10 foi limitado" || ok "white_list: 10.10.1.10 alertou mas NÃO foi limitado"
fi
sleep 62
try_alert 110100 avr-ing-01 30 2 "100 pedidos da mesma origem em 10 s (10.10.9.10)" web 10.10.9.10 120
wait_in $P-ing 45 "resposta executada NO ing-01: 10.10.9.10 no set nft inet ssle_rl limited" \
  "nft list set inet ssle_rl limited | grep -q 10.10.9.10"
docker exec $P-ing sh -c 'grep RATELIMIT /var/ossec/logs/active-responses.log | tail -1' | sed 's/^/      /'

step "T2 → quarentena (correlator no obs → 110210 → ssle-quarantine no responder)"
try_alert 110210 core-obs 30 2 "incidente do correlator: sensor sen-01 é a causa raiz" incident opo sen-01 sensor 10.10.2.50
wait_in $P-resp 45 "resposta executada NO responder: incus pause t490:sen-01 --project site-opo" \
  "grep -qx 'pause t490:sen-01 --project site-opo' /tmp/incus-calls"
docker exec $P-resp sh -c 'grep ssle-quarantine /var/ossec/logs/active-responses.log | tail -1' | sed 's/^/      /'

step "meta-correlação ENTRE agentes (obs + ing-01): uma botnet, dois impactos"
try_alert 110210 core-obs 30 2 "sen-02 é a causa raiz (agente obs)" incident opo sen-02 sensor 10.10.2.51
sleep 50   # o ignore=60 da 110100 (disparou para 10.10.9.10 há pouco)
try_alert 110900 avr-ing-01 30 2 "sen-02 é causa raiz (obs) E origem de DoS (ing-01)" web 10.10.2.51 110
wait_in $P-resp 45 "quarentena do sen-02" "grep -qx 'pause t490:sen-02 --project site-opo' /tmp/incus-calls"
echo "      chamadas ao incus (falso) no responder:"; docker exec $P-resp cat /tmp/incus-calls | sed 's/^/        /'

step "T3 no mail-01 (Postfix + spamd reais) + firewall-drop"
MAIL_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-mail)
OBS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-obs)
SEN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-sen)
for c in $P-obs $P-sen; do docker cp "$ROOT/threats/t3-spam/smtp-poc.sh" "$c:/tmp/smtp-poc.sh"; done
poc() { docker exec "$P-$1" bash /tmp/smtp-poc.sh "$MAIL_IP" "$2" "$3" | sed 's/^/      /'; }   # poc <cliente> <spam> <relay>
try_alert 110304 lis-mail-01 45 2 "GTUBE aceite e marcada pelo spamd (score 1000)" poc obs 1 0
try_alert 110300 lis-mail-01 60 1 "vaga: mais 10 GTUBE em 2 min" poc obs 10 0
try_alert 110302 lis-mail-01 45 1 "5 relays recusados (554) a partir do obs" poc obs 0 5
wait_in $P-mail 45 "firewall-drop executado NO mail-01: $OBS_IP bloqueado" "iptables -S | grep -q -- '-s $OBS_IP/32 -j DROP'"
echo "      do lado do cliente, depois do bloqueio:"; docker exec $P-obs bash /tmp/smtp-poc.sh "$MAIL_IP" 1 0 | sed 's/^/        /'

step "meta-correlação por relay (obs + mail-01): o sensor comprometido tenta usar o MTA"
try_alert 110210 core-obs 30 2 "sen-01 é a causa raiz (agente obs, srcip $SEN_IP)" incident opo sen-01 sensor "$SEN_IP"
sleep 50   # o ignore=60 da 110302 (disparou para o obs há pouco)
try_alert 110900 lis-mail-01 45 2 "sen-01 é causa raiz (obs) E tenta relay no mail-01" poc sen 0 5
wait_in $P-mail 45 "firewall-drop NO mail-01 também pela 110900: $SEN_IP bloqueado" "iptables -S | grep -q -- '-s $SEN_IP/32 -j DROP'"
echo "      o bot, do lado do cliente, depois do bloqueio:"; docker exec $P-sen bash /tmp/smtp-poc.sh "$MAIL_IP" 1 0 | sed 's/^/        /'

echo
[ $FAIL -eq 0 ] && echo "RESULTADO: integração SIEM OK ✅" || echo "RESULTADO: há falhas ✗"
exit $FAIL
