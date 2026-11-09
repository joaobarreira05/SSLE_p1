#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Deploy idempotente do lab do Projeto 1 (SSLE) a partir de inventory/sites.yaml.
#
#   SSLE_PROFILE=staging|full   (default: staging — fatia reduzida p/ pouca RAM)
#   SSLE_HOST=<label>           (default: auto por uname → t490 / mac-m2)
#   SSLE_IMAGE=images:debian/trixie
#   SSLE_SKIP_APPS=1            (só infra: projetos, redes, contentores)
#   SSLE_GRAFANA=0|1            (default: 1 no full, 0 no staging — o Grafana precisa de ~300 MiB)
#
# Reentrante: correr várias vezes só acrescenta/corrige o que falta.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
PROFILE="${SSLE_PROFILE:-staging}"
IMAGE="${SSLE_IMAGE:-images:debian/trixie}"
if [ -n "${SSLE_HOST:-}" ]; then HOST_LABEL="$SSLE_HOST"
elif uname -m | grep -qiE 'x86_64|amd64'; then HOST_LABEL="t490"
else HOST_LABEL="mac-m2"; fi

log()  { printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m%s\n' "$*"; }

cexec() { local name="$1" proj="$2"; shift 2; incus exec "$name" --project "$proj" -- "$@" </dev/null; }
cpush() { incus file push "$1" "$2" --project "$3" --create-dirs --quiet; }

exists_inst() { incus list --project "$2" --format csv -c n 2>/dev/null | grep -qx "$1"; }
exists_net()  { incus network show "$1" >/dev/null 2>&1; }
exists_proj() { incus project show "$1" >/dev/null 2>&1; }

# ── 0. render do inventário ────────────────────────────────────────────────────
render() {
  local args=(render --out "$BUILD" --host "$HOST_LABEL")
  [ "$PROFILE" = staging ] && args+=(--staging)
  python3 "$ROOT/infra/inventory.py" "${args[@]}" >/dev/null
  ok "inventário renderizado em build/ (profile=$PROFILE, host=$HOST_LABEL)"
}

# ── 1. projetos ────────────────────────────────────────────────────────────────
projects() {
  log "projetos Incus"
  local projs; projs="$(cut -f2 "$BUILD/containers.tsv" | sort -u)"
  while read -r p <&3; do
    [ -z "$p" ] && continue
    if exists_proj "$p"; then ok "projeto $p (existe)"; else
      incus project create "$p" -c features.images=false -c features.profiles=false >/dev/null </dev/null
      ok "projeto $p criado"
    fi
  done 3<<< "$projs"
}

# ── 2. redes ─────────────────────────────────────────────────────────────────
networks() {
  log "redes Incus"
  while IFS=$'\t' read -r bridge subnet gateway dns <&3; do
    [ -z "$bridge" ] && continue
    local mask="${subnet#*/}"
    if exists_net "$bridge"; then ok "rede $bridge (existe)"; else
      incus network create "$bridge" \
        ipv4.address="$gateway/$mask" ipv4.nat=true ipv6.address=none \
        dns.domain="$dns" >/dev/null </dev/null
      ok "rede $bridge ($gateway/$mask, dns=$dns)"
    fi
  done 3< "$BUILD/networks.tsv"
}

# ── 3. contentores ─────────────────────────────────────────────────────────────
launch_one() {
  local name="$1" proj="$2" net="$3" ip="$4" exporter="$5" role="$6" site="$7" team="$8" img="${9:--}"
  [ "$img" = - ] && img="$IMAGE"            # imagem própria só se o inventário a der (ex.: wazuh)
  if exists_inst "$name" "$proj"; then
    ok "$proj/$name (existe)"
  else
    incus launch "$img" "$name" --project "$proj" --network "$net" >/dev/null </dev/null
    incus config device set "$name" eth0 ipv4.address="$ip" --project "$proj" >/dev/null </dev/null
    ok "$proj/$name lançado em $net ($ip)"
  fi
  incus config set "$name" user.site="$site" user.role="$role" user.team="$team" --project "$proj" >/dev/null </dev/null
  # Rede: um só NIC por contentor. A comunicação core<->sites faz-se por
  # encaminhamento entre bridges do próprio host (verificado no teste de fumo).
}

containers() {
  log "contentores"
  while IFS=$'\t' read -r name proj net ip exporter role site team deps image <&3; do
    [ -z "$name" ] && continue
    launch_one "$name" "$proj" "$net" "$ip" "$exporter" "$role" "$site" "$team" "$image"
  done 3< "$BUILD/containers.tsv"
  log "à espera de rede (rota default) nos contentores…"
  while IFS=$'\t' read -r name proj net ip rest <&3; do
    [ -z "$name" ] && continue
    local up=0
    for _ in $(seq 1 45); do
      if cexec "$name" "$proj" sh -c 'ip -4 route 2>/dev/null | grep -q "^default"' 2>/dev/null; then up=1; break; fi
      sleep 1 || true
    done
    [ "$up" = 1 ] && ok "$proj/$name com rede ($ip)" || warn "$proj/$name sem rota default (segue mesmo assim)"
  done 3< "$BUILD/containers.tsv"
}

# ── 4. provisionamento ─────────────────────────────────────────────────────────
APT="DEBIAN_FRONTEND=noninteractive apt-get"
apt_in() { local n="$1" p="$2"; shift 2; cexec "$n" "$p" sh -c "$APT update -qq && $APT install -y -qq --no-install-recommends $*"; }

prov_node() {   # node_exporter
  local n="$1" p="$2"
  cexec "$n" "$p" sh -c "dpkg -s prometheus-node-exporter >/dev/null 2>&1" \
    || apt_in "$n" "$p" prometheus-node-exporter
  cexec "$n" "$p" systemctl enable --now prometheus-node-exporter >/dev/null 2>&1 || true
}

prov_flask() {  # serviço Flask + node_exporter
  local n="$1" p="$2" role="$3" site="$4" deps="$5"
  prov_node "$n" "$p"
  cexec "$n" "$p" sh -c "dpkg -s python3-flask >/dev/null 2>&1" || apt_in "$n" "$p" python3-flask python3
  cexec "$n" "$p" mkdir -p /opt/ssle /var/log/ssle
  cpush "$ROOT/services/app.py" "$n/opt/ssle/app.py" "$p"
  # serviços expostos (T1): log de acesso "combined" que o agente Wazuh lê (siem/shared/role-<papel>/agent.conf)
  local accesslog=""; case "$role" in ingestion|web) accesslog="SSLE_ACCESS_LOG=/var/log/ssle/access.log" ;; esac
  # dependências -> "nome=ip:porta" a partir do grafo/inventário (node_exporter:9100)
  # sensores: enviam leituras à 1.ª dependência (a ingestão), em :8000/ingest
  local depenv="" upstream=""
  if [ "$deps" != "-" ]; then
    IFS=',' read -ra ds <<< "$deps"
    for d in "${ds[@]}"; do
      local dn="${d%@*}" dsite="$site"; [[ "$d" == *@* ]] && dsite="${d##*@}"
      local dip; dip="$(awk -F'\t' -v nm="$dn" -v st="$dsite" '$1==nm && $7==st {print $4}' "$BUILD/containers.tsv")"
      [ -n "$dip" ] && depenv="${depenv:+$depenv,}$dn=$dip:9100"
      [ "$role" = sensor ] && [ -z "$upstream" ] && [ -n "$dip" ] && upstream="http://$dip:8000/ingest"
    done
  fi
  cexec "$n" "$p" sh -c "cat > /etc/systemd/system/ssle-service.service <<UNIT
[Unit]
Description=SSLE service ($role)
After=network-online.target
[Service]
Environment=SSLE_ROLE=$role SSLE_SITE=$site SSLE_INSTANCE=$n SSLE_DEPS=$depenv SSLE_UPSTREAM=$upstream PORT=8000 $accesslog
ExecStart=/usr/bin/python3 /opt/ssle/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable ssle-service >/dev/null 2>&1 && systemctl restart ssle-service"
  # restart (e não só enable --now): um re-deploy com código novo tem de o pôr a correr
}

prov_prom_site() {  # Prometheus de site
  local n="$1" p="$2" site="$3"
  prov_node "$n" "$p"
  cexec "$n" "$p" sh -c "dpkg -s prometheus >/dev/null 2>&1" || apt_in "$n" "$p" prometheus
  local am; am="$(cut -f3 "$BUILD/obs.tsv"):9093"   # Alertmanager central (obs, via routing)
  # template → config: AM central e, se o site tiver reg-01, o HTTP SD (infra/inventory.py siteprom)
  local args=(siteprom --site "$site" --host "$HOST_LABEL"); [ "$PROFILE" = staging ] && args+=(--staging)
  python3 "$ROOT/infra/inventory.py" "${args[@]}" > "$BUILD/prometheus-$site.yml"
  cpush "$BUILD/prometheus-$site.yml" "$n/etc/prometheus/prometheus.yml" "$p"
  for r in "$ROOT"/monitoring/site/rules/*.yml; do cpush "$r" "$n/etc/prometheus/rules/$(basename "$r")" "$p"; done
  cpush "$BUILD/targets/$site/node.json"  "$n/etc/prometheus/targets/node.json"  "$p"
  cpush "$BUILD/targets/$site/flask.json" "$n/etc/prometheus/targets/flask.json" "$p"
  cexec "$n" "$p" systemctl restart prometheus
  ok "  prometheus de $site configurado (AM=$am)"
}

prov_registry() {  # registry do site (R2): leases + HTTP SD + site_info — registry/
  local n="$1" p="$2" site="$3"
  prov_node "$n" "$p"
  cexec "$n" "$p" sh -c "dpkg -s python3-flask >/dev/null 2>&1" || apt_in "$n" "$p" python3-flask python3
  cexec "$n" "$p" mkdir -p /opt/registry /etc/ssle
  cpush "$ROOT/registry/core.py" "$n/opt/registry/core.py" "$p"
  cpush "$ROOT/registry/app.py" "$n/opt/registry/app.py" "$p"
  cpush "$BUILD/targets/$site/registry.json" "$n/opt/registry/registry.json" "$p"
  # token de escrita do site: GERADO aqui (nunca fixo no código), fica em build/secrets (fora do Git)
  local tok="$BUILD/secrets/registry-$site.token"
  if [ ! -s "$tok" ]; then
    (umask 077; mkdir -p "$BUILD/secrets"; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$tok")
  fi
  incus file push "$tok" "$n/etc/ssle/registry.token" --project "$p" --mode 0600 --uid 0 --gid 0 --quiet
  cexec "$n" "$p" sh -c 'cat > /etc/systemd/system/ssle-registry.service <<UNIT
[Unit]
Description=SSLE registry de site (R2)
After=network-online.target
[Service]
Environment=SSLE_REGISTRY_CONFIG=/opt/registry/registry.json SSLE_REGISTRY_TOKEN_FILE=/etc/ssle/registry.token PORT=5050
ExecStart=/usr/bin/python3 /opt/registry/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable ssle-registry >/dev/null 2>&1 && systemctl restart ssle-registry'
  ok "  registry de $site (token em build/secrets/registry-$site.token, 0600 no contentor)"
}

prov_obs() {  # Prometheus global + Alertmanager + correlator
  local n="$1" p="$2"
  prov_node "$n" "$p"
  cexec "$n" "$p" sh -c "dpkg -s prometheus >/dev/null 2>&1" || apt_in "$n" "$p" prometheus
  cexec "$n" "$p" sh -c "dpkg -s python3-flask >/dev/null 2>&1" || apt_in "$n" "$p" python3-flask python3
  # alertmanager: apt se existir, senão binário oficial
  if ! cexec "$n" "$p" sh -c "command -v alertmanager >/dev/null 2>&1 || dpkg -s prometheus-alertmanager >/dev/null 2>&1"; then
    if ! apt_in "$n" "$p" prometheus-alertmanager; then
      warn "apt sem prometheus-alertmanager — a obter binário oficial"
      cexec "$n" "$p" sh -c 'cd /tmp && A=$(uname -m); case $A in aarch64) G=arm64;; x86_64) G=amd64;; esac; \
        apt-get install -y -qq curl >/dev/null; \
        curl -sL https://github.com/prometheus/alertmanager/releases/download/v0.28.1/alertmanager-0.28.1.linux-$G.tar.gz | tar xz; \
        install alertmanager-0.28.1.linux-$G/alertmanager /usr/local/bin/alertmanager'
    fi
  fi
  # configs globais
  sed "s/HOSTPLACEHOLDER/$HOST_LABEL/g" "$ROOT/monitoring/global/prometheus.yml" > "$BUILD/global-prometheus.yml"
  cpush "$BUILD/global-prometheus.yml" "$n/etc/prometheus/prometheus.yml" "$p"
  cpush "$ROOT/monitoring/global/rules.yml" "$n/etc/prometheus/rules/rules.yml" "$p"
  cpush "$BUILD/federate.json" "$n/etc/prometheus/federate.json" "$p"
  cpush "$ROOT/monitoring/global/alertmanager.yml" "$n/etc/alertmanager/alertmanager.yml" "$p"
  # alertmanager como serviço (usa o do apt se existir; senão unit própria)
  if cexec "$n" "$p" sh -c "dpkg -s prometheus-alertmanager >/dev/null 2>&1"; then
    cpush "$ROOT/monitoring/global/alertmanager.yml" "$n/etc/prometheus/alertmanager.yml" "$p"
    cexec "$n" "$p" systemctl restart prometheus-alertmanager || true
  else
    cexec "$n" "$p" sh -c 'mkdir -p /var/lib/alertmanager; cat > /etc/systemd/system/alertmanager.service <<UNIT
[Unit]
Description=Alertmanager
After=network-online.target
[Service]
ExecStart=/usr/local/bin/alertmanager --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/var/lib/alertmanager
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now alertmanager'
  fi
  # correlator
  cexec "$n" "$p" mkdir -p /opt/correlator /var/log/ssle
  cpush "$ROOT/correlator/app.py" "$n/opt/correlator/app.py" "$p"
  cpush "$ROOT/correlator/rca.py" "$n/opt/correlator/rca.py" "$p"     # núcleo RCA (o app.py importa-o)
  cpush "$BUILD/graph.json" "$n/opt/correlator/graph.json" "$p"
  cexec "$n" "$p" sh -c 'cat > /etc/systemd/system/ssle-correlator.service <<UNIT
[Unit]
Description=SSLE correlator (RCA)
After=network-online.target
[Service]
Environment=CORRELATOR_GRAPH=/opt/correlator/graph.json CORRELATOR_LOG=/var/log/ssle/incidents.json CORRELATOR_SETTLE=30 PORT=9095
ExecStart=/usr/bin/python3 /opt/correlator/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable ssle-correlator >/dev/null 2>&1 && systemctl restart ssle-correlator'
  # node_exporter do HOST (só escuta em 127.0.0.1 — infra/t490/setup-host.sh): um proxy device do Incus
  # com bind=instance abre 127.0.0.1:9101 DENTRO do obs e liga-o ao 127.0.0.1:9100 do host, sem expor nada
  if [ "$HOST_LABEL" = t490 ] && [ "$PROFILE" = full ]; then
    incus config device show "$n" --project "$p" 2>/dev/null | grep -q '^hostnode:' || \
      incus config device add "$n" hostnode proxy listen=tcp:127.0.0.1:9101 connect=tcp:127.0.0.1:9100 \
        bind=instance --project "$p" >/dev/null </dev/null
    printf '[{"targets": ["localhost:9101"], "labels": {"site": "core", "instance_name": "%s", "host": "%s", "role": "hypervisor"}}]\n' \
      "$HOST_LABEL" "$HOST_LABEL" > "$BUILD/hypervisor.json"
  else
    echo '[]' > "$BUILD/hypervisor.json"
  fi
  cpush "$BUILD/hypervisor.json" "$n/etc/prometheus/hypervisor.json" "$p"
  cexec "$n" "$p" systemctl restart prometheus
  ok "  obs: prometheus global + alertmanager + correlator configurados"
  local want_grafana=0; [ "$PROFILE" = full ] && want_grafana=1
  [ "${SSLE_GRAFANA:-$want_grafana}" = 1 ] && prov_grafana "$n" "$p"
  return 0
}

prov_grafana() {  # Grafana no obs: datasources do inventário + dashboards como código (monitoring/grafana/)
  local n="$1" p="$2" ver=11.6.1
  if ! cexec "$n" "$p" sh -c "dpkg -s grafana 2>/dev/null | grep -q '^Version: $ver'"; then
    apt_in "$n" "$p" ca-certificates curl gnupg
    cexec "$n" "$p" sh -c "mkdir -p /etc/apt/keyrings && curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg \
      && echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' > /etc/apt/sources.list.d/grafana.list \
      && $APT update -qq && $APT install -y -qq grafana=$ver"
  fi
  local args=(grafana --host "$HOST_LABEL"); [ "$PROFILE" = staging ] && args+=(--staging)
  python3 "$ROOT/infra/inventory.py" "${args[@]}" > "$BUILD/grafana-datasources.yml"
  cpush "$BUILD/grafana-datasources.yml" "$n/etc/grafana/provisioning/datasources/ssle.yml" "$p"
  cpush "$ROOT/monitoring/grafana/providers/ssle.yml" "$n/etc/grafana/provisioning/dashboards/ssle.yml" "$p"
  for d in "$ROOT"/monitoring/grafana/dashboards/*.json; do
    cpush "$d" "$n/var/lib/grafana/dashboards/ssle/$(basename "$d")" "$p"
  done
  # só na rede do core (chega-se por túnel SSH a partir do host/Mac), sem anónimo, sem telemetria
  local obs_ip; obs_ip="$(cut -f3 "$BUILD/obs.tsv")"
  cexec "$n" "$p" sh -c "mkdir -p /etc/systemd/system/grafana-server.service.d && cat > /etc/systemd/system/grafana-server.service.d/ssle.conf <<UNIT
[Service]
Environment=GF_SERVER_HTTP_ADDR=$obs_ip GF_AUTH_ANONYMOUS_ENABLED=false GF_ANALYTICS_REPORTING_ENABLED=false
Environment=GF_ANALYTICS_CHECK_FOR_UPDATES=false GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false GF_NEWS_NEWS_FEED_ENABLED=false
UNIT
chown -R grafana:grafana /var/lib/grafana/dashboards && systemctl daemon-reload && systemctl enable grafana-server >/dev/null 2>&1 && systemctl restart grafana-server"
  # password de admin GERADA (nunca a 'admin' por omissão), guardada fora do Git
  local pw="$BUILD/secrets/grafana-admin.pass"
  [ -s "$pw" ] || (umask 077; mkdir -p "$BUILD/secrets"; python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$pw")
  incus file push "$pw" "$n/root/grafana-admin.pass" --project "$p" --mode 0600 --quiet
  cexec "$n" "$p" sh -c 'sleep 5; grafana cli --homepath /usr/share/grafana admin reset-admin-password "$(cat /root/grafana-admin.pass)" >/dev/null 2>&1; rm -f /root/grafana-admin.pass'
  ok "  grafana $ver em http://$obs_ip:3000 (admin: build/secrets/grafana-admin.pass; túnel: ssh -L 3000:$obs_ip:3000 …)"
}

prov_mail() {  # MTA do site (T3): Postfix + SpamAssassin da aula 8 — threats/t3-spam/mail-setup.sh
  local n="$1" p="$2" site="$3"
  prov_node "$n" "$p"
  local subnet; subnet="$(awk -F'\t' -v b="net-$site" '$1 == b {print $2}' "$BUILD/networks.tsv")"
  cpush "$ROOT/threats/t3-spam/mail-setup.sh" "$n/tmp/mail-setup.sh" "$p"
  cexec "$n" "$p" bash /tmp/mail-setup.sh "127.0.0.0/8 $subnet" "$site.ssle.lab"
  ok "  mail-01 de $site: relay só para $subnet; saída para fora desligada"
}

provision() {
  [ "${SSLE_SKIP_APPS:-0}" = 1 ] && { warn "SSLE_SKIP_APPS=1 — salto o provisionamento"; return; }
  log "provisionamento (apt + configs)"
  while IFS=$'\t' read -r name proj net ip exporter role site team deps _image <&3; do
    [ -z "$name" ] && continue
    case "$exporter" in
      global) prov_obs "$name" "$proj" ;;
      registry) prov_registry "$name" "$proj" "$site" ;;
      flask)  prov_flask "$name" "$proj" "$role" "$site" "$deps" ;;
      node)   case "$role" in
                prometheus) prov_prom_site "$name" "$proj" "$site" ;;
                mail) prov_mail "$name" "$proj" "$site" ;;
                *) prov_node "$name" "$proj" ;;
              esac ;;
    esac
  done 3< "$BUILD/containers.tsv"
}

# ── 5. SIEM (só no full): Wazuh all-in-one, agentes por grupo, respostas ─────────────────────────────────
# Os passos DENTRO dos contentores são os mesmos scripts que o siem/tests/it-agents.sh prova em Docker
# (manager e agentes reais): siem/manager/configure-manager.sh e siem/agent/install-agent.sh.
WAZUH_VERSION=""
siem_node() { awk -F'\t' -v r="$1" '$6 == r {print $1 "\t" $2 "\t" $4; exit}' "$BUILD/containers.tsv"; }

siem_bundle() {  # siem_bundle <ficheiro "id nome"> → build/siem (o pacote que o configure-manager.sh consome)
  local out="$BUILD/siem"; rm -rf "$out"; mkdir -p "$out"
  cp -r "$ROOT/siem/rules" "$ROOT/siem/decoders" "$ROOT/siem/lists" "$ROOT/siem/shared" "$out/"
  cp "$ROOT/siem/manager/apply.py" "$out/"
  cut -f5 "$BUILD/wazuh-agents.tsv" | tr ',' '\n' | sort -u > "$out/groups.txt"
  python3 "$ROOT/infra/inventory.py" wazuh-manager --host "$HOST_LABEL" --agents "$1" > "$out/ossec-ssle.conf"
}

siem_configure() {  # siem_configure <ficheiro "id nome">
  local n p ip; IFS=$'\t' read -r n p ip <<<"$(siem_node siem)"
  siem_bundle "$1"
  cexec "$n" "$p" rm -rf /tmp/siem
  incus file push -r "$BUILD/siem" "$n/tmp/" --project "$p" --quiet
  cpush "$ROOT/siem/manager/configure-manager.sh" "$n/tmp/configure-manager.sh" "$p"
  cexec "$n" "$p" bash /tmp/configure-manager.sh /tmp/siem
}

siem_manager() {  # Wazuh all-in-one como na aula 6 (manager + indexer + dashboard), ~10 min na 1.ª vez
  local n p ip; IFS=$'\t' read -r n p ip <<<"$(siem_node siem)"
  [ -n "$n" ] || { warn "inventário sem elemento role=siem — salto o SIEM"; return 1; }
  if ! cexec "$n" "$p" sh -c 'dpkg -s wazuh-manager >/dev/null 2>&1'; then
    log "  wazuh-install.sh -a -i em $p/$n (manager+indexer+dashboard; ~10 min)"
    apt_in "$n" "$p" curl ca-certificates
    cexec "$n" "$p" sh -c 'cd /root && curl -fsSO https://packages.wazuh.com/4.14/wazuh-install.sh && bash wazuh-install.sh -a -i'
  fi
  # passwords GERADAS pelo instalador → build/secrets (fora do Git), 0600; ficam também no tar, só root, no contentor
  local pw="$BUILD/secrets/wazuh-passwords.txt"
  [ -s "$pw" ] || (umask 077; mkdir -p "$BUILD/secrets"
    cexec "$n" "$p" tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > "$pw")
  WAZUH_VERSION="$(cexec "$n" "$p" dpkg-query -W -f='${Version}' wazuh-manager)"
  ok "  wazuh-manager $WAZUH_VERSION em $ip (passwords: build/secrets/wazuh-passwords.txt; dashboard: ssh -L 8443:$ip:443 …)"
}

siem_agents() {  # um agente por elemento (menos o próprio SIEM), com o grupo do site e o do papel
  local wip; wip="$(siem_node siem | cut -f3)"
  while IFS=$'\t' read -r agent proj inst _ip groups <&3; do
    [ -z "$agent" ] && continue
    local role; role="$(awk -F'\t' -v n="$inst" -v p="$proj" '$1 == n && $2 == p {print $6}' "$BUILD/containers.tsv")"
    cexec "$inst" "$proj" sh -c 'rm -rf /tmp/ssle-ar && mkdir -p /tmp/ssle-ar'
    cpush "$ROOT/siem/agent/install-agent.sh" "$inst/tmp/install-agent.sh" "$proj"
    case "$role" in
      ingestion|web) cpush "$ROOT/siem/active-response/ssle-ratelimit.sh" "$inst/tmp/ssle-ar/ssle-ratelimit.sh" "$proj" ;;
      responder) cpush "$ROOT/siem/active-response/ssle-quarantine.sh" "$inst/tmp/ssle-ar/ssle-quarantine.sh" "$proj"
                 cpush "$BUILD/wazuh-agents.tsv" "$inst/tmp/ssle-fleet.tsv" "$proj" ;;
    esac
    cexec "$inst" "$proj" env WAZUH_AGENT_VERSION="$WAZUH_VERSION" \
      bash /tmp/install-agent.sh "$wip" "$agent" "$groups" "$role" "${agent%%-*}" "$inst" "$HOST_LABEL"
  done 3< "$BUILD/wazuh-agents.tsv"
}

siem_responder() {  # API do Incus só na bridge do core + certificado RESTRITO aos site-* (menor privilégio)
  local n p ip; IFS=$'\t' read -r n p ip <<<"$(siem_node responder)"
  [ -n "$n" ] || return 0
  local want; want="$(awk -F'\t' '$1 == "net-core" {print $3}' "$BUILD/networks.tsv"):8443"
  local addr; addr="$(incus config get core.https_address </dev/null)"
  if [ -z "$addr" ]; then
    incus config set core.https_address "$want" </dev/null; ok "  API do Incus só em $want (bridge do core)"
  elif [ "$addr" != "$want" ]; then
    warn "core.https_address já é '$addr' (não fui eu: não mexo) — quarentena por configurar"; return 0
  fi
  cexec "$n" "$p" sh -c 'command -v incus >/dev/null' || apt_in "$n" "$p" incus-client
  if ! cexec "$n" "$p" sh -c 'incus remote list --format csv 2>/dev/null | grep -q "^t490,"'; then
    incus config trust revoke-token responder </dev/null >/dev/null 2>&1 || true      # token pendente antigo
    local tok; tok="$(incus config trust add responder --restricted --projects site-avr,site-opo,site-lis </dev/null | tail -1)"
    cexec "$n" "$p" incus remote add t490 "$tok" >/dev/null
  fi
  # prova do menor privilégio: vê os sites, NÃO vê o core. Se vir o core → retira o certificado (falha fechada)
  if cexec "$n" "$p" incus list t490: --project site-opo --format csv >/dev/null 2>&1; then ok "  responder vê site-opo"
  else warn "responder não chega à API do Incus (quarentena não vai funcionar)"; fi
  if cexec "$n" "$p" incus list t490: --project core --format csv >/dev/null 2>&1; then
    warn "o certificado do responder VÊ o projeto core — a retirá-lo (falha fechada)"
    local fp; fp="$(incus config trust list --format csv </dev/null | awk -F, '$2 == "responder" {print $4}')"
    [ -n "$fp" ] && incus config trust remove "$fp" </dev/null
  else ok "  responder NÃO vê o projeto core (certificado restrito aos site-*)"; fi
}

siem() {
  [ "$PROFILE" = full ] || return 0
  [ "${SSLE_SKIP_APPS:-0}" = 1 ] && return 0
  log "SIEM (Wazuh) — manager, agentes por grupo, respostas"
  python3 "$ROOT/infra/inventory.py" wazuh-agents --host "$HOST_LABEL" > "$BUILD/wazuh-agents.tsv"
  siem_manager || return 0
  : > "$BUILD/wazuh-agent-ids.txt"
  siem_configure "$BUILD/wazuh-agent-ids.txt"           # 1.ª passagem: regras/grupos ANTES das inscrições
  siem_agents
  local n p ip; IFS=$'\t' read -r n p ip <<<"$(siem_node siem)"
  # só as colunas id e nome do client.keys saem do contentor (as chaves ficam lá)
  cexec "$n" "$p" sh -c "cut -d' ' -f1,2 /var/ossec/etc/client.keys" > "$BUILD/wazuh-agent-ids.txt"
  siem_configure "$BUILD/wazuh-agent-ids.txt"           # 2.ª passagem: respostas com os IDs reais
  siem_responder
  ok "  SIEM: $(grep -c . "$BUILD/wazuh-agent-ids.txt") agentes inscritos"
}

main() {
  log "=== SSLE P1 deploy (profile=$PROFILE, image=$IMAGE, host=$HOST_LABEL) ==="
  render; projects; networks; containers; provision; siem
  log "=== concluído. 'incus list --all-projects' para ver a frota. ==="
}
main "$@"
