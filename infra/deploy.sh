#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Deploy idempotente do lab do Projeto 1 (SSLE) a partir de inventory/sites.yaml.
#
#   SSLE_PROFILE=staging|full   (default: staging — fatia reduzida p/ pouca RAM)
#   SSLE_HOST=<label>           (default: auto por uname → t490 / mac-m2)
#   SSLE_IMAGE=images:debian/trixie
#   SSLE_SKIP_APPS=1            (só infra: projetos, redes, contentores)
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
  local name="$1" proj="$2" net="$3" ip="$4" exporter="$5" role="$6" site="$7" team="$8"
  if exists_inst "$name" "$proj"; then
    ok "$proj/$name (existe)"
  else
    incus launch "$IMAGE" "$name" --project "$proj" --network "$net" >/dev/null </dev/null
    incus config device set "$name" eth0 ipv4.address="$ip" --project "$proj" >/dev/null </dev/null
    ok "$proj/$name lançado em $net ($ip)"
  fi
  incus config set "$name" user.site="$site" user.role="$role" user.team="$team" --project "$proj" >/dev/null </dev/null
  # Rede: um só NIC por contentor. A comunicação core<->sites faz-se por
  # encaminhamento entre bridges do próprio host (verificado no teste de fumo).
}

containers() {
  log "contentores"
  while IFS=$'\t' read -r name proj net ip exporter role site team deps <&3; do
    [ -z "$name" ] && continue
    launch_one "$name" "$proj" "$net" "$ip" "$exporter" "$role" "$site" "$team"
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
  cexec "$n" "$p" mkdir -p /opt/ssle
  cpush "$ROOT/services/app.py" "$n/opt/ssle/app.py" "$p"
  # dependências -> "nome=ip:porta" a partir do grafo/inventário (node_exporter:9100)
  local depenv=""
  if [ "$deps" != "-" ]; then
    IFS=',' read -ra ds <<< "$deps"
    for d in "${ds[@]}"; do
      local dn="${d%@*}" dsite="$site"; [[ "$d" == *@* ]] && dsite="${d##*@}"
      local dip; dip="$(awk -F'\t' -v nm="$dn" -v st="$dsite" '$1==nm && $7==st {print $4}' "$BUILD/containers.tsv")"
      [ -n "$dip" ] && depenv="${depenv:+$depenv,}$dn=$dip:9100"
    done
  fi
  cexec "$n" "$p" sh -c "cat > /etc/systemd/system/ssle-service.service <<UNIT
[Unit]
Description=SSLE service ($role)
After=network-online.target
[Service]
Environment=SSLE_ROLE=$role SSLE_SITE=$site SSLE_INSTANCE=$n SSLE_DEPS=$depenv PORT=8000
ExecStart=/usr/bin/python3 /opt/ssle/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now ssle-service >/dev/null 2>&1"
}

prov_prom_site() {  # Prometheus de site
  local n="$1" p="$2" site="$3"
  prov_node "$n" "$p"
  cexec "$n" "$p" sh -c "dpkg -s prometheus >/dev/null 2>&1" || apt_in "$n" "$p" prometheus
  local am; am="$(cut -f3 "$BUILD/obs.tsv"):9093"   # Alertmanager central (obs, via routing)
  sed -e "s/@@SITE@@/$site/g" -e "s#@@ALERTMANAGER@@#$am#g" \
      "$ROOT/monitoring/site/prometheus.yml.tmpl" > "$BUILD/prometheus-$site.yml"
  cpush "$BUILD/prometheus-$site.yml" "$n/etc/prometheus/prometheus.yml" "$p"
  for r in "$ROOT"/monitoring/site/rules/*.yml; do cpush "$r" "$n/etc/prometheus/rules/$(basename "$r")" "$p"; done
  cpush "$BUILD/targets/$site/node.json"  "$n/etc/prometheus/targets/node.json"  "$p"
  cpush "$BUILD/targets/$site/flask.json" "$n/etc/prometheus/targets/flask.json" "$p"
  cexec "$n" "$p" systemctl restart prometheus
  ok "  prometheus de $site configurado (AM=$am)"
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
  cpush "$BUILD/graph.json" "$n/opt/correlator/graph.json" "$p"
  cexec "$n" "$p" sh -c 'cat > /etc/systemd/system/ssle-correlator.service <<UNIT
[Unit]
Description=SSLE correlator (RCA)
After=network-online.target
[Service]
Environment=CORRELATOR_GRAPH=/opt/correlator/graph.json CORRELATOR_LOG=/var/log/ssle/incidents.json PORT=9095
ExecStart=/usr/bin/python3 /opt/correlator/app.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now ssle-correlator'
  cexec "$n" "$p" systemctl restart prometheus
  ok "  obs: prometheus global + alertmanager + correlator configurados"
}

provision() {
  [ "${SSLE_SKIP_APPS:-0}" = 1 ] && { warn "SSLE_SKIP_APPS=1 — salto o provisionamento"; return; }
  log "provisionamento (apt + configs)"
  while IFS=$'\t' read -r name proj net ip exporter role site team deps <&3; do
    [ -z "$name" ] && continue
    case "$exporter" in
      global) prov_obs "$name" "$proj" ;;
      flask)  prov_flask "$name" "$proj" "$role" "$site" "$deps" ;;
      node)   if [ "$role" = prometheus ]; then prov_prom_site "$name" "$proj" "$site"; else prov_node "$name" "$proj"; fi ;;
    esac
  done 3< "$BUILD/containers.tsv"
}

main() {
  log "=== SSLE P1 deploy (profile=$PROFILE, image=$IMAGE, host=$HOST_LABEL) ==="
  render; projects; networks; containers; provision
  log "=== concluído. 'incus list --all-projects' para ver a frota. ==="
}
main "$@"
