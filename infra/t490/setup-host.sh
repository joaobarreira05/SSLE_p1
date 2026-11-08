#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Setup do host T490 (F0 do Projeto 1) num só comando — skill ssle-t490-lab §4–§5.
#
#   bash infra/t490/setup-host.sh                  # --check (default): SÓ LEITURA, resumo "está / falta"
#   sudo bash infra/t490/setup-host.sh --apply     # aplica SÓ o que falta (idempotente)
#
# O --apply tem duas fases, porque a atualização única quase sempre traz um kernel novo:
#   fase 1: -Syu única + configuração do host  → pede REBOOT
#   fase 2: (depois do reboot, o MESMO comando) incus admin init (pool btrfs "lab") + teste de fumo
#
# Opções:
#   --docker=disable   (default) para e desativa o Docker do host (reversível: ver o fim do output)
#   --docker=coexist   mantém o Docker mas com ip-forward-no-drop (não põe o FORWARD em DROP)
#   --docker=keep      não mexe no Docker (NÃO recomendado: parte a rede do Incus)
#   --pool-size=180GiB tamanho do ficheiro loop btrfs da pool "lab" (raiz em ext4)
#   --skip-upgrade     não faz a -Syu (p.ex. se a atualização única já foi feita por outra via)
#   --force-upgrade    repete a -Syu mesmo com o marcador (nunca nas 48 h antes da entrega/demo)
#   --skip-smoke       não corre o teste de fumo
#
# Falha fechada: perante erro, pára (set -e) sem deixar meia-configuração; cada passo verifica antes
# de mexer (corre-se as vezes que for preciso). Nada aqui expõe serviços à rede de casa: o
# node_exporter do host fica em 127.0.0.1 (o core/obs chega-lhe por um proxy device do Incus).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODE=check; DOCKER_MODE=disable; POOL_SIZE=180GiB
SKIP_UPGRADE=0; FORCE_UPGRADE=0; SKIP_SMOKE=0
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    --apply) MODE=apply ;;
    --docker=*) DOCKER_MODE="${a#*=}" ;;
    --pool-size=*) POOL_SIZE="${a#*=}" ;;
    --skip-upgrade) SKIP_UPGRADE=1 ;;
    --force-upgrade) FORCE_UPGRADE=1 ;;
    --skip-smoke) SKIP_SMOKE=1 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "opção desconhecida: $a" >&2; exit 2 ;;
  esac
done
case "$DOCKER_MODE" in disable|coexist|keep) ;; *) echo "--docker=disable|coexist|keep" >&2; exit 2 ;; esac

# Tudo o que o host vai precisar, numa SÓ transação (no Arch não há upgrades parciais).
PKGS=(incus btrfs-progs openssh git prometheus-node-exporter linux-lts
      jq go-yq tmux htop rsync tcpdump bind wireguard-tools python python-yaml)
SERVICES=(incus.socket incus.service sshd.service prometheus-node-exporter.service systemd-timesyncd.service)
STATE=/var/lib/ssle                       # marcadores do setup (fora do repo, fora do Git)
MARK_SYU="$STATE/syu-done"
TARGET_USER="${SUDO_USER:-$(id -un)}"
NODE_DROPIN=/etc/systemd/system/prometheus-node-exporter.service.d/ssle.conf
LID_CONF=/etc/systemd/logind.conf.d/lid.conf
# Congelamento: nada de -Syu nas 48 h antes da entrega (22/11). A data da demo, quando houver: SSLE_DEMO_DATE=AAAA-MM-DD
FREEZE_DATES=("2026-11-20" "2026-11-21" "2026-11-22")
[ -n "${SSLE_DEMO_DATE:-}" ] && FREEZE_DATES+=("$(date -d "$SSLE_DEMO_DATE -2 day" +%F)" "$(date -d "$SSLE_DEMO_DATE -1 day" +%F)" "$SSLE_DEMO_DATE")

LOG=""; MISSING=0
say()  { printf '%s\n' "$*"; [ -n "$LOG" ] && printf '%s\n' "$*" >>"$LOG" || true; }
step() { say ""; say "── $* ──"; }
okk()  { say "  ✓ $*"; }
miss() { say "  ✗ $*"; MISSING=$((MISSING+1)); }
info() { say "  · $*"; }
die()  { say "  ✗ ERRO: $*"; exit 1; }

reboot_pending() { [ ! -d "/usr/lib/modules/$(uname -r)" ]; }
has_incus()      { command -v incus >/dev/null 2>&1; }
incus_ready()    { has_incus && incus admin waitready --timeout 2 >/dev/null 2>&1; }

# ── diagnóstico (só leitura; serve para --check e para o fim do --apply) ─────
check() {
  MISSING=0
  step "plataforma"
  [ "$(uname -m)" = x86_64 ] && [ -f /etc/arch-release ] && okk "Arch Linux x86_64 ($(uname -r))" \
    || die "não estou no T490 (uname -m=$(uname -m)); esta skill só se aplica ao Arch x86_64"
  if reboot_pending; then miss "REBOOT pendente: o kernel foi atualizado sem reiniciar"; else okk "sem reboot pendente"; fi
  info "RAM: $(free -h | awk '/^Mem:/{print $2" total, "$7" disponível"}') · CPUs: $(nproc)"
  info "disco /: $(df -h / | awk 'NR==2{print $4" livres ("$5" usado)"}'), fs=$(findmnt -no FSTYPE /)"

  step "pacotes (atualização única)"
  if [ -f "$MARK_SYU" ]; then okk "atualização única feita: $(cat "$MARK_SYU")"
  else miss "atualização única (-Syu) ainda não feita para o projeto (última: $(grep 'starting full system upgrade' /var/log/pacman.log | tail -1 | cut -c2-11))"; fi
  local p missing_pkgs=()
  for p in "${PKGS[@]}"; do pacman -Q "$p" >/dev/null 2>&1 || missing_pkgs+=("$p"); done
  if [ ${#missing_pkgs[@]} -eq 0 ]; then okk "todos os pacotes: ${PKGS[*]}"; else miss "faltam pacotes: ${missing_pkgs[*]}"; fi

  step "kernel de reserva (linux-lts)"
  if pacman -Q linux-lts >/dev/null 2>&1; then okk "linux-lts $(pacman -Q linux-lts | cut -d' ' -f2) instalado"; else miss "linux-lts não instalado"; fi
  if [ "$(id -u)" = 0 ]; then
    if lts_entry_present; then okk "linux-lts visível no bootloader"; else miss "linux-lts sem entrada no bootloader"; fi
  else info "entrada no bootloader: só verificável com sudo (/boot é só do root)"; fi

  step "contentores sem privilégios"
  if grep -q '^root:' /etc/subuid 2>/dev/null && grep -q '^root:' /etc/subgid 2>/dev/null; then
    okk "root: em /etc/subuid e /etc/subgid ($(grep '^root:' /etc/subuid))"
  else miss "falta 'root:' em /etc/subuid e/ou /etc/subgid"; fi

  step "serviços"
  local s
  for s in "${SERVICES[@]}"; do
    if systemctl is-enabled "$s" >/dev/null 2>&1; then okk "$s enabled ($(systemctl is-active "$s" 2>/dev/null || true))"
    else miss "$s não está enabled"; fi
  done
  if [ "$(timedatectl show -p NTPSynchronized --value)" = yes ]; then okk "relógio sincronizado (NTP)"; else miss "relógio NÃO sincronizado"; fi
  if [ -f "$NODE_DROPIN" ]; then okk "node_exporter do host só em 127.0.0.1:9100 (drop-in)"; else miss "node_exporter sem o drop-in 127.0.0.1 (ficaria exposto na rede de casa)"; fi
  local mm; mm=$(sysctl -n vm.max_map_count)
  [ "$mm" -ge 262144 ] && okk "vm.max_map_count=$mm (Wazuh indexer quer ≥ 262144)" || miss "vm.max_map_count=$mm < 262144"

  step "grupo incus-admin"
  if getent group incus-admin >/dev/null && getent group incus-admin | cut -d: -f4 | tr ',' '\n' | grep -qx "$TARGET_USER"; then
    okk "$TARGET_USER está no incus-admin"
    id -nG | tr ' ' '\n' | grep -qx incus-admin || info "esta sessão é anterior: usar 'sg incus-admin -c \"incus …\"' ou sair e voltar a entrar"
  else miss "$TARGET_USER não está no incus-admin"; fi

  step "Docker no host (regra 2: parte a rede do Incus)"
  if ! pacman -Q docker >/dev/null 2>&1; then okk "Docker ausente"
  elif systemctl is-enabled docker.service >/dev/null 2>&1 || systemctl is-enabled docker.socket >/dev/null 2>&1 \
       || systemctl is-active docker.service >/dev/null 2>&1; then
    if grep -q '"ip-forward-no-drop": *true' /etc/docker/daemon.json 2>/dev/null; then okk "Docker ativo em modo coexist (ip-forward-no-drop)"
    else miss "Docker ativo no host (FORWARD fica em DROP → contentores Incus sem rede)"; fi
  else okk "Docker instalado mas desativado (reverter: sudo systemctl enable --now docker.socket docker.service)"; fi

  step "Incus"
  if ! has_incus; then miss "incus não instalado"
  elif ! incus_ready; then miss "daemon do Incus não responde (incus.service parado ou sem permissão — grupo incus-admin)"
  else
    okk "incus $(incus version 2>/dev/null | awk -F': ' '/Server/{print $2}')"
    if incus storage show lab >/dev/null 2>&1; then
      local drv; drv=$(incus storage show lab | awk '/^driver:/{print $2}')
      [ "$drv" = btrfs ] && okk "pool lab (btrfs)" || miss "pool lab existe mas o driver é '$drv' (queria btrfs)"
      incus profile show default | grep -q 'pool: lab' && okk "profile default → pool lab" || miss "profile default não usa a pool lab"
    else miss "pool 'lab' não existe (incus admin init)"; fi
  fi

  step "máquina de lab"
  [ -f "$LID_CONF" ] && okk "tampa fechada não suspende ($LID_CONF)" || miss "falta $LID_CONF (tampa fechada suspende o lab)"
  local asuser=(); [ "$(id -u)" = 0 ] && asuser=(sudo -u "$TARGET_USER")
  local gh; gh=$("${asuser[@]}" ssh -o BatchMode=yes -o ConnectTimeout=5 -T git@github.com 2>&1 || true)   # -T sai com 1 mesmo a autenticar
  if grep -q 'successfully authenticated' <<< "$gh"; then
    okk "GitHub por SSH autentica ($TARGET_USER)"
  else info "GitHub por SSH: não verificado/autenticado"; fi

  say ""
  if [ "$MISSING" -eq 0 ]; then say "RESULTADO: host PRONTO (fim da F0) ✅"; else say "RESULTADO: faltam $MISSING itens ✗"; fi
}

# ── bootloader: entrada do linux-lts ─────────────────────────────────────────
boot_dir() { bootctl --print-boot-path 2>/dev/null || echo /boot; }
lts_entry_present() {
  if [ -f /boot/grub/grub.cfg ]; then grep -q 'vmlinuz-linux-lts' /boot/grub/grub.cfg; return; fi
  local d; d="$(boot_dir)/loader/entries"
  [ -d "$d" ] && grep -qs 'vmlinuz-linux-lts' "$d"/*.conf
}
add_lts_entry() {
  if lts_entry_present; then okk "linux-lts já está no bootloader"; return; fi
  [ -f "$(boot_dir)/vmlinuz-linux-lts" ] || [ -f /boot/vmlinuz-linux-lts ] || { miss "não encontro /boot/vmlinuz-linux-lts (o pacote linux-lts instalou?)"; return; }
  if [ -f /boot/grub/grub.cfg ]; then
    cp -a /boot/grub/grub.cfg "$STATE/grub.cfg.bak-$(date +%Y%m%d%H%M)"
    grub-mkconfig -o /boot/grub/grub.cfg && okk "GRUB regenerado com o linux-lts (backup em $STATE/)"
    return
  fi
  local d src dst; d="$(boot_dir)/loader/entries"
  [ -d "$d" ] || { miss "bootloader não reconhecido (nem GRUB nem systemd-boot): acrescentar o linux-lts à mão"; return; }
  # entrada principal do kernel 'linux' (não a fallback): tem 'linux /vmlinuz-linux' e initramfs-linux.img
  src=$(grep -lE '^linux[[:space:]]+/vmlinuz-linux[[:space:]]*$' "$d"/*.conf 2>/dev/null | xargs -r grep -L 'fallback' | head -1 || true)
  [ -n "$src" ] || { miss "não encontrei a entrada systemd-boot do kernel 'linux' em $d — não adivinho: acrescentar à mão"; return; }
  dst="$d/ssle-linux-lts.conf"
  sed -E -e 's#^(linux[[:space:]]+/vmlinuz-linux)[[:space:]]*$#\1-lts#' \
         -e 's#initramfs-linux\.img#initramfs-linux-lts.img#' \
         -e 's#^(title[[:space:]]+.*)$#\1 (LTS, reserva SSLE)#' "$src" > "$dst"
  okk "systemd-boot: nova entrada $dst (copiada de $(basename "$src"); o default NÃO muda)"
  say "$(sed 's/^/      | /' "$dst")"
}

# ── passos do --apply ────────────────────────────────────────────────────────
do_upgrade() {
  step "1. atualização única (-Syu) com todos os pacotes"
  if [ "$SKIP_UPGRADE" = 1 ]; then info "--skip-upgrade: salto a -Syu"; return; fi
  local today; today=$(date +%F)
  for f in "${FREEZE_DATES[@]}"; do
    [ "$today" = "$f" ] && die "congelamento: hoje ($today) está nas 48 h antes da entrega/demo — nada de -Syu"
  done
  if [ -f "$MARK_SYU" ] && [ "$FORCE_UPGRADE" = 0 ]; then
    okk "já feita ($(cat "$MARK_SYU")) — a partir daí o sistema está CONGELADO"
    local p missing_pkgs=()
    for p in "${PKGS[@]}"; do pacman -Q "$p" >/dev/null 2>&1 || missing_pkgs+=("$p"); done
    [ ${#missing_pkgs[@]} -eq 0 ] || die "faltam ${missing_pkgs[*]} mas a -Syu já foi feita; instalar sem -Syu seria um upgrade parcial. Decide: --force-upgrade (fora das vésperas) ou viver sem eles"
    return
  fi
  local ts; ts=$(date +%Y%m%d-%H%M)
  pacman -Q > "$STATE/pkgs-before-$ts.txt"
  info "lista de pacotes antes da atualização: $STATE/pkgs-before-$ts.txt (para downgrade a partir de /var/cache/pacman/pkg)"
  info "vai pedir confirmação (S/n): revê a lista antes de aceitar"
  pacman -Syu --needed "${PKGS[@]}"
  printf '%s (kernel linux %s, linux-lts %s, incus %s)\n' "$(date -Is)" \
    "$(pacman -Q linux | cut -d' ' -f2)" "$(pacman -Q linux-lts | cut -d' ' -f2)" "$(pacman -Q incus | cut -d' ' -f2)" > "$MARK_SYU"
  okk "atualização única concluída: $(cat "$MARK_SYU")"
}

do_subids() {
  step "2. UID/GID para contentores sem privilégios"
  if grep -q '^root:' /etc/subuid && grep -q '^root:' /etc/subgid; then okk "já existe ($(grep '^root:' /etc/subuid))"; return; fi
  usermod -v 1000000-1000999999 -w 1000000-1000999999 root
  okk "root:1000000:1000000000 em /etc/subuid e /etc/subgid"
}

do_docker() {
  step "3. Docker do host (modo: $DOCKER_MODE)"
  pacman -Q docker >/dev/null 2>&1 || { okk "Docker ausente"; return; }
  case "$DOCKER_MODE" in
    keep) info "--docker=keep: não mexo (atenção: com o Docker ativo o FORWARD fica em DROP)";;
    disable)
      { systemctl is-enabled docker.service; systemctl is-enabled docker.socket; } > "$STATE/docker-was-enabled" 2>&1 || true
      systemctl disable --now docker.socket docker.service 2>&1 | sed 's/^/      /' || true
      okk "Docker parado e desativado (estado anterior em $STATE/docker-was-enabled)"
      info "reverter (p.ex. para o projeto de CA): sudo systemctl enable --now docker.socket docker.service"
      if iptables -S FORWARD 2>/dev/null | head -1 | grep -q 'DROP'; then
        info "a política FORWARD=DROP que o Docker deixou só desaparece no reboot (ou: sudo iptables -P FORWARD ACCEPT)"
      fi ;;
    coexist)
      mkdir -p /etc/docker
      if [ -f /etc/docker/daemon.json ]; then
        cp -a /etc/docker/daemon.json "$STATE/daemon.json.bak-$(date +%Y%m%d%H%M)"
        jq '. + {"ip-forward-no-drop": true}' /etc/docker/daemon.json > /etc/docker/daemon.json.new
        mv /etc/docker/daemon.json.new /etc/docker/daemon.json
      else printf '{\n  "ip-forward-no-drop": true\n}\n' > /etc/docker/daemon.json; fi
      systemctl restart docker.service
      iptables -P FORWARD ACCEPT
      okk "Docker em coexist: ip-forward-no-drop (o FORWARD continua ACCEPT para as bridges do Incus)";;
  esac
}

do_node_exporter() {
  step "4. node_exporter do host só em 127.0.0.1"
  mkdir -p "$(dirname "$NODE_DROPIN")"
  cat > "$NODE_DROPIN" <<'EOF'
# SSLE: não expor as métricas do host na rede de casa (safeguard "não expor por omissão").
# O core/obs chega aqui por um proxy device do Incus (bind=instance) criado pelo infra/deploy.sh.
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=127.0.0.1:9100
EOF
  systemctl daemon-reload
  okk "$NODE_DROPIN"
}

do_lid() {
  step "5. tampa fechada sem suspender"
  [ -f "$LID_CONF" ] && { okk "já existe"; return; }
  mkdir -p "$(dirname "$LID_CONF")"
  printf '[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\n' > "$LID_CONF"
  okk "$LID_CONF (aplica-se no próximo arranque)"
}

do_services() {
  step "6. serviços e grupo"
  systemctl enable --now sshd.service prometheus-node-exporter.service systemd-timesyncd.service 2>&1 | sed 's/^/      /' || true
  timedatectl set-ntp true
  if reboot_pending; then
    systemctl enable incus.socket incus.service 2>&1 | sed 's/^/      /'
    info "incus enabled; arranca depois do reboot (módulos do kernel novo)"
  else
    systemctl enable --now incus.socket incus.service 2>&1 | sed 's/^/      /'
  fi
  getent group incus-admin >/dev/null || die "o grupo incus-admin não existe (o pacote incus instalou?)"
  usermod -aG incus-admin "$TARGET_USER"
  okk "$TARGET_USER no incus-admin (≈ root: aceitável numa máquina de lab dedicada)"
  okk "sshd, node_exporter, timesyncd enabled; NTP ligado"
}

do_incus_init() {
  step "7. Incus: pool btrfs 'lab' (incus admin init --preseed)"
  incus admin waitready --timeout 60 || die "o daemon do Incus não arrancou (journalctl -u incus)"
  if incus storage show lab >/dev/null 2>&1; then okk "pool lab já existe"; return; fi
  if [ -n "$(incus storage list --format csv 2>/dev/null)" ]; then
    die "já há outra pool no Incus ($(incus storage list --format csv | cut -d, -f1 | tr '\n' ' ')) — não sobreponho; decidir à mão"
  fi
  local free_g want_g
  free_g=$(df -BG --output=avail /var/lib | tail -1 | tr -dc 0-9)
  want_g=$(echo "$POOL_SIZE" | tr -dc 0-9)
  [ "$free_g" -gt $((want_g + 40)) ] || die "pouco disco: ${free_g}G livres para uma pool de $POOL_SIZE (+40G de margem para o host)"
  sed "s/@@POOL_SIZE@@/$POOL_SIZE/" "$HERE/incus-preseed.yaml" | incus admin init --preseed
  [ "$(incus storage show lab | awk '/^driver:/{print $2}')" = btrfs ] || die "a pool lab não ficou em btrfs"
  okk "pool lab (btrfs, ficheiro loop $POOL_SIZE esparso) + incusbr0 + profile default"
  incus storage info lab | sed 's/^/      /' | head -8
}

do_smoke() {
  step "8. teste de fumo"
  [ "$SKIP_SMOKE" = 1 ] && { info "--skip-smoke"; return; }
  local c=ssle-smoke
  if incus info "$c" >/dev/null 2>&1; then info "já existe um contentor '$c' (não fui eu agora): não lhe mexo; salto o teste"; return; fi
  incus launch images:debian/trixie "$c" >/dev/null
  local ok=0
  for _ in $(seq 1 40); do incus exec "$c" -- sh -c 'ip -4 route | grep -q ^default' 2>/dev/null && { ok=1; break; }; sleep 1; done
  [ "$ok" = 1 ] || { incus delete -f "$c"; die "contentor sem rota default: ver firewall/Docker (regras 2 e 3)"; }
  incus exec "$c" -- sh -c 'apt-get update -qq && echo REDE-OK' | tail -1 | sed 's/^/      /'
  local t0 t1; t0=$(date +%s.%N); incus snapshot create "$c" s1; t1=$(date +%s.%N)
  okk "snapshot btrfs em $(echo "$t1 - $t0" | bc 2>/dev/null || python3 -c "print(round($t1-$t0,2))") s"
  incus snapshot list "$c" --format csv | sed 's/^/      /'
  incus delete -f "$c"
  okk "teste de fumo passou (contentor $c apagado)"
  incus image list images: kali architecture=x86_64 --format csv -c l 2>/dev/null | head -2 | sed 's/^/      kali x86_64: /' || true
}

apply() {
  [ "$(id -u)" = 0 ] || { echo "o --apply precisa de root: sudo bash $0 --apply"; exit 1; }
  [ "$(uname -m)" = x86_64 ] && [ -f /etc/arch-release ] || { echo "não é o T490 (Arch x86_64) — paro"; exit 1; }
  mkdir -p "$STATE" "$ROOT/build"
  LOG="$ROOT/build/t490-setup-$(date +%Y%m%d-%H%M).log"; : > "$LOG"; chown "$TARGET_USER": "$LOG" "$ROOT/build" 2>/dev/null || true
  say "SSLE P1 — setup do T490 ($(date -Is)) · utilizador: $TARGET_USER · docker=$DOCKER_MODE · pool=$POOL_SIZE"
  do_upgrade
  do_subids
  do_docker
  do_node_exporter
  do_lid
  step "kernel de reserva no bootloader"; add_lts_entry
  do_services
  if reboot_pending; then
    say ""
    say "════════════════════════════════════════════════════════════════════"
    say " FASE 1 concluída. O kernel foi atualizado: REINICIA agora o T490"
    say "   sudo reboot"
    say " e depois corre o MESMO comando para a fase 2 (Incus + pool + teste):"
    say "   sudo bash infra/t490/setup-host.sh --apply"
    say "════════════════════════════════════════════════════════════════════"
    say "(log: $LOG)"
    return
  fi
  do_incus_init
  do_smoke
  say ""; say "══ verificação final ══"
  check
  say "(log: $LOG)"
}

if [ "$MODE" = apply ]; then apply; else check; fi
