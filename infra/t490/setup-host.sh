#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# T490 host setup (Project 1, phase F0) in a single command.
#
#   bash infra/t490/setup-host.sh                  # --check (default): READ ONLY, "present / missing" summary
#   sudo bash infra/t490/setup-host.sh --apply     # applies ONLY what is missing (idempotent)
#
# --apply has two phases, because the single upgrade almost always brings a new kernel:
#   phase 1: single -Syu + host configuration  → asks for a REBOOT
#   phase 2: (after the reboot, the SAME command) incus admin init (btrfs pool "lab") + smoke test
#
# Options:
#   --docker=disable   (default) stops and disables the host Docker (reversible: see the end of the output)
#   --docker=coexist   keeps Docker but with ip-forward-no-drop (does not set FORWARD to DROP)
#   --docker=keep      leaves Docker alone (NOT recommended: it breaks Incus networking)
#   --pool-size=180GiB size of the btrfs loop file of the "lab" pool (root on ext4)
#   --skip-upgrade     does not run the -Syu (e.g. if the single upgrade was already done another way)
#   --force-upgrade    repeats the -Syu even with the marker (never in the 48 h before delivery/demo)
#   --skip-smoke       does not run the smoke test
#
# Fail closed: on error it stops (set -e) without leaving a half configuration; each step checks before
# changing anything (run it as many times as needed). Nothing here exposes services to the home network:
# the host node_exporter stays on 127.0.0.1 (core/obs reaches it through an Incus proxy device).
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
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
case "$DOCKER_MODE" in disable|coexist|keep) ;; *) echo "--docker=disable|coexist|keep" >&2; exit 2 ;; esac

# Everything the host will need, in a SINGLE transaction (no partial upgrades on Arch).
PKGS=(incus btrfs-progs openssh git prometheus-node-exporter linux-lts
      jq go-yq tmux htop rsync tcpdump bind wireguard-tools python python-yaml)
SERVICES=(incus.socket incus.service sshd.service prometheus-node-exporter.service systemd-timesyncd.service)
STATE=/var/lib/ssle                       # setup markers (outside the repo, outside Git)
MARK_SYU="$STATE/syu-done"
TARGET_USER="${SUDO_USER:-$(id -un)}"
NODE_DROPIN=/etc/systemd/system/prometheus-node-exporter.service.d/ssle.conf
LID_CONF=/etc/systemd/logind.conf.d/lid.conf
# Freeze: no -Syu in the 48 h before delivery (22/11). Demo date, when known: SSLE_DEMO_DATE=YYYY-MM-DD
FREEZE_DATES=("2026-11-20" "2026-11-21" "2026-11-22")
[ -n "${SSLE_DEMO_DATE:-}" ] && FREEZE_DATES+=("$(date -d "$SSLE_DEMO_DATE -2 day" +%F)" "$(date -d "$SSLE_DEMO_DATE -1 day" +%F)" "$SSLE_DEMO_DATE")

LOG=""; MISSING=0
say()  { printf '%s\n' "$*"; [ -n "$LOG" ] && printf '%s\n' "$*" >>"$LOG" || true; }
step() { say ""; say "── $* ──"; }
okk()  { say "  ✓ $*"; }
miss() { say "  ✗ $*"; MISSING=$((MISSING+1)); }
info() { say "  · $*"; }
die()  { say "  ✗ ERROR: $*"; exit 1; }

reboot_pending() { [ ! -d "/usr/lib/modules/$(uname -r)" ]; }
has_incus()      { command -v incus >/dev/null 2>&1; }
incus_ready()    { has_incus && incus admin waitready --timeout 2 >/dev/null 2>&1; }

# ── diagnosis (read only; used by --check and at the end of --apply) ─────────
check() {
  MISSING=0
  step "platform"
  [ "$(uname -m)" = x86_64 ] && [ -f /etc/arch-release ] && okk "Arch Linux x86_64 ($(uname -r))" \
    || die "not on the T490 (uname -m=$(uname -m)); this script only applies to Arch x86_64"
  if reboot_pending; then miss "REBOOT pending: the kernel was upgraded without restarting"; else okk "no reboot pending"; fi
  info "RAM: $(free -h | awk '/^Mem:/{print $2" total, "$7" available"}') · CPUs: $(nproc)"
  info "disk /: $(df -h / | awk 'NR==2{print $4" free ("$5" used)"}'), fs=$(findmnt -no FSTYPE /)"

  step "packages (single upgrade)"
  if [ -f "$MARK_SYU" ]; then okk "single upgrade done: $(cat "$MARK_SYU")"
  else miss "single upgrade (-Syu) not yet done for the project (last one: $(grep 'starting full system upgrade' /var/log/pacman.log | tail -1 | cut -c2-11))"; fi
  local p missing_pkgs=()
  for p in "${PKGS[@]}"; do pacman -Q "$p" >/dev/null 2>&1 || missing_pkgs+=("$p"); done
  if [ ${#missing_pkgs[@]} -eq 0 ]; then okk "all packages: ${PKGS[*]}"; else miss "missing packages: ${missing_pkgs[*]}"; fi

  step "fallback kernel (linux-lts)"
  if pacman -Q linux-lts >/dev/null 2>&1; then okk "linux-lts $(pacman -Q linux-lts | cut -d' ' -f2) installed"; else miss "linux-lts not installed"; fi
  if [ "$(id -u)" = 0 ]; then
    if lts_entry_present; then okk "linux-lts visible in the bootloader"; else miss "linux-lts has no bootloader entry"; fi
  else info "bootloader entry: only verifiable with sudo (/boot is root only)"; fi

  step "unprivileged containers"
  if grep -q '^root:' /etc/subuid 2>/dev/null && grep -q '^root:' /etc/subgid 2>/dev/null; then
    okk "root: in /etc/subuid and /etc/subgid ($(grep '^root:' /etc/subuid))"
  else miss "'root:' missing from /etc/subuid and/or /etc/subgid"; fi

  step "services"
  local s
  for s in "${SERVICES[@]}"; do
    if systemctl is-enabled "$s" >/dev/null 2>&1; then okk "$s enabled ($(systemctl is-active "$s" 2>/dev/null || true))"
    else miss "$s is not enabled"; fi
  done
  if [ "$(timedatectl show -p NTPSynchronized --value)" = yes ]; then okk "clock synchronised (NTP)"; else miss "clock NOT synchronised"; fi
  if [ -f "$NODE_DROPIN" ]; then okk "host node_exporter only on 127.0.0.1:9100 (drop-in)"; else miss "node_exporter without the 127.0.0.1 drop-in (it would be exposed on the home network)"; fi
  local mm; mm=$(sysctl -n vm.max_map_count)
  [ "$mm" -ge 262144 ] && okk "vm.max_map_count=$mm (Wazuh indexer wants ≥ 262144)" || miss "vm.max_map_count=$mm < 262144"

  step "incus-admin group"
  if getent group incus-admin >/dev/null && getent group incus-admin | cut -d: -f4 | tr ',' '\n' | grep -qx "$TARGET_USER"; then
    okk "$TARGET_USER is in incus-admin"
    id -nG | tr ' ' '\n' | grep -qx incus-admin || info "this session predates it: use 'sg incus-admin -c \"incus …\"' or log out and back in"
  else miss "$TARGET_USER is not in incus-admin"; fi

  step "Docker on the host (it breaks Incus networking)"
  if ! pacman -Q docker >/dev/null 2>&1; then okk "Docker absent"
  elif systemctl is-enabled docker.service >/dev/null 2>&1 || systemctl is-enabled docker.socket >/dev/null 2>&1 \
       || systemctl is-active docker.service >/dev/null 2>&1; then
    if grep -q '"ip-forward-no-drop": *true' /etc/docker/daemon.json 2>/dev/null; then okk "Docker active in coexist mode (ip-forward-no-drop)"
    else miss "Docker active on the host (FORWARD set to DROP → Incus containers without network)"; fi
  else okk "Docker installed but disabled (revert: sudo systemctl enable --now docker.socket docker.service)"; fi

  step "Incus"
  if ! has_incus; then miss "incus not installed"
  elif ! incus_ready; then miss "Incus daemon not answering (incus.service stopped or no permission — incus-admin group)"
  else
    okk "incus $(incus version 2>/dev/null | awk -F': ' '/Server/{print $2}')"
    if incus storage show lab >/dev/null 2>&1; then
      local drv; drv=$(incus storage show lab | awk '/^driver:/{print $2}')
      [ "$drv" = btrfs ] && okk "pool lab (btrfs)" || miss "pool lab exists but its driver is '$drv' (wanted btrfs)"
      incus profile show default | grep -q 'pool: lab' && okk "profile default → pool lab" || miss "default profile does not use the lab pool"
    else miss "pool 'lab' does not exist (incus admin init)"; fi
  fi

  step "lab machine"
  [ -f "$LID_CONF" ] && okk "closed lid does not suspend ($LID_CONF)" || miss "missing $LID_CONF (a closed lid suspends the lab)"
  local asuser=(); [ "$(id -u)" = 0 ] && asuser=(sudo -u "$TARGET_USER")
  local gh; gh=$("${asuser[@]}" ssh -o BatchMode=yes -o ConnectTimeout=5 -T git@github.com 2>&1 || true)   # -T exits with 1 even when authenticating
  if grep -q 'successfully authenticated' <<< "$gh"; then
    okk "GitHub over SSH authenticates ($TARGET_USER)"
  else info "GitHub over SSH: not verified/authenticated"; fi

  say ""
  if [ "$MISSING" -eq 0 ]; then say "RESULT: host READY (end of F0) ✅"; else say "RESULT: $MISSING items missing ✗"; fi
}

# ── bootloader: linux-lts entry ──────────────────────────────────────────────
boot_dir() { bootctl --print-boot-path 2>/dev/null || echo /boot; }
lts_entry_present() {
  if [ -f /boot/grub/grub.cfg ]; then grep -q 'vmlinuz-linux-lts' /boot/grub/grub.cfg; return; fi
  local d; d="$(boot_dir)/loader/entries"
  [ -d "$d" ] && grep -qs 'vmlinuz-linux-lts' "$d"/*.conf
}
add_lts_entry() {
  if lts_entry_present; then okk "linux-lts is already in the bootloader"; return; fi
  [ -f "$(boot_dir)/vmlinuz-linux-lts" ] || [ -f /boot/vmlinuz-linux-lts ] || { miss "cannot find /boot/vmlinuz-linux-lts (did the linux-lts package install?)"; return; }
  if [ -f /boot/grub/grub.cfg ]; then
    cp -a /boot/grub/grub.cfg "$STATE/grub.cfg.bak-$(date +%Y%m%d%H%M)"
    grub-mkconfig -o /boot/grub/grub.cfg && okk "GRUB regenerated with linux-lts (backup in $STATE/)"
    return
  fi
  local d src dst; d="$(boot_dir)/loader/entries"
  [ -d "$d" ] || { miss "bootloader not recognised (neither GRUB nor systemd-boot): add linux-lts by hand"; return; }
  # main entry of the 'linux' kernel (not the fallback): has 'linux /vmlinuz-linux' and initramfs-linux.img
  src=$(grep -lE '^linux[[:space:]]+/vmlinuz-linux[[:space:]]*$' "$d"/*.conf 2>/dev/null | xargs -r grep -L 'fallback' | head -1 || true)
  [ -n "$src" ] || { miss "systemd-boot entry for the 'linux' kernel not found in $d — not guessing: add it by hand"; return; }
  dst="$d/ssle-linux-lts.conf"
  sed -E -e 's#^(linux[[:space:]]+/vmlinuz-linux)[[:space:]]*$#\1-lts#' \
         -e 's#initramfs-linux\.img#initramfs-linux-lts.img#' \
         -e 's#^(title[[:space:]]+.*)$#\1 (LTS, SSLE fallback)#' "$src" > "$dst"
  okk "systemd-boot: new entry $dst (copied from $(basename "$src"); the default does NOT change)"
  say "$(sed 's/^/      | /' "$dst")"
}

# ── --apply steps ────────────────────────────────────────────────────────────
do_upgrade() {
  step "1. single upgrade (-Syu) with every package"
  if [ "$SKIP_UPGRADE" = 1 ]; then info "--skip-upgrade: skipping the -Syu"; return; fi
  local today; today=$(date +%F)
  for f in "${FREEZE_DATES[@]}"; do
    [ "$today" = "$f" ] && die "freeze: today ($today) is within 48 h of delivery/demo — no -Syu"
  done
  if [ -f "$MARK_SYU" ] && [ "$FORCE_UPGRADE" = 0 ]; then
    okk "already done ($(cat "$MARK_SYU")) — from then on the system is FROZEN"
    local p missing_pkgs=()
    for p in "${PKGS[@]}"; do pacman -Q "$p" >/dev/null 2>&1 || missing_pkgs+=("$p"); done
    [ ${#missing_pkgs[@]} -eq 0 ] || die "missing ${missing_pkgs[*]} but the -Syu was already done; installing without -Syu would be a partial upgrade. Decide: --force-upgrade (not on the eve) or live without them"
    return
  fi
  local ts; ts=$(date +%Y%m%d-%H%M)
  pacman -Q > "$STATE/pkgs-before-$ts.txt"
  info "package list before the upgrade: $STATE/pkgs-before-$ts.txt (for a downgrade from /var/cache/pacman/pkg)"
  info "it will ask for confirmation (Y/n): review the list before accepting"
  pacman -Syu --needed "${PKGS[@]}"
  printf '%s (kernel linux %s, linux-lts %s, incus %s)\n' "$(date -Is)" \
    "$(pacman -Q linux | cut -d' ' -f2)" "$(pacman -Q linux-lts | cut -d' ' -f2)" "$(pacman -Q incus | cut -d' ' -f2)" > "$MARK_SYU"
  okk "single upgrade finished: $(cat "$MARK_SYU")"
}

do_subids() {
  step "2. UID/GID for unprivileged containers"
  if grep -q '^root:' /etc/subuid && grep -q '^root:' /etc/subgid; then okk "already present ($(grep '^root:' /etc/subuid))"; return; fi
  usermod -v 1000000-1000999999 -w 1000000-1000999999 root
  okk "root:1000000:1000000000 in /etc/subuid and /etc/subgid"
}

do_docker() {
  step "3. host Docker (mode: $DOCKER_MODE)"
  pacman -Q docker >/dev/null 2>&1 || { okk "Docker absent"; return; }
  case "$DOCKER_MODE" in
    keep) info "--docker=keep: left alone (careful: with Docker active FORWARD is set to DROP)";;
    disable)
      { systemctl is-enabled docker.service; systemctl is-enabled docker.socket; } > "$STATE/docker-was-enabled" 2>&1 || true
      systemctl disable --now docker.socket docker.service 2>&1 | sed 's/^/      /' || true
      okk "Docker stopped and disabled (previous state in $STATE/docker-was-enabled)"
      info "revert (e.g. for another project): sudo systemctl enable --now docker.socket docker.service"
      if iptables -S FORWARD 2>/dev/null | head -1 | grep -q 'DROP'; then
        info "the FORWARD=DROP policy left by Docker only goes away on reboot (or: sudo iptables -P FORWARD ACCEPT)"
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
      okk "Docker in coexist: ip-forward-no-drop (FORWARD stays ACCEPT for the Incus bridges)";;
  esac
}

do_node_exporter() {
  step "4. host node_exporter only on 127.0.0.1"
  mkdir -p "$(dirname "$NODE_DROPIN")"
  cat > "$NODE_DROPIN" <<'EOF'
# SSLE: do not expose the host metrics on the home network ("not exposed by default" safeguard).
# core/obs reaches this through an Incus proxy device (bind=instance) created by infra/deploy.sh.
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=127.0.0.1:9100
EOF
  systemctl daemon-reload
  okk "$NODE_DROPIN"
}

do_lid() {
  step "5. closed lid without suspending"
  [ -f "$LID_CONF" ] && { okk "already present"; return; }
  mkdir -p "$(dirname "$LID_CONF")"
  printf '[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\n' > "$LID_CONF"
  okk "$LID_CONF (applies on the next boot)"
}

do_services() {
  step "6. services and group"
  systemctl enable --now sshd.service prometheus-node-exporter.service systemd-timesyncd.service 2>&1 | sed 's/^/      /' || true
  timedatectl set-ntp true
  if reboot_pending; then
    systemctl enable incus.socket incus.service 2>&1 | sed 's/^/      /'
    info "incus enabled; starts after the reboot (new kernel modules)"
  else
    systemctl enable --now incus.socket incus.service 2>&1 | sed 's/^/      /'
  fi
  getent group incus-admin >/dev/null || die "the incus-admin group does not exist (did the incus package install?)"
  usermod -aG incus-admin "$TARGET_USER"
  okk "$TARGET_USER in incus-admin (≈ root: acceptable on a dedicated lab machine)"
  okk "sshd, node_exporter, timesyncd enabled; NTP on"
}

do_incus_init() {
  step "7. Incus: pool btrfs 'lab' (incus admin init --preseed)"
  incus admin waitready --timeout 60 || die "the Incus daemon did not start (journalctl -u incus)"
  if incus storage show lab >/dev/null 2>&1; then okk "pool lab already exists"; return; fi
  if [ -n "$(incus storage list --format csv 2>/dev/null)" ]; then
    die "Incus already has another pool ($(incus storage list --format csv | cut -d, -f1 | tr '\n' ' ')) — not overriding; decide by hand"
  fi
  local free_g want_g
  free_g=$(df -BG --output=avail /var/lib | tail -1 | tr -dc 0-9)
  want_g=$(echo "$POOL_SIZE" | tr -dc 0-9)
  [ "$free_g" -gt $((want_g + 40)) ] || die "not enough disk: ${free_g}G free for a $POOL_SIZE pool (+40G margin for the host)"
  sed "s/@@POOL_SIZE@@/$POOL_SIZE/" "$HERE/incus-preseed.yaml" | incus admin init --preseed
  [ "$(incus storage show lab | awk '/^driver:/{print $2}')" = btrfs ] || die "the lab pool did not end up on btrfs"
  okk "pool lab (btrfs, sparse $POOL_SIZE loop file) + incusbr0 + default profile"
  incus storage info lab | sed 's/^/      /' | head -8
}

do_smoke() {
  step "8. smoke test"
  [ "$SKIP_SMOKE" = 1 ] && { info "--skip-smoke"; return; }
  local c=ssle-smoke
  if incus info "$c" >/dev/null 2>&1; then info "a container '$c' already exists (not created now): leaving it alone; skipping the test"; return; fi
  incus launch images:debian/trixie "$c" >/dev/null
  local ok=0
  for _ in $(seq 1 40); do incus exec "$c" -- sh -c 'ip -4 route | grep -q ^default' 2>/dev/null && { ok=1; break; }; sleep 1; done
  [ "$ok" = 1 ] || { incus delete -f "$c"; die "container has no default route: check firewall/Docker"; }
  incus exec "$c" -- sh -c 'apt-get update -qq && echo NETWORK-OK' | tail -1 | sed 's/^/      /'
  local t0 t1; t0=$(date +%s.%N); incus snapshot create "$c" s1; t1=$(date +%s.%N)
  okk "btrfs snapshot in $(echo "$t1 - $t0" | bc 2>/dev/null || python3 -c "print(round($t1-$t0,2))") s"
  incus snapshot list "$c" --format csv | sed 's/^/      /'
  incus delete -f "$c"
  okk "smoke test passed (container $c deleted)"
  incus image list images: kali architecture=x86_64 --format csv -c l 2>/dev/null | head -2 | sed 's/^/      kali x86_64: /' || true
}

apply() {
  [ "$(id -u)" = 0 ] || { echo "--apply needs root: sudo bash $0 --apply"; exit 1; }
  [ "$(uname -m)" = x86_64 ] && [ -f /etc/arch-release ] || { echo "this is not the T490 (Arch x86_64) — stopping"; exit 1; }
  mkdir -p "$STATE" "$ROOT/build"
  LOG="$ROOT/build/t490-setup-$(date +%Y%m%d-%H%M).log"; : > "$LOG"; chown "$TARGET_USER": "$LOG" "$ROOT/build" 2>/dev/null || true
  say "SSLE P1 — T490 setup ($(date -Is)) · user: $TARGET_USER · docker=$DOCKER_MODE · pool=$POOL_SIZE"
  do_upgrade
  do_subids
  do_docker
  do_node_exporter
  do_lid
  step "fallback kernel in the bootloader"; add_lts_entry
  do_services
  if reboot_pending; then
    say ""
    say "════════════════════════════════════════════════════════════════════"
    say " PHASE 1 done. The kernel was upgraded: REBOOT the T490 now"
    say "   sudo reboot"
    say " and then run the SAME command for phase 2 (Incus + pool + test):"
    say "   sudo bash infra/t490/setup-host.sh --apply"
    say "════════════════════════════════════════════════════════════════════"
    say "(log: $LOG)"
    return
  fi
  do_incus_init
  do_smoke
  say ""; say "══ final check ══"
  check
  say "(log: $LOG)"
}

if [ "$MODE" = apply ]; then apply; else check; fi
