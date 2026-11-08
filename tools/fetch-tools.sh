#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Ferramentas de VALIDAÇÃO no host, sem root e sem tocar no sistema:
#   build/tools/promtool-2   (Prometheus 2.53.x — a linha do apt dos Prometheus de site, Debian trixie)
#   build/tools/promtool-3   (Prometheus 3.5.x LTS — o global do docker-compose)
#   build/tools/amtool       (Alertmanager)
#   build/tools/prometheus-2 (o servidor 2.53.x — testes de integração locais em 127.0.0.1)
# Binários oficiais do GitHub, com o sha256 conferido contra o sha256sums.txt da release
# (se não bater, aborta — falha fechada). build/ está no .gitignore.
#
#   bash tools/fetch-tools.sh && bash tools/test-all.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/tools"; mkdir -p "$OUT"
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "arquitetura?"; exit 1 ;; esac

fetch() {  # fetch <repo> <versão> "<binário>:<nome final> [...]"
  local repo="$1" ver="$2" pairs="$3" p all=1
  for p in $pairs; do [ -x "$OUT/${p#*:}" ] || all=0; done
  if [ "$all" = 1 ]; then for p in $pairs; do echo "  ✓ ${p#*:} ($("$OUT/${p#*:}" --version 2>&1 | head -1))"; done; return; fi
  local base="https://github.com/prometheus/$repo/releases/download/v$ver"
  local tgz="$repo-$ver.linux-$ARCH.tar.gz" tmp; tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$tgz" "$base/$tgz"
  curl -fsSL -o "$tmp/sha256sums.txt" "$base/sha256sums.txt"
  (cd "$tmp" && grep " $tgz\$" sha256sums.txt | sha256sum -c --quiet -) || { echo "  ✗ sha256 NÃO confere: $tgz"; rm -rf "$tmp"; exit 1; }
  for p in $pairs; do
    tar -xzf "$tmp/$tgz" -C "$tmp" "$repo-$ver.linux-$ARCH/${p%%:*}"
    install -m 0755 "$tmp/$repo-$ver.linux-$ARCH/${p%%:*}" "$OUT/${p#*:}"
    echo "  ✓ ${p#*:} ($("$OUT/${p#*:}" --version 2>&1 | head -1)) — sha256 conferido"
  done
  rm -rf "$tmp"
}

echo "[tools] a obter para $OUT"
fetch prometheus   2.53.5 "promtool:promtool-2 prometheus:prometheus-2"
fetch prometheus   3.5.5  "promtool:promtool-3"
fetch alertmanager 0.28.1 "amtool:amtool"
