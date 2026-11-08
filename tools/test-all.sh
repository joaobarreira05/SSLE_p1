#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# "CI" local do Projeto 1: tudo o que se valida SEM o lab (sem Incus, sem root).
#   bash tools/fetch-tools.sh     # 1.ª vez: promtool-2/-3 + amtool em build/tools (sha256 conferido)
#   bash tools/test-all.sh        # sai ≠ 0 se alguma coisa falhar
# Opcional: SSLE_LOGTEST=1 também corre o wazuh-logtest (siem/tests/run-logtest.sh, precisa de Docker).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/build/tools"
FAIL=0
run() {  # run <descrição> <comando…>
  local d="$1"; shift
  local out; out="$("$@" 2>&1)"; local rc=$?
  if [ $rc -eq 0 ]; then printf '  ✓ %s\n' "$d"; else printf '  ✗ %s\n%s\n' "$d" "$(sed 's/^/      /' <<<"$out")"; FAIL=1; fi
}
[ -x "$T/promtool-2" ] || bash "$ROOT/tools/fetch-tools.sh"

echo "[1] regras Prometheus (sintaxe) e testes unitários"
for v in 2 3; do
  run "promtool-$v check rules (site + global)" "$T/promtool-$v" check rules "$ROOT"/monitoring/site/rules/*.yml "$ROOT/monitoring/global/rules.yml"
  run "promtool-$v test rules (monitoring/tests/*.yml)" sh -c "cd '$ROOT/monitoring/tests' && '$T/promtool-$v' test rules *.yml"
done
echo "[2] configs"
run "amtool check-config alertmanager.yml" "$T/amtool" check-config "$ROOT/monitoring/global/alertmanager.yml"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 "$ROOT/infra/inventory.py" render --out "$tmp/build" --host t490 >/dev/null
sed "s/HOSTPLACEHOLDER/t490/" "$ROOT/monitoring/global/prometheus.yml" > "$tmp/global.yml"
sed -i "s#/etc/prometheus/federate.json#$tmp/build/federate.json#; s#/etc/prometheus/rules/\*.yml#$ROOT/monitoring/global/rules.yml#" "$tmp/global.yml"
run "promtool-3 check config (Prometheus global, renderizado)" "$T/promtool-3" check config --syntax-only "$tmp/global.yml"
for site in avr opo lis; do
  sed -e "s/@@SITE@@/$site/g" -e "s#@@ALERTMANAGER@@#10.10.0.10:9093#g" \
      -e "s#/etc/prometheus/rules/\*.yml#$ROOT/monitoring/site/rules/*.yml#" \
      -e "s#/etc/prometheus/targets/#$tmp/build/targets/$site/#g" "$ROOT/monitoring/site/prometheus.yml.tmpl" > "$tmp/site-$site.yml"
  run "promtool-2 check config (Prometheus de site $site, renderizado)" "$T/promtool-2" check config --syntax-only "$tmp/site-$site.yml"
done
echo "[3] Python"
run "correlator: python3 -m unittest correlator/test_rca.py" python3 -m unittest -q "$ROOT/correlator/test_rca.py"
for f in "$ROOT"/correlator/*.py "$ROOT"/services/*.py "$ROOT"/infra/*.py "$ROOT"/threats/*/*.py; do
  [ -f "$f" ] && run "py_compile ${f#"$ROOT"/}" python3 -m py_compile "$f"
done
echo "[4] shell"
mapfile -t SH < <(find "$ROOT/infra" "$ROOT/threats" "$ROOT/tools" "$ROOT/siem" "$ROOT/evaluation" -name '*.sh' | sort)
for f in "${SH[@]}"; do run "bash -n ${f#"$ROOT"/}" bash -n "$f"; done
if command -v shellcheck >/dev/null 2>&1; then SC=(shellcheck); elif command -v uvx >/dev/null 2>&1; then SC=(uvx -q --from shellcheck-py shellcheck); else SC=(); fi
# C.UTF-8 e caminhos relativos: o caminho do repo tem acentos ("Área de Trabalho") e o shellcheck não os escreve em LC_ALL=C
[ ${#SC[@]} -gt 0 ] && run "shellcheck -S warning (${#SH[@]} scripts)" \
  env LC_ALL=C.UTF-8 sh -c 'cd "$1" && shift && "$@"' _ "$ROOT" "${SC[@]}" -S warning "${SH[@]#"$ROOT"/}"
if [ "${SSLE_LOGTEST:-0}" = 1 ]; then
  echo "[5] Wazuh"
  run "wazuh-logtest (siem/tests/run-logtest.sh)" bash "$ROOT/siem/tests/run-logtest.sh"
fi
echo
[ $FAIL -eq 0 ] && echo "RESULTADO: tudo verde ✅" || echo "RESULTADO: há falhas ✗"
exit $FAIL
