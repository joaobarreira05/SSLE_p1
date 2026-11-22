#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Local "CI" for Project 1: everything that can be validated WITHOUT the lab (no Incus, no root).
#   bash tools/fetch-tools.sh     # 1st time: promtool-2/-3 + amtool into build/tools (sha256 checked)
#   bash tools/test-all.sh        # exits ≠ 0 if anything fails
# Optional: SSLE_LOGTEST=1 also runs wazuh-logtest (siem/tests/run-logtest.sh, needs Docker).
#           SSLE_IT=1 also runs the integration with real agents (siem/tests/it-agents.sh, Docker + network, ~8 min).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$ROOT/build/tools"
FAIL=0
run() {  # run <description> <command…>
  local d="$1"; shift
  local out; out="$("$@" 2>&1)"; local rc=$?
  if [ $rc -eq 0 ]; then printf '  ✓ %s\n' "$d"; else printf '  ✗ %s\n%s\n' "$d" "$(sed 's/^/      /' <<<"$out")"; FAIL=1; fi
}
[ -x "$T/promtool-2" ] || bash "$ROOT/tools/fetch-tools.sh"

echo "[1] Prometheus rules (syntax) and unit tests"
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
run "promtool-3 check config (global Prometheus, rendered)" "$T/promtool-3" check config --syntax-only "$tmp/global.yml"
for site in avr opo lis; do
  python3 "$ROOT/infra/inventory.py" siteprom --site "$site" --host t490 \
    | sed -e "s#/etc/prometheus/rules/\*.yml#$ROOT/monitoring/site/rules/*.yml#" \
          -e "s#/etc/prometheus/targets/#$tmp/build/targets/$site/#g" > "$tmp/site-$site.yml"
  run "promtool-2 check config (site Prometheus $site, rendered)" "$T/promtool-2" check config --syntax-only "$tmp/site-$site.yml"
done
# Grafana: the dashboards' PromQL expressions, wrapped in recording rules → promtool validates the syntax
python3 - "$ROOT/monitoring/grafana/dashboards" > "$tmp/dash-rules.yml" <<'PY'
import glob, json, os, sys
print("groups:\n- name: dashboards\n  rules:")
n = 0
for f in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    for p in json.load(open(f))["panels"]:
        for t in p.get("targets", []):
            n += 1
            print("  - record: dashboard:expr_%d:check\n    expr: %s" % (n, json.dumps(t["expr"])))
PY
run "promtool-3 check: dashboard PromQL ($(grep -c 'record:' "$tmp/dash-rules.yml") expressions)" "$T/promtool-3" check rules "$tmp/dash-rules.yml"
run "generated dashboards = build_dashboards.py (no manual edits)" sh -c "cd '$ROOT' && cp -r monitoring/grafana/dashboards '$tmp/dash-before' && python3 monitoring/grafana/build_dashboards.py >/dev/null && diff -r '$tmp/dash-before' monitoring/grafana/dashboards"
echo "[3] Python"
run "correlator: python3 -m unittest correlator/test_rca.py" python3 -m unittest -q "$ROOT/correlator/test_rca.py"
run "registry: python3 -m unittest registry/test_core.py" python3 -m unittest -q "$ROOT/registry/test_core.py"
for f in "$ROOT"/correlator/*.py "$ROOT"/registry/*.py "$ROOT"/monitoring/grafana/*.py "$ROOT"/services/*.py "$ROOT"/infra/*.py "$ROOT"/threats/*/*.py "$ROOT"/siem/*/*.py "$ROOT"/report/figures/*.py; do
  [ -f "$f" ] && run "py_compile ${f#"$ROOT"/}" python3 -m py_compile "$f"
done
echo "[4] shell"
mapfile -t SH < <(find "$ROOT/infra" "$ROOT/threats" "$ROOT/tools" "$ROOT/siem" "$ROOT/evaluation" \
                       "$ROOT/monitoring" "$ROOT/registry" -name '*.sh' | sort)
for f in "${SH[@]}"; do run "bash -n ${f#"$ROOT"/}" bash -n "$f"; done
if command -v shellcheck >/dev/null 2>&1; then SC=(shellcheck); elif command -v uvx >/dev/null 2>&1; then SC=(uvx -q --from shellcheck-py shellcheck); else SC=(); fi
# C.UTF-8 and relative paths: the repo path may contain accents (e.g. "Área de Trabalho") and shellcheck cannot print them under LC_ALL=C
[ ${#SC[@]} -gt 0 ] && run "shellcheck -S warning (${#SH[@]} scripts)" \
  env LC_ALL=C.UTF-8 sh -c 'cd "$1" && shift && "$@"' _ "$ROOT" "${SC[@]}" -S warning "${SH[@]#"$ROOT"/}"
echo "[5] SIEM without Docker"
run "active-response: siem/active-response/test-ar.sh (fake incus + nft in its own namespace)" bash "$ROOT/siem/active-response/test-ar.sh"
run "ossec-ssle.conf WITHOUT enrolled agents: only the defined-agent blocks go, the 2 <command> stay" \
  sh -c ": > '$tmp/none' && test \"\$(python3 '$ROOT/infra/inventory.py' wazuh-manager --host t490 --agents '$tmp/none' 2>/dev/null | grep -c '<name>ssle-')\" = 2"
run "ossec-ssle.conf renders from the inventory (no unresolved placeholders)" \
  sh -c "printf '001 core-responder\n002 avr-ing-01\n003 lis-web-01\n' > '$tmp/agents' && python3 '$ROOT/infra/inventory.py' wazuh-manager --host t490 --agents '$tmp/agents' > /dev/null"
if [ "${SSLE_LOGTEST:-0}" = 1 ]; then
  echo "[6] Wazuh"
  run "wazuh-logtest (siem/tests/run-logtest.sh)" bash "$ROOT/siem/tests/run-logtest.sh"
fi
if [ "${SSLE_IT:-0}" = 1 ]; then
  echo "[7] Wazuh with real agents"
  run "integration (siem/tests/it-agents.sh)" bash "$ROOT/siem/tests/it-agents.sh"
fi
echo
[ $FAIL -eq 0 ] && echo "RESULT: all green ✅" || echo "RESULT: failures ✗"
exit $FAIL
