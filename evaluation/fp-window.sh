#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# False positives over an ATTACK-FREE window of the live lab (T490): everything that fires while no
# PoC is running is, by definition, a false positive.
#
#   bash evaluation/fp-window.sh <from_epoch> <to_epoch>   → evaluation/fp-window-<date>.md
#
# Counts, from the sources:
#   · Prometheus — firing EPISODES (0 → firing transitions of ALERTS) per alert and instance, on the three
#     site Prometheus servers and on the global one (query_range at 15 s);
#   · correlator — incidents opened (incidents.json on core/obs);
#   · Wazuh — alerts of the project's rules (1100xx–1109xx, level ≥ 7; 110105 is level 1 and never an
#     alert) and of any other rule with level ≥ 10, from the manager's alerts.json and daily archives;
#   · active responses executed ("add" lines in active-responses.log of every agent with a response).
# Gaps in the data (e.g. the host suspended) are measured and subtracted from the window.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROM="${1:?usage: fp-window.sh <from_epoch> <to_epoch>}"; TO="${2:?to_epoch}"
OUT="$ROOT/evaluation/fp-window-$(date -d "@$FROM" +%d%b | tr 'A-Z' 'a-z').md"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PROMS="global=http://10.10.0.10:9090 avr=http://10.10.1.10:9090 opo=http://10.10.2.10:9090 lis=http://10.10.3.10:9090"

for p in $PROMS; do
  name="${p%%=*}"; url="${p#*=}"
  curl -sf -G "$url/api/v1/query_range" --data-urlencode 'query=ALERTS{alertstate="firing"}' \
    --data-urlencode "start=$FROM" --data-urlencode "end=$TO" --data-urlencode step=15 > "$T/alerts-$name.json"
  curl -sf -G "$url/api/v1/query_range" --data-urlencode 'query=up{job="prometheus"}' \
    --data-urlencode "start=$FROM" --data-urlencode "end=$TO" --data-urlencode step=15 > "$T/up-$name.json"
done
incus exec obs --project core -- cat /var/log/ssle/incidents.json > "$T/incidents.json" 2>/dev/null </dev/null || : > "$T/incidents.json"
incus exec wazuh --project core -- sh -c 'cat /var/ossec/logs/alerts/alerts.json;
  for f in /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz; do [ -f "$f" ] && zcat "$f"; done;
  for f in /var/ossec/logs/alerts/*/*/ossec-alerts-*.json; do [ -f "$f" ] && cat "$f"; done' \
  > "$T/wazuh.json" 2>/dev/null </dev/null || true
: > "$T/ar.log"
while IFS=$'\t' read -r agent proj inst _ip groups; do
  case ",$groups," in *,role-ingestion,*|*,role-web,*|*,role-responder,*|*,role-mail,*) ;; *) continue ;; esac
  incus exec "$inst" --project "$proj" -- cat /var/ossec/logs/active-responses.log 2>/dev/null </dev/null \
    | sed "s|^|$agent |" >> "$T/ar.log" || true
done < <(python3 "$ROOT/infra/inventory.py" wazuh-agents --host t490)

python3 -I - "$T" "$FROM" "$TO" > "$OUT" <<'PY'
import collections, glob, json, os, re, sys
from datetime import datetime, timezone
T, FROM, TO = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
iso = lambda e: datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# data gaps: holes > 60 s in up{job="prometheus"} of the global (host suspended, Prometheus down)
gaps = 0.0
with open(os.path.join(T, "up-global.json")) as fh:
    res = json.load(fh)["data"]["result"]
ts = sorted({float(t) for s in res for t, _ in s["values"]})
if ts:
    gaps += max(0.0, ts[0] - FROM) + max(0.0, TO - ts[-1])
    gaps += sum(b - a for a, b in zip(ts, ts[1:]) if b - a > 60)
hours = (TO - FROM - gaps) / 3600

episodes = collections.Counter()
for f in sorted(glob.glob(os.path.join(T, "alerts-*.json"))):
    prom = os.path.basename(f)[7:-5]
    with open(f) as fh:
        for s in json.load(fh)["data"]["result"]:
            m = s["metric"]; key = (prom, m.get("alertname"), m.get("instance_name") or m.get("site", "-"))
            prev = None
            for t, _ in s["values"]:
                t = float(t)
                if prev is None or t - prev > 15.5:
                    episodes[key] += 1
                prev = t

incidents = []
with open(os.path.join(T, "incidents.json")) as fh:
    for line in fh:
        try:
            inc = json.loads(line)
            e = datetime.fromisoformat(inc["ts"].replace("Z", "+00:00")).timestamp()
        except (ValueError, KeyError):
            continue
        if FROM <= e <= TO and inc.get("status") != "resolved":
            incidents.append((inc["ts"], inc.get("root_cause"), ",".join(inc.get("alert_names") or [])))

wazuh = collections.Counter(); seen = set()
with open(os.path.join(T, "wazuh.json"), errors="replace") as fh:
    for line in fh:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if a.get("id") in seen:
            continue
        seen.add(a.get("id"))
        e = datetime.strptime(a["timestamp"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        r = a["rule"]; lvl = int(r["level"]); rid = r["id"]
        if not (FROM <= e <= TO):
            continue
        if (rid.startswith("110") and lvl >= 7) or lvl >= 10:
            wazuh[(rid, lvl, a["agent"]["name"], r["description"][:70])] += 1

ar = []   # our scripts log ISO 8601; Wazuh's own firewall-drop logs "YYYY/MM/DD HH:MM:SS … {json}"
with open(os.path.join(T, "ar.log"), errors="replace") as fh:
    for line in fh:
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        try:
            e = datetime.fromisoformat(parts[1]).timestamp()
        except ValueError:
            try:
                e = datetime.strptime(parts[1] + " " + parts[2][:8], "%Y/%m/%d %H:%M:%S") \
                    .replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                continue
        if FROM <= e <= TO and re.search(r'\b(RATELIMIT|QUARANTINE) add\b|"command":\s*"add"', parts[2]):
            ar.append(line.strip())

n_prom = sum(episodes.values()); n_waz = sum(wazuh.values())
print("# False positives over an attack-free window (T490)\n")
print("> Generated by `bash evaluation/fp-window.sh %d %d`. Window %s → %s; data gaps %.0f s;"
      % (FROM, TO, iso(FROM), iso(TO), gaps))
print("> **%.2f h** of observation with the full fleet running, the sensors sending readings and no PoC.\n" % hours)
print("| Source | Events | Per hour |\n|---|---|---|")
print("| Prometheus — firing episodes (3 sites + global) | %d | %.2f |" % (n_prom, n_prom / hours))
print("| Correlator — incidents opened | %d | %.2f |" % (len(incidents), len(incidents) / hours))
print("| Wazuh — SSLE rules (level ≥ 7) and any rule level ≥ 10 | %d | %.2f |" % (n_waz, n_waz / hours))
print("| Active responses executed | %d | %.2f |" % (len(ar), len(ar) / hours))
print("\n## Prometheus episodes\n")
print("\n".join("- `%s` %s on %s: %d" % (k[1], k[2], k[0], v) for k, v in sorted(episodes.items())) or "- none")
print("\n## Correlator incidents\n")
print("\n".join("- %s root cause `%s` (%s)" % i for i in incidents) or "- none")
print("\n## Wazuh alerts\n")
print("\n".join("- %s (level %d) on %s ×%d — %s" % (k[0], k[1], k[2], v, k[3]) for k, v in sorted(wazuh.items())) or "- none")
print("\n## Active responses\n")
print("\n".join("- `%s`" % l for l in ar) or "- none")
PY
cat "$OUT"
