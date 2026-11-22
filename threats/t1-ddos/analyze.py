#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat 1 (DoS) — analysis of measured runs (stdlib only; runs on the host).

    python3 threats/t1-ddos/analyze.py threats/t1-ddos/evidence/run-*
    python3 threats/t1-ddos/analyze.py --offline threats/t1-ddos/evidence/run-*   # saved evidence only

For each run-N directory reads times.env (T0, T1, TE in epoch), re-queries
Prometheus (the source of truth; reanalysis gives the same result while
retention holds), saves raw JSON and a summary.json, and at the end writes
evidence/results.csv and evidence/results.md (table with mean +/- std dev).

Definitions (same as in the post-mortem):
  MTTD rule    = 1st instant with ALERTS{alertstate="firing"} - T0
  1st signal   = 1st instant with ALERTS{alertstate="pending"} - T0
  impact       = p95 latency as seen by the SENSOR (legitimate client) > SLO
  recovery     = last instant with impact - T1 (end of stimulus)
  MTTD SOC     = ts of the 1st correlator incident - T0
  ClientLatencySLO retro = 1st instant where the SENSOR p95 stays > SLO for 60 s (simulates the
                 for: 1m of the rule on the stored series) - T0; for runs prior to the rule.

  SIEM response = 1st "RATELIMIT add" in the active-response log of the target, per rule and target - T0

--offline: does not talk to Prometheus or Incus; re-reads saved JSONs in run-N/ (queries that
did not exist at the time remain empty) and the "soc" block from the previous summary.json.
--keep: runs that already have a summary.json are only read back into the table (neither re-queried
nor rewritten) — once retention has passed, re-querying would overwrite the evidence with nothing.
"""
import json, os, re, statistics, subprocess, sys, urllib.parse, urllib.request
from datetime import datetime, timezone

PROM_AVR = os.environ.get("PROM_AVR", "http://10.10.1.10:9090")
PROM_OPO = os.environ.get("PROM_OPO", "http://10.10.2.10:9090")
TARGET = os.environ.get("TARGET", "ing-01")
SLO = 0.1          # s — same as ServiceLatencyHigh
STEP = 5
SEL = 'instance_name="%s"' % TARGET
RATE = 'instance:http_requests:rate1m{%s}' % SEL

QUERIES = {
    # name: (prometheus, expression)
    "alerts-TrafficAnomaly-pending": (PROM_AVR, 'ALERTS{alertname="TrafficAnomaly",%s,alertstate="pending"}' % SEL),
    "alerts-TrafficAnomaly-firing": (PROM_AVR, 'ALERTS{alertname="TrafficAnomaly",%s,alertstate="firing"}' % SEL),
    "alerts-ServiceLatencyHigh-pending": (PROM_AVR, 'ALERTS{alertname="ServiceLatencyHigh",%s,alertstate="pending"}' % SEL),
    "alerts-ServiceLatencyHigh-firing": (PROM_AVR, 'ALERTS{alertname="ServiceLatencyHigh",%s,alertstate="firing"}' % SEL),
    "rate1m": (PROM_AVR, RATE),
    "p95-server": (PROM_AVR, 'instance:http_request_duration_seconds:p95_1m{%s}' % SEL),
    # live counterproof: mean/std-dev z (old version) vs robust z (current)
    "z-meanstd": (PROM_AVR, 'abs(%s - avg_over_time(%s[1h])) / clamp_min(stddev_over_time(%s[1h]), 0.5)' % (RATE, RATE, RATE)),
    "z-robust": (PROM_AVR, 'abs(%s - quantile_over_time(0.5, %s[1h])) / clamp_min((quantile_over_time(0.75, %s[1h]) - quantile_over_time(0.25, %s[1h])) / 1.349, 0.5)' % (RATE, RATE, RATE, RATE)),
    # impact on the legitimate client (opo sensor → avr ing-01)
    "p95-sensor": (PROM_OPO, 'histogram_quantile(0.95, sum by (le) (rate(ssle_sensor_upstream_duration_seconds_bucket[1m])))'),
    "sensor-readings": (PROM_OPO, 'sum by (result) (ssle_sensor_readings_total)'),
    # client-side SLO (rule created after the 06/11 staging runs)
    "alerts-ClientLatencySLO-pending": (PROM_OPO, 'ALERTS{alertname="ClientLatencySLO",alertstate="pending"}'),
    "alerts-ClientLatencySLO-firing": (PROM_OPO, 'ALERTS{alertname="ClientLatencySLO",alertstate="firing"}'),
}
OFFLINE = False
KEEP = False
AR_ADD = re.compile(r"^(\S+) ssle-ratelimit\[[^\]]+\]: RATELIMIT add rule=(\d+) (.*?) →")


def prom_range(base, expr, start, end):
    qs = urllib.parse.urlencode({"query": expr, "start": start, "end": end, "step": STEP})
    with urllib.request.urlopen("%s/api/v1/query_range?%s" % (base, qs), timeout=30) as r:
        return json.load(r)


def points(doc):
    """[(ts, value)] across all series (NaN/Inf discarded)."""
    out = []
    for s in doc.get("data", {}).get("result", []):
        for ts, v in s.get("values", []):
            try:
                f = float(v)
            except ValueError:
                continue
            if f == f and f not in (float("inf"), float("-inf")):
                out.append((float(ts), f))
    return sorted(out)


def first(pts, pred=lambda v: True, lo=None):
    for ts, v in pts:
        if (lo is None or ts >= lo) and pred(v):
            return ts
    return None


def last(pts, pred=lambda v: True, lo=None):
    r = None
    for ts, v in pts:
        if (lo is None or ts >= lo) and pred(v):
            r = ts
    return r


def sustained(pts, thr, need_s, lo, hi):
    """1st instant at which v>thr has held for ≥ need_s (simulates the for:)."""
    run_start = None
    for ts, v in pts:
        if ts < lo or ts > hi:
            continue
        if v > thr:
            run_start = ts if run_start is None else run_start
            if ts - run_start >= need_s:
                return ts
        else:
            run_start = None
    return None


def delta(a, b):
    return None if a is None or b is None else round(a - b, 1)


def counter_delta(doc, result, t0, te):
    for s in doc.get("data", {}).get("result", []):
        if s["metric"].get("result") != result:
            continue
        vals = [(float(ts), float(v)) for ts, v in s["values"]]
        before = [v for ts, v in vals if ts <= t0] or [vals[0][1]]
        after = [v for ts, v in vals if ts <= te] or [vals[-1][1]]
        d = after[-1] - before[-1]
        return int(d if d >= 0 else after[-1])   # counter reset → count from 0
    return 0


def incidents(t0, te):
    try:
        raw = subprocess.run(["incus", "exec", "obs", "--project", "core", "--", "cat",
                              "/var/log/ssle/incidents.json"], capture_output=True, text=True,
                             timeout=20, stdin=subprocess.DEVNULL).stdout
    except Exception:
        return []
    out = []
    for line in raw.splitlines():
        try:
            inc = json.loads(line)
            ts = datetime.fromisoformat(inc["ts"]).timestamp()
        except Exception:
            continue
        if t0 <= ts <= te:
            inc["_epoch"] = ts
            out.append(inc)
    return out


def responses(run_dir, t0, te):
    """First "RATELIMIT add" per rule and target in the saved AR log (ar.log), as seconds after T0."""
    out = {}
    try:
        with open(os.path.join(run_dir, "ar.log")) as fh:
            for line in fh:
                m = AR_ADD.match(line.strip())
                if not m:
                    continue
                ts = datetime.fromisoformat(m.group(1)).timestamp()
                key = "%s %s" % (m.group(2), m.group(3))
                if t0 <= ts <= te and key not in out:
                    out[key] = round(ts - t0, 1)
    except OSError:
        pass
    return out


def analyze(run_dir):
    if KEEP and os.path.exists(os.path.join(run_dir, "summary.json")):
        with open(os.path.join(run_dir, "summary.json")) as fh:
            return json.load(fh)
    env = {}
    with open(os.path.join(run_dir, "times.env")) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                env[k] = v
    n, t0, t1, te = int(env["N"]), float(env["T0"]), float(env["T1"]), float(env["TE"])
    start = int(t0) - 120
    docs = {}
    for name, (base, expr) in QUERIES.items():
        path = os.path.join(run_dir, name + ".json")
        if OFFLINE:
            try:
                with open(path) as fh:
                    docs[name] = json.load(fh)
            except OSError:
                docs[name] = {}
            continue
        docs[name] = prom_range(base, expr, start, int(te))
        with open(path, "w") as fh:
            json.dump(docs[name], fh)
    p = {k: points(v) for k, v in docs.items()}

    ta_pend = first(p["alerts-TrafficAnomaly-pending"], lo=t0 - 30)
    ta_fire = first(p["alerts-TrafficAnomaly-firing"], lo=t0 - 30)
    ta_last = last(p["alerts-TrafficAnomaly-firing"], lo=t0 - 30)
    lh_fire = first(p["alerts-ServiceLatencyHigh-firing"], lo=t0 - 30)
    win = lambda k: [v for ts, v in p[k] if t0 <= ts <= t1 + 60]
    zr, zm = win("z-robust"), win("z-meanstd")
    legacy_fire = sustained(p["z-meanstd"], 3, 60, t0, te)        # would the old rule have fired?
    imp_first = first(p["p95-sensor"], lambda v: v > SLO, lo=t0)
    imp_last = last(p["p95-sensor"], lambda v: v > SLO, lo=t0)
    err = counter_delta(docs["sensor-readings"], "error", t0, te)
    ok = counter_delta(docs["sensor-readings"], "ok", t0, te)
    cl_fire = first(p["alerts-ClientLatencySLO-firing"], lo=t0 - 30)
    cl_retro = sustained(p["p95-sensor"], SLO, 60, t0, te)
    if OFFLINE:
        try:
            with open(os.path.join(run_dir, "summary.json")) as fh:
                old = json.load(fh).get("soc", {})
        except (OSError, ValueError):
            old = {}
        soc = {"_epoch": t0 + old["mttd_s"] if old.get("mttd_s") is not None else None,
               "root_cause": old.get("root_cause"), "alert_names": old.get("alerts"),
               "raw_alert_count": old.get("raw_alert_count"), "cross_site": old.get("cross_site")}
    else:
        incs = [i for i in incidents(t0, te) if i.get("status") != "resolved"]
        soc = incs[0] if incs else {}

    summary = {
        "run": n,
        "t0": datetime.fromtimestamp(t0, timezone.utc).isoformat(),
        "stimulus_s": round(t1 - t0), "concurrency": int(env.get("CONC", 0)),
        "origins": env.get("ORIGINS", "host").strip('"'),
        "peak_rate_rps": round(max(win("rate1m") or [0]), 1),
        "server_p95_max_ms": round(1000 * max(win("p95-server") or [0]), 1),
        "TrafficAnomaly": {"first_signal_s": delta(ta_pend, t0), "mttd_s": delta(ta_fire, t0),
                           "resolved_after_stimulus_s": delta(ta_last, t1)},
        "ServiceLatencyHigh": {"mttd_s": delta(lh_fire, t0), "fired": lh_fire is not None},
        "ClientLatencySLO": {"mttd_s": delta(cl_fire, t0), "fired": cl_fire is not None,
                             "retro_mttd_s": delta(cl_retro, t0)},
        "z_max": {"robust": round(max(zr or [0]), 1), "mean_std": round(max(zm or [0]), 1),
                  "mean_std_would_fire": legacy_fire is not None,
                  "mean_std_mttd_s": delta(legacy_fire, t0)},
        "impact": {"sensor_p95_max_ms": round(1000 * max(win("p95-sensor") or [0]), 1),
                   "time_to_impact_s": delta(imp_first, t0),
                   "recovery_after_stimulus_s": delta(imp_last, t1),
                   "sensor_readings_ok": ok, "sensor_readings_lost": err},
        "soc": {"mttd_s": delta(soc.get("_epoch"), t0), "root_cause": soc.get("root_cause"),
                "alerts": soc.get("alert_names"), "raw_alert_count": soc.get("raw_alert_count"),
                "cross_site": soc.get("cross_site")},
        "siem_responses": responses(run_dir, t0, te),
    }
    with open(os.path.join(run_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    return summary


COLS = [  # (header, extractor)
    ("run", lambda s: s["run"]),
    ("t0", lambda s: s["t0"][11:19]),
    ("peak_rate_rps", lambda s: s["peak_rate_rps"]),
    ("1st_signal_s", lambda s: s["TrafficAnomaly"]["first_signal_s"]),
    ("mttd_TrafficAnomaly_s", lambda s: s["TrafficAnomaly"]["mttd_s"]),
    ("mttd_SOC_s", lambda s: s["soc"]["mttd_s"]),
    ("robust_z_max", lambda s: s["z_max"]["robust"]),
    ("mean_std_z_max", lambda s: s["z_max"]["mean_std"]),
    ("mean_std_would_fire", lambda s: s["z_max"]["mean_std_would_fire"]),
    ("server_p95_max_ms", lambda s: s["server_p95_max_ms"]),
    ("ServiceLatencyHigh", lambda s: s["ServiceLatencyHigh"]["fired"]),
    ("mttd_ClientLatencySLO_s", lambda s: s["ClientLatencySLO"]["mttd_s"]),
    ("ClientLatencySLO_retro_s", lambda s: s["ClientLatencySLO"]["retro_mttd_s"]),
    ("sensor_p95_max_ms", lambda s: s["impact"]["sensor_p95_max_ms"]),
    ("time_to_impact_s", lambda s: s["impact"]["time_to_impact_s"]),
    ("recovery_after_stimulus_s", lambda s: s["impact"]["recovery_after_stimulus_s"]),
    ("lost_readings", lambda s: s["impact"]["sensor_readings_lost"]),
    ("root_cause_SOC", lambda s: (s["soc"]["root_cause"] or "—").split(":")[-1]),
]


def main(dirs):
    sums = [analyze(d) for d in sorted(dirs)]
    ev = os.path.dirname(os.path.abspath(sorted(dirs)[0]))
    with open(os.path.join(ev, "results.csv"), "w") as fh:
        fh.write(",".join(c for c, _ in COLS) + "\n")
        for s in sums:
            fh.write(",".join(str(f(s)) for _, f in COLS) + "\n")
    md = ["| " + " | ".join(c for c, _ in COLS) + " |", "|" + "---|" * len(COLS)]
    for s in sums:
        md.append("| " + " | ".join(str(f(s)) for _, f in COLS) + " |")
    row = []
    for c, f in COLS:
        vals = [f(s) for s in sums]
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if c in ("run", "t0"):
            row.append("**mean ± σ**" if c == "run" else "")
        elif len(nums) == len(vals) and nums:
            sd = statistics.stdev(nums) if len(nums) > 1 else 0.0
            row.append("%.1f ± %.1f" % (statistics.mean(nums), sd))
        else:
            row.append("/".join(sorted({str(v) for v in vals})))
    md.append("| " + " | ".join(row) + " |")
    with open(os.path.join(ev, "results.md"), "w") as fh:
        fh.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    args = sys.argv[1:]
    while args and args[0] in ("--offline", "--keep"):
        if args[0] == "--offline":
            OFFLINE = True
        else:
            KEEP = True
        args = args[1:]
    if not args:
        sys.exit("usage: analyze.py [--offline] [--keep] <evidence/run-N> [...]")
    main(args)
