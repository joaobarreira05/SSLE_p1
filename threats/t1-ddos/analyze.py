#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ameaça 1 (DoS) — análise de execuções medidas (só stdlib; corre no host).

    python3 threats/t1-ddos/analyze.py threats/t1-ddos/evidence/run-*
    python3 threats/t1-ddos/analyze.py --offline threats/t1-ddos/evidence/run-*   # só a evidência guardada

Para cada diretório run-N lê times.env (T0, T1, TE em epoch), volta a pedir as
séries ao Prometheus (são a fonte; reanalisar dá o mesmo resultado enquanto
houver retenção), grava o JSON bruto e um summary.json, e no fim escreve
evidence/results.csv e evidence/results.md (tabela com média ± desvio-padrão).

Definições (iguais às do post-mortem):
  MTTD regra   = 1.º instante com ALERTS{alertstate="firing"} − T0
  1.º sinal    = 1.º instante com ALERTS{alertstate="pending"} − T0
  impacto      = p95 da latência vista pelo SENSOR (cliente legítimo) > SLO
  recuperação  = último instante com impacto − T1 (fim do estímulo)
  MTTD SOC     = ts do 1.º incidente do correlator − T0
  ClientLatencySLO retro = 1.º instante em que o p95 do SENSOR fica > SLO durante 60 s (simula o
                 for: 1m da regra sobre a série guardada) − T0; serve para execuções anteriores à regra.

--offline: não fala com o Prometheus nem com o Incus; relê os JSON já guardados em run-N/ (as
consultas que não existiam na altura ficam vazias) e o bloco "soc" do summary.json anterior.
"""
import json, os, statistics, subprocess, sys, urllib.parse, urllib.request
from datetime import datetime, timezone

PROM_AVR = os.environ.get("PROM_AVR", "http://10.10.1.10:9090")
PROM_OPO = os.environ.get("PROM_OPO", "http://10.10.2.10:9090")
TARGET = os.environ.get("TARGET", "ing-01")
SLO = 0.1          # s — o mesmo do ServiceLatencyHigh
STEP = 5           # s — resolução das consultas
SEL = 'instance_name="%s"' % TARGET
RATE = 'instance:http_requests:rate1m{%s}' % SEL

QUERIES = {
    # nome: (prometheus, expressão)
    "alerts-TrafficAnomaly-pending": (PROM_AVR, 'ALERTS{alertname="TrafficAnomaly",%s,alertstate="pending"}' % SEL),
    "alerts-TrafficAnomaly-firing": (PROM_AVR, 'ALERTS{alertname="TrafficAnomaly",%s,alertstate="firing"}' % SEL),
    "alerts-ServiceLatencyHigh-pending": (PROM_AVR, 'ALERTS{alertname="ServiceLatencyHigh",%s,alertstate="pending"}' % SEL),
    "alerts-ServiceLatencyHigh-firing": (PROM_AVR, 'ALERTS{alertname="ServiceLatencyHigh",%s,alertstate="firing"}' % SEL),
    "rate1m": (PROM_AVR, RATE),
    "p95-server": (PROM_AVR, 'instance:http_request_duration_seconds:p95_1m{%s}' % SEL),
    # contraprova ao vivo: z média/desvio-padrão (versão antiga) vs z robusto (atual)
    "z-meanstd": (PROM_AVR, 'abs(%s - avg_over_time(%s[1h])) / clamp_min(stddev_over_time(%s[1h]), 0.5)' % (RATE, RATE, RATE)),
    "z-robust": (PROM_AVR, 'abs(%s - quantile_over_time(0.5, %s[1h])) / clamp_min((quantile_over_time(0.75, %s[1h]) - quantile_over_time(0.25, %s[1h])) / 1.349, 0.5)' % (RATE, RATE, RATE, RATE)),
    # impacto no cliente legítimo (sensor de opo → ing-01 de avr)
    "p95-sensor": (PROM_OPO, 'histogram_quantile(0.95, sum by (le) (rate(ssle_sensor_upstream_duration_seconds_bucket[1m])))'),
    "sensor-readings": (PROM_OPO, 'sum by (result) (ssle_sensor_readings_total)'),
    # SLO do lado do cliente (regra criada depois das execuções de staging de 06/11)
    "alerts-ClientLatencySLO-pending": (PROM_OPO, 'ALERTS{alertname="ClientLatencySLO",alertstate="pending"}'),
    "alerts-ClientLatencySLO-firing": (PROM_OPO, 'ALERTS{alertname="ClientLatencySLO",alertstate="firing"}'),
}
OFFLINE = False


def prom_range(base, expr, start, end):
    qs = urllib.parse.urlencode({"query": expr, "start": start, "end": end, "step": STEP})
    with urllib.request.urlopen("%s/api/v1/query_range?%s" % (base, qs), timeout=30) as r:
        return json.load(r)


def points(doc):
    """[(ts, valor)] de todas as séries (NaN/Inf descartados)."""
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
    """1.º instante em que v>thr se mantém durante ≥ need_s (simula o for:)."""
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
        return int(d if d >= 0 else after[-1])   # reset do contador → conta desde 0
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


def analyze(run_dir):
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
    legacy_fire = sustained(p["z-meanstd"], 3, 60, t0, te)        # a regra antiga teria disparado?
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
    }
    with open(os.path.join(run_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    return summary


COLS = [  # (cabeçalho, extrator)
    ("run", lambda s: s["run"]),
    ("t0", lambda s: s["t0"][11:19]),
    ("taxa_pico_rps", lambda s: s["peak_rate_rps"]),
    ("1o_sinal_s", lambda s: s["TrafficAnomaly"]["first_signal_s"]),
    ("mttd_TrafficAnomaly_s", lambda s: s["TrafficAnomaly"]["mttd_s"]),
    ("mttd_SOC_s", lambda s: s["soc"]["mttd_s"]),
    ("z_robusto_max", lambda s: s["z_max"]["robust"]),
    ("z_media_desvio_max", lambda s: s["z_max"]["mean_std"]),
    ("media_desvio_dispararia", lambda s: s["z_max"]["mean_std_would_fire"]),
    ("p95_servidor_max_ms", lambda s: s["server_p95_max_ms"]),
    ("ServiceLatencyHigh", lambda s: s["ServiceLatencyHigh"]["fired"]),
    ("mttd_ClientLatencySLO_s", lambda s: s["ClientLatencySLO"]["mttd_s"]),
    ("ClientLatencySLO_retro_s", lambda s: s["ClientLatencySLO"]["retro_mttd_s"]),
    ("p95_sensor_max_ms", lambda s: s["impact"]["sensor_p95_max_ms"]),
    ("tempo_ate_impacto_s", lambda s: s["impact"]["time_to_impact_s"]),
    ("recuperacao_apos_estimulo_s", lambda s: s["impact"]["recovery_after_stimulus_s"]),
    ("leituras_perdidas", lambda s: s["impact"]["sensor_readings_lost"]),
    ("causa_raiz_SOC", lambda s: (s["soc"]["root_cause"] or "—").split(":")[-1]),
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
            row.append("**média ± σ**" if c == "run" else "")
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
    if args and args[0] == "--offline":
        OFFLINE, args = True, args[1:]
    if not args:
        sys.exit("uso: analyze.py [--offline] <evidence/run-N> [...]")
    main(args)
