# Grafana as code

> **Purpose:** the SOC dashboards (R5/R6/R7) and the mandatory report figure *"Grafana during a
> PoC"*. Everything comes from Git: datasources from the **inventory**, dashboards from a **Python generator**.

| File | What it is |
|---|---|
| [`build_dashboards.py`](build_dashboards.py) | **source** for the dashboards (writes `dashboards/*.json`) |
| `dashboards/ssle-soc.json` | SOC: Geomap of sites (`site:info:last` + `site:up:ratio`), availability, correlator incidents (open, settling, noise reduction), firing alerts across **all** sites (`site:alerts:firing`), federation cost (R5), dynamic elements (R2) |
| `dashboards/ssle-t1.json` | T1 on `ing-01`: rate (R), robust z-score, **server vs client latency** with SLO, rule state, sensor readings |
| [`providers/ssle.yml`](providers/ssle.yml) | *provider*: without it Grafana ignores the JSONs (was missing before 08/11) |
| `infra/inventory.py grafana` | datasources generated from the inventory: `prom-global`, `prom-<site>` (per-instance drill-down, which the global lacks), `alertmanager` |
| [`it-local.sh`](it-local.sh) | validates provisioning with a **real Grafana 11.6.1** on 127.0.0.1 |
| [`replay-t1.sh`](replay-t1.sh) | replays T1 evidence on the dashboard and captures figures for `report/figures/` |

In the lab, `infra/deploy.sh` (profile `full`) installs Grafana 11.6.1 on `core/obs` from the official apt
repository (signed key, pinned version), listening **only** on the `obs` IP on `net-core` (accessible via SSH
tunnel), with no anonymous access and the admin password **generated** in `build/secrets/grafana-admin.pass`
(outside Git).

**Why per-site datasources:** the global Prometheus only receives aggregates (`site.*:.*`, `up` and active
alerts) — that is what saves bandwidth (R5). Per-instance detail (the rate of `ing-01`, each sensor's p95)
remains on each site's `prom-01`, and Grafana fetches it only when someone opens the drill-down.

## Validation (08/11/2026, real output)

```text
(t490$) bash monitoring/grafana/it-local.sh
[grafana] version 11.6.1 · db ok
  datasources: alertmanager, prom-avr, prom-global, prom-lis, prom-opo
  dashboards: SSLE/ssle-soc, SSLE/ssle-t1
  ssle-soc: 11 panels (geomap, stat, table, timeseries)
  ssle-t1: 6 panels (timeseries)
RESULT: Grafana provisioning error-free ✅
```

In CI (`bash tools/test-all.sh`): the **21 PromQL expressions** from the dashboards pass through `promtool`
(wrapped in recording rules) and the JSONs are verified to be exactly what the generator produces (no manual edits).

## T1 figure — *replay* of staging evidence (06/11, run 1)

`bash monitoring/grafana/replay-t1.sh 1` → `report/figures/t1-replay-run1-{dashboard,latency,rules}.png`

![T1 — dashboard (replay)](../../report/figures/t1-replay-run1-dashboard.png)

How it works: the JSONs saved in `threats/t1-ddos/evidence/run-*/` (Prometheus responses at 5 s) are
converted to OpenMetrics, imported into a local TSDB with `promtool tsdb create-blocks-from openmetrics`,
served by a Prometheus 2.53.5 on 127.0.0.1 and viewed with **the same dashboard** as the lab.

**This is a replay, not a new measurement** — and the report caption must say so:
- the sensor p95 and readings were expression results; here they receive `sen-01` labels (the only
  staging sensor) to match the dashboard queries;
- the robust z-score is recalculated over the saved window (< 1 h of baseline);
- `ClientLatencySLO` did not exist on 06/11, so it does not appear in the rule state;
- the "Served latency — distribution" panel is empty (raw buckets were not saved);
- the replay Prometheus uses `--query.lookback-delta=15s` (backfill brings no staleness markers): the end of
  *firing* appears up to 15 s later than it was.

The definitive figure (with `ClientLatencySLO` and the automatic response) comes from the T490 runs.

## Errors found along the way (and why they matter for the report)

- **State-timeline lies when the series ends:** it extends the last state to the end of the graph, so a
  resolved alert at 15:27 appeared *firing* until 15:31. Replaced with a step series.
- **Two series with the same colour** on the latency panel — exactly the panel that illustrates the T1 lesson.
  Fixed colours per query (server blue, client orange).

## Takeaways

- **Dashboards are code:** generator + versioned JSONs + provider + inventory datasources = Grafana
  rebuilds itself with no clicks.
- **The global sees aggregates; drill-down goes to the site.** The same R5 architecture choice, in Grafana.
- **A replay figure is an illustration, not a measurement** — and the caption must say so.
