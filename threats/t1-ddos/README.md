# Threat 1 — Massive disruption via DoS/DDoS (Availability)

> **Limited** stimulus, inside the lab, with fixed duration (lecture 7). Never external targets.

- **Description/relevance:** `ing-01` is the entry point for all sensors on a site
  (single point of failure for availability). `/work` is a deliberately expensive endpoint.
- **Detection (Prometheus, per instance — [`monitoring/site/rules/anomalies.yml`](../../monitoring/site/rules/anomalies.yml)):**
  1. `TrafficAnomaly` — **robust** z-score (median + IQR of the last hour) of `instance:http_requests:rate1m` > 3;
  2. `ServiceLatencyHigh` — served latency p95 above the **100 ms SLO** (absolute layer, server);
  3. `ClientLatencySLO` / `ClientUpstreamErrors` — the same SLO **as seen by the sensor** (the server does not
     see the queue before serving: 23 ms vs 242 ms in the PoC). The correlator joins the sensor symptom (`opo`)
     to the `ing-01` incident (`avr`) following the inventory graph: 1 incident, root cause `ing-01`.
  Baseline = legitimate sensor telemetry (`sen-0x` → `POST /ingest` every ~5 s).
  Wazuh (profile `full`) — per-origin frequency (rule 110100) and volume (110101).
- **Response (implemented):** `ssle-ratelimit` (nft) — per origin from 110100, and for **every** origin (each with
  its own bucket) from 110101/110110; 300 s timeout. **Planned:** graceful degradation (503) and a 2nd replica.
  The per-origin responses **require** that inter-site traffic does **not** pass through NAT (see post-mortem).
- **Measured PoC:** `bash measure.sh <n> [duration_s=120] [concurrency=20]` — runs [`run.sh`](run.sh), waits for
  recovery and computes MTTD/impact/recovery from the `ALERTS` series and sensor metrics.
- **Results and post-mortem:** [`post-mortem.md`](post-mortem.md) · evidence in [`evidence/`](evidence/)
  ([`results.csv`](evidence/results.csv) + JSON per run).

## Run
```bash
# baseline: let sensors send ≥ 20 min before the 1st run
bash threats/t1-ddos/measure.sh 4 120 20
# distributed variant: 7 clients on each of 3 origins (3 sites), 240 s, separate evidence folder
EVROOT=threats/t1-ddos/evidence-ddos ORIGINS="host site-opo/sen-02 site-lis/web-01" \
  bash threats/t1-ddos/measure.sh 12 240 7
# stimulus only, no measurement:
bash threats/t1-ddos/run.sh 10.10.1.30 120 20
```

Evidence: [`evidence/`](evidence/) (staging runs 1–3, T490 runs 4–9), [`evidence-22nov/`](evidence-22nov/)
(run 10, the live figure of the report) and [`evidence-ddos/`](evidence-ddos/) (3 origins: run 11 before and
run 12 after the fix of the "all origins" response).
