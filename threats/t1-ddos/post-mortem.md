# Post-mortem — Threat 1 (application DoS on `avr/ing-01`) · staging arm64 · 2026-11-06

> *Blameless*, following the plan §4.7 template. Runs measured by [`measure.sh`](measure.sh); raw evidence in
> [`evidence/`](evidence/) (one directory per run + [`results.csv`](evidence/results.csv)).
> **Environment:** `staging` profile (Debian arm64 VM, 6 containers), **no Wazuh** (only in `full` profile, T490) —
> so there is no automatic response here: these runs are the **control group** (detection + impact without
> mitigation) against which the T490 response is measured.

## Description
**Application-layer** DoS (lecture 7): many concurrent requests to the most expensive endpoint of the ingestion
service (`/work`, ~6 ms CPU per request at rest). Classification on the 3 axes from lecture 7: **application (L7)**
layer · **single** origin (the lab host; the distributed variant is for the T490 with `kali-01` + clients on 2–3
sites) · **constant** pattern during a fixed window.

## Relevance
`ing-01` is the **entry point for all sensors** (single point of failure for availability — CIA: **A**).
If ingestion slows down, telemetry from other sites (here, `opo/sen-01`) is delayed or lost, with no sensor
actually faulty — exactly the scenario where an operator without correlation would look in the wrong place.

## Exploitation / PoC
**Limited, fixed-duration** stimulus ([`run.sh`](run.sh)): `CONC` concurrent `curl` cycles against
`http://ing-01:8000/work` for `DUR` seconds, only on the lab's internal bridges. **No escalation.**

## Metrics
| Signal | Series | Why |
|---|---|---|
| Rate (R of RED) | `instance:http_requests:rate1m` | input to robust z-score (`TrafficAnomaly`) |
| Latency (D of RED) | `instance:http_request_duration_seconds:p95_1m` | the 100 ms SLO (`ServiceLatencyHigh`) |
| Legitimate client impact | p95 of `ssle_sensor_upstream_duration_seconds` (`opo` sensor) | what the fleet feels; defines **recovery** |
| Client-side errors | `ssle_sensor_readings_total{result="error"}` | lost readings (5 s timeout) |
| SOC arrival | `incidents.json` from correlator (`ts`, `root_cause`) | end-to-end MTTD |

**Definitions.** **MTTD** = first instant when the rule is `firing` − T0 (stimulus start).
**Recovery** = last instant with sensor p95 > SLO − T1 (stimulus end). Without automatic response,
staging "MTTR" is **the time the system takes to recover on its own after the attack stops** — the baseline
that the T490 automatic response must beat.

## Responses / mitigation
**Staging:** none automatic (control group). **T490 (`full`):** in order of proportionality —
(1) per-origin *rate-limit*; (2) `firewall-drop` with `timeout`; (3) graceful degradation (fast 503 on `/work`);
(4) 2nd replica behind the registry. **Blocker found in this PoC (see "What went wrong"): per-origin responses
are unsafe while NAT exists between sites.**

## PoC post-mortem

### Summary
3 identical runs (120 s × 20 `curl` cycles, ~160 req/s against a baseline of 0.2/s).
`TrafficAnomaly` (robust z-score) detected **3/3** with **MTTD = 81.7 ± 2.9 s** and **0 false positives** over
56 min of observation; the correlator opened **1 incident per run** with the **correct root cause** (`ing-01`)
at **92.9 ± 0.1 s**. The absolute layer (`ServiceLatencyHigh`) **failed 3/3** — and the reason is this PoC's
main lesson.

### Timeline (run 1; the others differ by ≤ 5 s)
| Instant | Event | Source |
|---|---|---|
| **T0** 15:24:10 | stimulus start | `run.log` |
| T0 + 20 s | **impact**: sensor p95 crosses SLO (100 ms) | `p95-sensor.json` |
| T0 + 25 s | **1st signal**: `TrafficAnomaly` *pending* (z ≈ 320) | `alerts-TrafficAnomaly-pending.json` |
| T0 + 85 s | **detection**: `TrafficAnomaly` *firing* (`for: 1m`) → **MTTD** | `alerts-TrafficAnomaly-firing.json` |
| T0 + 93 s | **SOC incident**: correlator, root cause `ssle:pt:avr:mac-m2:ing-01` | `incidents.json` (correlator) |
| T2 | Wazuh alert | — (no Wazuh in staging) |
| T3 | response applied | — (control group) |
| **T1** = T0 + 120 s | stimulus end | `run.log` |
| T1 + 45 s | **recovery**: sensor p95 returns below SLO | `p95-sensor.json` |
| T1 + 65 s | alert resolved | `ALERTS` series |

### Results for all 3 runs
| run | T0 | peak rate (req/s) | 1st signal (s) | **MTTD rule (s)** | **MTTD SOC (s)** | robust z max | mean/std z max | mean/std would fire? | server p95 max (ms) | `ServiceLatencyHigh` | **sensor p95 max (ms)** | recovery after stimulus (s) | lost readings | root cause (SOC) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 15:24:10 | 160.2 | 25 | 85 | 93.0 | 320.0 | 7.6 | **yes** | 23.0 | no | 242.5 | 45 | 0 | `ing-01` |
| 2 | 15:43:15 | 162.2 | 20 | 80 | 92.9 | 323.9 | 3.3 | **no** | 23.2 | no | 242.5 | 45 | 0 | `ing-01` |
| 3 | 15:53:15 | 157.9 | 20 | 80 | 92.9 | 315.4 | 2.8 | **no** | 23.3 | no | 242.5 | 45 | 0 | `ing-01` |
| **mean ± σ** | | 160.1 ± 2.2 | 21.7 ± 2.9 | **81.7 ± 2.9** | **92.9 ± 0.1** | 319.8 ± 4.3 | 4.6 ± 2.6 | 1/3 | 23.2 ± 0.2 | 0/3 | 242.5 | 45.0 | 0 | 3/3 |

Generated by [`analyze.py`](analyze.py) → [`evidence/results.md`](evidence/results.md). **`TrafficAnomaly`
effectiveness: TP = 3 · FP = 0 · FN = 0** (all *firing* intervals between 15:10 and 16:06 fall within a run —
[`evidence/alerts-1510-1606.json`](evidence/alerts-1510-1606.json)). **Measurement precision:** T0/T1 to the
second, queries at 5 s, rule evaluation at 15 s → ±15 s on MTTD. MTTD is dominated by the `for: 1m` (the
1st signal arrives at ~22 s): that is the chosen cost of not alerting on a one-minute spike.

### Detection — what fired, what did not fire, and why
1. **`TrafficAnomaly` (relative) — 3/3.** z ≈ 320 ≫ 3: with a baseline of 0.2 req/s and the minimum
   dispersion of 0.5, this stimulus is not subtle. ✅
2. **Live counterproof — the mean/std version would have detected only run 1.** In run 2 (19 min later)
   and run 3 (29 min later) the previous attack was still inside the 1 h window and had inflated σ:
   z max 3.3 and 2.8, never above 3 for 1 min → **2 false negatives avoided** by median + IQR. This is what
   the [`anomaly_test.yml`](../../monitoring/tests/anomaly_test.yml) test proves in the lab (z 39.6 vs ≈2.0);
   here it is confirmed with real traffic. *(An attacker repeating the attack would gain invisibility with the old version.)*
3. **`ServiceLatencyHigh` (absolute) — 0/3. Blind spot.** The p95 **measured inside the app** never exceeded
   23 ms, but the sensor saw **242.5 ms** (≈ 27× the resting average of 8.8 ms). The server histogram starts
   counting when Flask is already handling the request; the wait **before** that (accepting the connection,
   spawning a thread, contending the GIL with 20 expensive requests) is excluded — and that queue is precisely
   what the client feels.
   **Lesson:** a latency SLO must be measured **on the client side** (blackbox probes or the client's own
   telemetry), not just by server instrumentation.

### Impact
Degradation, not outage: the sensor p95 rose from ~10–46 ms to **242.5 ms** from T0 + 20 s and **no readings
were lost** (sensor timeout is 5 s). Recovery **45 s after the stimulus ends** (the 1 min rate windows).
The 242.5 ms value is the same in all 3 runs because `histogram_quantile` interpolates within the
100–250 ms bucket: p95 resolution is limited by the bucket boundaries.

### Response
None automatic (control group). **What the T490 response must beat:** recovery = end of attack + 45 s;
collateral damage = 0 lost readings.

### Root cause — computed vs actual
The correlator identified `ssle:pt:avr:mac-m2:ing-01` in all 3 runs: **correct regarding the affected element**.
The true cause is the **external load** arriving at `ing-01`, and that origin the system **cannot attribute**
(see 1. below): the correlator answers "*where* it hurts", not "*who* is hitting".

### What went wrong or is fragile
1. **NAT between sites hides the origin.** Inter-bridge traffic passes through Incus *masquerade*
   (`ipv4.nat=true`): `ing-01` sees the `opo` sensor **and** the attacker as `10.10.1.1`. A per-origin response
   (`firewall-drop`, *rate-limit*) **would cut legitimate traffic too**, and Wazuh could not attribute the attack.
   → Disable NAT for **internal** 10.10.0.0/16 traffic (keep it only for Internet). Affects host firewall →
   confirm before changing.
2. **Server-side SLO blind spot** (above, Detection 3).
3. **Before this PoC there was a total false negative:** `ing-01` had no traffic and the counter only appeared on
   the 1st request, so the attack's first sample was also the baseline (z ≈ 0). Fixed with sensor telemetry
   and a pre-initialised counter (commit `be88daa`).
4. **Correlation within site only.** If the `opo` sensor alerted (the client symptom), the correlator would open
   a 2nd incident on `opo` with the wrong root cause (`sen-01`), because it did not follow the `sen-01 → ing-01@avr`
   edge across sites.
5. **Flash crowd vs attack.** With the minimum dispersion of 0.5 req/s, a legitimate fleet expansion (e.g., +10
   sensors) would also trigger. The plan (§4.2) called for requiring **3 signals** (z + p95 + 5xx), but the Flask
   dev server **does not return 5xx under load** (it queues): there is no 3rd signal.
6. **Lab on a single host.** The attacker (the host) and the target share CPU; and the VM was paused between
   15:37 and 15:41 (gap in the series) — **outside** the measured windows, but a reminder that staging is not
   production.

### Future actions
- [x] **Client-side SLO** (08/11, T490): rule `ClientLatencySLO` (sensor p95 > 100 ms for 1 min) and
      `ClientUpstreamErrors` (> 50% of readings fail) in
      [`anomalies.yml`](../../monitoring/site/rules/anomalies.yml), tested from raw histogram to alert
      ([`client_slo_test.yml`](../../monitoring/tests/client_slo_test.yml): reproduces the 242.5 ms). **Retroactive
      analysis** on saved evidence (`analyze.py --offline`): would have fired at **T0 + 80 s in all 3/3**
      runs (vs 0/3 for `ServiceLatencyHigh`); at rest the sensor p95 never exceeded 38.7 ms.
      Note: this is a simulation of `for: 1m` over the 5 s series, **not** a live measurement — measured on the T490.
- [x] **Cross-site correlation** (08/11): the correlator core ([`rca.py`](../../correlator/rca.py)) no longer
      groups by `site` and now performs **greedy set-cover on the graph** (which crosses sites): the `opo` sensor
      symptom joins the `ing-01` incident from `avr` → **1 incident, cause `ing-01`, `cross_site=true`**.
      Bonus: two independent faults now produce two incidents (before, what the best candidate did not explain
      was left out). Tests in [`test_rca.py`](../../correlator/test_rca.py).
- [x] **New risk found while implementing the previous item** (08/11): if the sensor alert arrived at the SOC
      before the server alert, the correlator would emit "root cause = sensor" — and Wazuh rule 110210 treats
      that as a **quarantine** candidate (a legitimate sensor isolated because of a DoS on the server). Fixed with
      a **settle window** (`CORRELATOR_SETTLE=30` s): a new root cause is only emitted when the oldest symptom
      is 30 s old. Cost: +≤ 30 s on SOC MTTD (chosen trade-off: accuracy > speed). The test
      `test_without_settle_the_sensor_would_be_blamed` proves the problem and `test_client_first_never_blames_the_sensor`
      proves the fix.
- [ ] **NAT only for Internet** (preserves origin IP within the lab) — with confirmation.
- [ ] **T490 (`full`):** Wazuh 110100/110101 + proportional response (*rate-limit* → `firewall-drop` with
      `timeout`) and compare recovery against these 45 s; **distributed** variant from `kali-01` and
      clients on 2–3 sites; `limits.cpu=1` on `ing-01`, as in lecture 7.
- [ ] Serve with `gunicorn` (503 responses under saturation) for the 3rd signal to distinguish flash crowd.
