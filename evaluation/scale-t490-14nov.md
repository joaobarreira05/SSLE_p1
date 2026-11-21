# F4 — Lab scale (T490, 14/11/2026)

> 15 Incus containers, 12 monitored elements across 3 sites, 14 Wazuh agents.
> Host: ThinkPad T490, 24 GiB RAM, kernel 7.2.15-arch1-1.

## Prometheus (process-level, via `process_*` and `prometheus_*`)

| Instance | Targets | Series | Ingestion (samples/s) | RSS | CPU (5 min) | TSDB |
|---|---|---|---|---|---|---|
| obs (global) | 8 (3 federate + 5 local) | 4 428 | 147 | 26.0 MiB | 0.7 % | 1.9 MiB |
| site-avr | 9 (5 node + 2 flask + prom + registry) | 7 577 | 502 | 26.5 MiB | 1.6 % | 5.0 MiB |
| site-opo | 8 (4 node + 2 flask + prom + registry) | 6 300 | 417 | 26.8 MiB | 1.4 % | 3.6 MiB |
| site-lis | 5 (3 node + 1 flask + prom) | 4 750 | 315 | 25.9 MiB | 1.4 % | 3.0 MiB |

## Scrape duration

| Target type | Duration (ms) | Samples/scrape |
|---|---|---|
| node_exporter | 208–334 | ~1 331 |
| flask (service/sensor) | 1.9–4.6 | 14–30 |
| registry | 3.4–4.3 | 13 |
| prometheus (self) | 18–25 | 706–816 |
| federation (global ← site) | 1.0–3.0 | 10–19 |

## Rule evaluation

| Instance | p99 duration |
|---|---|
| site (avr/opo/lis) | 8–11 ms |
| global | 0.7 ms |

## Federation (real, 3 sites)

55 total series, 7 971 B text, **1 110 B gzip**. At 4 requests/min per site:
~4.4 kB/min across all sites (confirmed against the extrapolated value from `federation-bytes.sh`).

## Container memory (Incus)

| Container | Memory |
|---|---|
| wazuh | 3.33 GiB |
| obs | 969 MiB |
| prom-01 (avr) | 497 MiB |
| prom-01 (opo) | 481 MiB |
| prom-01 (lis) | 480 MiB |
| mail-01 | 459 MiB |
| ing-01 | 337 MiB |
| sen-01 | 286 MiB |
| sen-02 | 277 MiB |
| reg-01 (avr) | 262 MiB |
| reg-01 (opo) | 262 MiB |
| web-01 | 264 MiB |
| ana-01 | 261 MiB |
| responder | 223 MiB |
| sto-01 | 214 MiB |
| **Total** | **~8.3 GiB** |

Host: 6.6 GiB used / 23 GiB total (16 GiB free).
