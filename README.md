# SSLE — Project 1: Threat Detection, Monitoring and Prevention

Large-scale infrastructure **as code**: multi-site fleet in Incus containers, monitoring
with **hierarchical** Prometheus (per site + global that federates only aggregates), **root-cause**
correlation and a SIEM (Wazuh) with active response. Everything originates from a single source of truth:
[`inventory/sites.yaml`](inventory/sites.yaml).

## Architecture at a glance

```
            core/obs ─ Prometheus global (federates only aggregates) ─ Alertmanager ─ correlator (RCA) ─► incidents.json ─► Wazuh
               ▲ /federate 30s (saves bandwidth)                         ▲ topological inhibition       │ root cause
     ┌─────────┴─────────┐                                               │                              ▼ active response (core/responder)
   site-avr            site-opo            site-lis
   prom-01             prom-01             prom-01
   ing-01→sto-01       sen-01..N           web-01, mail-01
   (scrape 15s, aggregates, anomaly/liveness rules)
```

Unique identity across Prometheus and Wazuh: `ssle:<region>:<site>:<host>:<instance>` (e.g. `ssle:pt:avr:t490:sto-01`).

## Reproduce in 3 commands

```bash
# 1) reduced profile (low RAM): 2 sites + core, 6 containers
SSLE_PROFILE=staging bash infra/deploy.sh
# 2) inspect the fleet
incus list --all-projects
# 3) run the detection → correlation → root-cause demo
bash infra/demo.sh
```

On the T490 (24 GB): `SSLE_PROFILE=full bash infra/deploy.sh` adds the remaining sites and Wazuh.

## What the demo proves (validated in staging, arm64)

- **Bandwidth-saving federation (R5):** the global sees `site:up:ratio` from each site without federating raw series.
- **Root cause (R6/R7):** stopping `sto-01` generates `ElementDown` (sto-01) **and** `ServiceDegraded` (ing-01, which
  depends on it). The Alertmanager inhibits same-host symptoms; the **correlator** merges the 2 alerts into a **single
  incident** with root cause `sto-01` (`noise_reduction=2.0`) and writes it to `incidents.json` (bridge to Wazuh).

## Repository map

| Folder | Contents |
|---|---|
| `inventory/` | `sites.yaml` — single source of truth |
| `infra/` | `inventory.py` (portable reader), `deploy.sh`, `destroy.sh`, `demo.sh` |
| `monitoring/` | `site/` (prometheus+rules), `global/` (federation, alertmanager, compose), `tests/` (promtool), `grafana/` |
| `correlator/` | webhook → RCA via dependency graph → `incidents.json` + `/metrics` |
| `services/` | Flask lab service (RED + dependency health) |
| `siem/` | rules 1100xx–1109xx, decoders, CDB lists, `agent.conf` per group, active response, logtest tests |
| `threats/` | t1-ddos, t2-botnet, t3-spam (limited PoCs + post-mortem) |
| `evaluation/`, `docs/`, `report/` | measurements, traceability/ADR, report |

## Lab safety
Stimuli are **limited and fixed-duration**, only on internal bridges; the botnet is a **benign emulation** of indicators.
No external targets, no real floods. Responses are proportional, reversible and logged (SOC IPs on the allow-list).
