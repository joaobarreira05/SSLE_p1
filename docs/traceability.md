# Traceability matrix (requirement → evidence)

> Status: ✅ proved live (staging and/or T490) · 🧩 code ready (not tested live).

| # | Requirement (slide) | Where | Status |
|---|---|---|---|
| R1 | Scalable service architecture | `inventory/sites.yaml`, `infra/deploy.sh` (fleet per site) | ✅ |
| R2 | Scalable identification/registration (name construction) | convention `ssle:region:site:host:inst` + labels; **site registry** (`registry/`: TTL leases, authenticated writes, per-site/subnet delegation, HTTP SD) — integration proved with real Prometheus 2.53.5 (`registry/it-local.sh`); on T490 lab: `reg-01` running in avr/opo | ✅ |
| R3 | Physical vs logical | labels `host` (t490/mac-m2), `instance_name`, `project`, `role` | ✅ |
| R4 | Geographic location + delegation | Incus projects/networks per site; Wazuh groups/`agent.conf`; Alertmanager routes by `team`; Grafana Geomap with inventory coordinates | ✅ |
| R5 | (Bonus) monitor by location saving bandwidth | Hierarchical Prometheus; **federation of aggregates only** (`site:up:ratio` visible on global); Grafana SOC with **Geomap** (`site:info:last`) and federation cost per site; drill-down goes to the site's `prom-01` (`monitoring/grafana/README.md`) | ✅ · bandwidth **measured**: 99.3–99.7% fewer bytes than without hierarchy (N = 10/25/50; `evaluation/federation-bytes.md`) |
| R6 | Quickly locate the origin | labels on all alerts + **root cause** in `incidents.json` | ✅ |
| R7 | Prometheus (anomalies) + correlation for root cause | site rules (`TrafficAnomaly` robust z + `ServiceLatencyHigh`, `monitoring/tests/anomaly_test.yml`; T2: `OutboundAnomaly` on sensor outbound connections, `monitoring/tests/outbound_test.yml`); Alertmanager (inhibition); **correlator** (RCA via graph); T1 live: 13/13 detected (3 staging + 10 T490), root cause `ing-01` 13/13 (`threats/t1-ddos/evidence*/results.md`); distributed variant with 3 origins on 3 sites (`threats/t1-ddos/evidence-ddos/`); false positives over a 10.1 h attack-free window: 0 from every source (`evaluation/fp-window-22nov.md`) | ✅ |
| R8 | FCAPS detect→diagnose→correlate→resolve→post-mortem | detect/correlate ✅; resolve: responses on T490 (nft ~6 s, quarantine ~140 s, firewall-drop <10 s); post-mortem T1/T2/T3 in report §5.1–5.3 | ✅ |
| R9 | SIEM: 3 incident types + active response | `siem/rules` (1100–1109xx): **25/25 cases** on real `wazuh-analysisd` + integration with real agents (Docker + T490 14 agents); responses validated live on all 3 types; the "all origins" T1 response validated with 3 origins only after a fix (22/11, `siem/tests/README.md`) | ✅ |
| R10 | SIEM: log management | `siem/shared/*/agent.conf` per group (site/role): auth.log, *combined* access log, mail.log, `incidents.json`, FIM, listening-ports command; identity labels on every alert; 14 agents on T490 | ✅ |
| R11 | Per threat: description…post-mortem | T1–T3 with the 6 subtitles from slide 12 in report §5.1–5.3; PoCs validated on T490 (14/11) with versioned evidence | ✅ |
| R12 | Conclusions (why it is not perfect, future work) | report §7: limitations (8 points) + future work (4 points) | ✅ |
| R13 | Report in article/thesis style | `report/latex/main.tex` → `main.pdf` (25 pages, xelatex, English, 15 references) | ✅ |
| R14 | Demo + repositories | this repo + `infra/demo.sh` | ✅ |

**Staging note:** the SIEM (Wazuh, 4–6 GiB) and the `lis`/`opo`-extra sites are excluded from the `staging` profile
to save RAM on the arm64 VM. They run on the T490 with `SSLE_PROFILE=full`.
