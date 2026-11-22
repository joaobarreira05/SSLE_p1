# ADR-0001 — Architecture decisions for Project 1

- **T490 = production/demo; Mac (VM arm64) = development/staging.** Not because of ARM (Wazuh/Prometheus
  run on arm64), but because of RAM/disk. Everything is config-as-code, portable between the two.
- **Unique identity** `ssle:region:site:host:instance`, the same labels in Prometheus and Wazuh.
- **Hierarchical Prometheus:** one per site (scrape 15 s, aggregates) + a global that **only federates aggregates**
  (saves bandwidth — R5).
- **Two-level correlation:** Alertmanager (topological inhibition, same host/site) + **correlator**
  (RCA via dependency graph, cross-element). Reduces N alerts to 1 incident with root cause.
- **Prometheus→Wazuh bridge:** the correlator writes `incidents.json`; a Wazuh agent reads the file.
- **Responses** on `core/responder` with an Incus certificate **restricted** to the site projects (least privilege).
- **Staging:** static IPs per NIC + forwarding between host bridges (avoids multi-bridge DNS);
  global stack via **apt** (lighter). Production on the T490 can use **docker-compose** (Prometheus v3 + Grafana).
