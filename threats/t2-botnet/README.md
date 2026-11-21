# Threat 2 — IoT fleet botnet (Integrity → Availability)

> **Benign indicator emulation** (purple-team/atomic style). No malicious code,
> no real control capability. Goal: validate detection → correlation → response.

- **Indicators emulated on a `sen-0x`:**
  1. repeated failed SSH logins (weak credentials) → Wazuh 110200;
  2. "marker" file in a persistence directory (`/etc/cron.d/ssle-marker`) → FIM, Wazuh 110201;
  3. harmless process with periodic *beaconing* (40 × 3 s) to an internal endpoint that only returns 200
     → `OutboundAnomaly` in Prometheus (robust z-score on `node_netstat_Tcp_ActiveOpens`, critical,
     `monitoring/tests/outbound_test.yml`) → correlator (root cause = sensor) → Wazuh **110210** (only with the
     indicator; a root-cause sensor without it triggers 110211, with no quarantine).
- **Response:** `ssle-quarantine` (incus pause / move to `net-quarantine`), block destination (CDB),
  rotate credentials, reimage from golden snapshot.
- **PoC:** `bash run.sh <sen-01> <project>` (runs the 3 indicators, with fixed duration).
- **Meta-correlation (1109xx):** the same `sen-0x` appears as the traffic origin for Threat 1 → "one botnet, two impacts".
