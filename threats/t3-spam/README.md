# Threat 3 — Junk e-mail (spam) + reputation

> Reuses lecture 8 (Postfix + SpamAssassin) on `lis/mail-01`, which does **not** enter the `staging` profile
> (saves RAM). Everything as code here; runs on the T490 (`SSLE_PROFILE=full`) and is **proved without the lab**
> via `siem/tests/it-agents.sh` (real MTA and Wazuh agent in Docker).

| File | What it does |
|---|---|
| [`mail-setup.sh`](mail-setup.sh) | sets up the MTA inside the container (deploy calls it for the `mail` role): relay only for `mynetworks` (`reject_unauth_destination` → **554**), *content filter* `spamc`/`spamd` (user `debian-spamd`), `anvil` (60 messages/connections per minute per client), **outbound disabled** (`default_transport = error`), Postfix queue for Prometheus (*textfile collector*, `postfix_queue_messages`) |
| [`smtp-poc.sh`](smtp-poc.sh) | SMTP client in **pure bash** (`/dev/tcp`), runs on a sensor without installing anything: N messages with the **GTUBE** (SpamAssassin standard test string, harmless) + M relay attempts to `external.example` |
| [`run.sh`](run.sh) | the lab PoC: `bash threats/t3-spam/run.sh sen-01 site-opo 10.10.3.70 11 5` |

## Detection (Wazuh, validated on real `wazuh-analysisd` and with real agent)

| Signal in `mail.log` | Rule |
|---|---|
| `spamd: result: Y 1000 - GTUBE,…` | 3501 → **110301** (spam) → **110304** (high confidence, score ≥ 15) |
| ≥ 10 marked messages in 2 min | **110300** (wave; counts by group `ssle_spam_msg`, because GTUBE ends at 110304) |
| `NOQUEUE: reject: RCPT … 554 5.7.1 … Relay access denied` × 5 from same origin | 3301 → **110302** → `firewall-drop` (600 s) |
| rejection from an origin in the `ssle-reputation` list | **110310** (CDB) |
| relay origin is a sensor the correlator flagged as root cause | **110900** (meta, cross-agent) → quarantine |

**Why the explicit `reject_unauth_destination`:** Postfix ships with `defer_unauth_destination`, which
responds **450** (try again later). That matches ruleset rule 3303, not the 3301 that 110302 depends on:
the relay would be refused and the SIEM would never know.

## Response and prevention

`firewall-drop` with *timeout* on `mail-01` (temporary origin block), reputation list (CDB + RBL) and
MTA *rate-limit* (`anvil`). Planned: SPF/DKIM/DMARC against spoofing.

## Limitations (anticipated post-mortem)

- **Local path:** the GTUBE proves the chain, not the filter quality. Real spam with untrained Bayes has
  false negatives, and lowering `required_score` trades them for false positives (ham → spam).
- **IP-rotating attacker:** `firewall-drop` is per-origin; against that, reputation and `anvil`.
- **After-queue:** the MTA accepts first and filters afterwards, so spam is already in the queue when detected.
