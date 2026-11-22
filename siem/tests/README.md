# Validating the SIEM-as-code

## 1. Loading on a real manager (no lab) — `run-logtest.sh`

```bash
bash siem/tests/run-logtest.sh                 # or: SSLE_LOGTEST=1 bash tools/test-all.sh
```

Starts a **disposable** `wazuh/wazuh-manager:4.14.10` (`--network none`, `--memory 1g`), copies
`siem/rules`, `siem/decoders` and `siem/lists`, restarts the manager and **fails** if `wazuh-analysisd` complains.
If `siem/tests/cases.json` exists, it runs it through the logtest socket (`logtest_cases.py`, stateful sessions).

**Why this matters:** a single invalid rule makes the analysisd **reject the entire `local_rules.xml`**
(`CRITICAL: (1220): Error loading the rules`). On the T490 this would mean a SIEM running **without any**
project rule — with no visible error on the dashboard. This is what this validation caught on 08/11/2026 (real output):

```text
wazuh-analysisd: ERROR: Failure to read rule 110002. Field 'status' is static.
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
   → fixed: <status>^resolved$</status> (status, srcip, id, url… are STATIC fields: own tag)

wazuh-analysisd: ERROR: (5107): Syntax error on tag 'root_cause_role' in rule 110110
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
   → fixed: ^ingestion$|^web$ (OS_Regex has no groups ( ) nor classes [ ]); 110301 moved to PCRE2
```

After fixes:

```text
[logtest] loading siem/ on the manager (v4.14.10)
  ✓ rules, decoders and lists loaded with no errors or warnings
wazuh-analysisd: INFO: Total rules enabled: '8468'
```

**Learn:** Wazuh's default rule engine is **OS_Regex** (inherited from OSSEC): `\d`, `\w`, `\S`, `\.`
(any character), `^`, `$` and `|` between whole patterns — **no** `[...]`, `(...)` or *backtracking*. For
anything more: `type="pcre2"` on the `<field>`/`<regex>`/`<match>`.

## 2. Rule cases — `cases.json` (25 cases, with assertions)

`run-logtest.sh` runs each case in a logtest **session** (`frequency`/`if_matched_*` state accumulates
as in the real manager) and compares rule, level, decoder and fields. There are **negative** cases (what
must NOT alert) alongside each positive — without them, a rule that always fires would pass the test.

```text
  ✓ T1: 100 requests from same origin in 10 s — rule 110100 (at event 100)
  ✓ T1: 60 requests from same origin are not enough (no false positive) — rule 110105
  ✓ T2: 8 wrong passwords from same origin (like threats/t2-botnet/run.sh) — rule 110200
  ✓ T2: new listening port (533 → 110202) — rule 110202
  ✓ T3: GTUBE (score 1000) → high confidence — rule 110304
  ✓ T3: 'identified spam' line does not duplicate the alert — no alert
  ✓ meta: compromised sensor AND relay origin → one botnet, two impacts — rule 110900
  ✓ meta: relay from ANOTHER origin does not correlate with the sensor — rule 110302
  …
25/25 cases passed      (since 09/11: + wave with GTUBE only; + T1 victim sensor WITHOUT quarantine → 110211)
```

### Defects caught by the cases (08/11/2026, real manager 4.14.10)

| Rule | Symptom in logtest | Cause | Fix |
|---|---|---|---|
| 110301 (spam) | `spamd` always matched **3501, level 0**, empty fields | (1) decoder looked for `score=… required=…`, which `spamd` does not write; (2) root **3500** in the ruleset matches `^spamd` first, so a top-level rule with `decoded_as` never won | decoder for `result: Y 6 - TESTS …required_score=5.0` and `identified spam (6.2/5.0)`; 110301 becomes a **child of 3501** and uses SpamAssassin's own `Y` verdict |
| 110100/110101 (T1) | 120 requests and **never** fired | 200 responses end at **31108 (level 0)** and the analysisd **discards level-0 events** before storing them for `if_matched_sid` | base rule **110105 at level 1** (stored, but below `log_alert_level`=3: does not fill `alerts.json`) |
| 110100 (T1) | Flask log did not decode | werkzeug writes `[08/Nov/2026 20:00:00]`; the `web-accesslog` decoder wants *combined* format | `SSLE_ACCESS_LOG` in `services/app.py` (combined format, rotated at 10 MiB × 2) |
| 110200 (T2) | pointed to 5710 alone; `run.sh` used `logger` without `-t sshd` | without the tag, `program_name` is `root` and the sshd decoder never sees it | child of composites **5712/5720/5763** (fires at 8th event, proven) + `logger -t sshd` |
| 110202 (T2) | command ran but no rule saw it | 533 only matches the exact alias `netstat listening ports` | `agent.conf` for `role-sensor` with that alias, TCP only and no pid (avoids `check_diff` false positives) |
| 110900 (meta) | counted 2 incidents from the **same** sensor (did not join threats) | — | pattern from **40112**: `if_group ssle_impact` + `if_matched_group ssle_botnet_host` + `same_source_ip`; correlator now sets `srcip` = root cause IP |
| `ossec-ssle.conf` | on **adding** another `<ossec_config>` with `<ruleset>`, `WARNING: (7616): List 'etc/lists/amazon/aws-eventnames' could not be loaded. Rule '80202' will be ignored.` | a 2nd `<ruleset>` **replaces** default lists — SIEM ends up with silent holes | `siem/manager/apply.py` **merges** `white_list`/`list` into existing sections (between markers, idempotent); only `command`/`active-response` go in a separate block |

**Learn:** in a SIEM, "the rule loads" does not mean "the rule fires". Of the 7 defects above, **only 2**
produced load errors (section 1); the other 5 were valid rules that **never** fired — the worst kind of
failure in a detection system, because it is invisible.

## 3. Responses (active-response) — `siem/active-response/test-ar.sh`

No root and no lab: `ssle-quarantine` with a **fake** `incus` on PATH (only records the arguments) and the
real inventory fleet map; `ssle-ratelimit` with **real nft** in its own network namespace (`unshare -rn`:
root only inside, the host firewall is untouched). Real output:

```text
[ssle-quarantine] fake incus + inventory fleet map
  ✓ 110210 sensor sen-01 (opo) → incus pause t490:sen-01 --project site-opo
  ✓ 110900 meta by srcip 10.10.2.51 → incus pause t490:sen-02 --project site-opo
  ✓ root cause in storage (sto-01) is REFUSED (nothing executed)
  ✓ injected name ('sen-01; reboot') does not resolve (nothing executed)
  ✓ execd unresponsive (fail-closed) (nothing executed)
[ssle-ratelimit] real nft in its own network namespace (unshare -rn)
  ✓ no limit: 40/40 connections accepted
  ✓ with limit (5/s, burst 10): 29/40 accepted in 4 s (bucket ceiling: 31) — excess was dropped
  ✓ delete → empty set and 40/40 again
  ✓ 110110 for web-01 on ing-01 → ignored
```

**Why 110110 (T1) rate-limits rather than isolates:** in T1 the root cause is the **victim** (`ing-01`).
Quarantining it would accomplish the DoS on the attacker's behalf. Quarantine (`incus pause`, preserves state
for forensics) is reserved for **sensors** (110210, 110900) — and the script confirms this via the fleet map,
not from the alert payload.

## 4. Integration with real agents — `it-agents.sh` (no Incus lab)

```bash
bash siem/tests/it-agents.sh            # or: SSLE_IT=1 bash tools/test-all.sh   (~8 min, Docker + network)
```

Manager `wazuh/wazuh-manager:4.14.10` + 5 Debian trixie containers with **real `wazuh-agent` 4.14.10**
(`core-obs`, `core-responder`, `avr-ing-01`, `opo-sen-01` and `lis-mail-01` with **real Postfix + `spamd`**
set up by `threats/t3-spam/mail-setup.sh`) on a dedicated Docker network, no ports published on the host.
Each node is installed with **the same scripts as `infra/deploy.sh`** — `siem/manager/configure-manager.sh`
(2 passes: groups before enrolments, responses after, with the `client.keys` IDs) and
`siem/agent/install-agent.sh` — so the test validates the deploy. The responder's `incus` is fake (records
arguments). Real output (09/11/2026):

```text
[it] T2 on sensor (opo-sen-01)
  ✓ SSH brute force (logger -t sshd, …) → 110200 L11 agent=opo-sen-01 labels=host=t490,instance=sen-01,region=pt,role=sensor,site=opo srcip=10.10.99.66 (attempt 2)
  ✓ real-time FIM: persistence marker in /etc/cron.d → 110201 L12 agent=opo-sen-01 … path=/etc/cron.d/ssle-marker
  ✓ new listening port (31337) via agent.conf remote command → 110202 L10 agent=opo-sen-01
[it] T1 on ing-01: white_list first, then the response (the ignore=60 on 110100 is per-rule)
  ✓ DoS pattern from prom-01 (10.10.1.10, on the white_list) → 110100 L10 agent=avr-ing-01 srcip=10.10.1.10
  ✓ white_list: 10.10.1.10 alerted but was NOT rate-limited
  ✓ 100 requests from same origin in 10 s (10.10.9.10) → 110100 L10 agent=avr-ing-01 srcip=10.10.9.10
  ✓ response executed ON ing-01: 10.10.9.10 in nft set inet ssle_rl limited
      2026-11-09T08:29:13+00:00 ssle-ratelimit[ing-01]: RATELIMIT add rule=110100 origin 10.10.9.10 → 20 conn/s (burst 40) on port 8000
[it] T2 → quarantine (correlator on obs → 110210 → ssle-quarantine on responder)
  ✓ correlator incident: sensor sen-01 is root cause → 110210 L12 agent=core-obs srcip=10.10.2.50
  ✓ response executed ON responder: incus pause t490:sen-01 --project site-opo
[it] meta-correlation ACROSS agents (obs + ing-01): one botnet, two impacts
  ✓ sen-02 is root cause (obs) AND DoS origin (ing-01) → 110900 L14 agent=avr-ing-01 srcip=10.10.2.51
  ✓ sen-02 quarantined
[it] T3 on mail-01 (real Postfix + spamd) + firewall-drop
      [t3] 1 spam + 0 relay to 172.19.0.7 → 250×1
  ✓ GTUBE accepted and marked by spamd (score 1000) → 110304 L10 agent=lis-mail-01 | … (score 1002; tests ALL_TRUSTED,GTUBE,MISSING_DATE,…)
      [t3] 10 spam + 0 relay to 172.19.0.7 → 250×10
  ✓ wave: 10 more GTUBE in 2 min → 110300 L10 agent=lis-mail-01
      [t3] 0 spam + 5 relay to 172.19.0.7 → 554×5
  ✓ 5 refused relays (554) from obs → 110302 L10 agent=lis-mail-01 srcip=172.19.0.3
  ✓ firewall-drop executed ON mail-01: 172.19.0.3 blocked
        [t3] 1 spam + 0 relay to 172.19.0.7 → no-connection×1
[it] meta-correlation by relay (obs + mail-01): compromised sensor tries to use the MTA
  ✓ sen-01 is root cause (agent obs, srcip 172.19.0.6) → 110210 L12 agent=core-obs
  ✓ sen-01 is root cause (obs) AND tries relay on mail-01 → 110900 L14 agent=lis-mail-01 srcip=172.19.0.6
  ✓ firewall-drop ON mail-01 also from 110900: 172.19.0.6 blocked
RESULT: SIEM integration OK ✅        (34 checks; automatic unblock, alert 652, arrives 600 s later)
```

### What the integration caught that logtest could not

| Defect | How it was found | Fix |
|---|---|---|
| 110900 **never** correlated across agents | 110210 (agent `obs`) and 110100 (agent `ing-01`) with the same `srcip`, 6 s apart, and nothing | on the manager, composite-rule state is **per-agent**: `<global_frequency/>` on 110900 (proven live) |
| The `ignore="60"` on 110100 is **per-rule**, not per-origin | the 2nd origin within 60 s did not alert (in logtest it did: there the counter drained) | 110101 (total volume) now activates the "all origins" mode of `ssle-ratelimit` |
| The regex stripping responses without agent swallowed the `<command>` blocks | 1st pass: `ERROR: (1303): Invalid command 'ssle-ratelimit'` — `configure-manager.sh` restored the last known-good state | anchored regex at line start + regression test in `tools/test-all.sh` |
| FIM with no directory to watch | `cannot create /etc/cron.d/ssle-marker: Directory nonexistent` | `install-agent.sh` creates `/etc/cron.d`, `/etc/systemd/system`, `/root/.ssh` on sensors |
| Lost lines at startup | rsyslog only creates `auth.log` on the first message and logcollector only reads what arrives after opening | `touch` the logs for each role before starting the agent; test repeats stimulus and says so ("attempt 2") |
| One bot's meta hid **another's** for 5 min | 110900 from `sen-02` (DoS) and, 2 min later, nothing for `sen-01`'s relay | the `ignore="300"` on 110900 is per-rule: removed (quarantine is already deduplicated by `check_keys`) |
| With meta, the bot **kept sending** | the child 110900 alert replaces 110302's → `firewall-drop` from 110302 did not run (`250×1` after meta) | `firewall-drop` (local) also attached to 110900: blocks at target AND isolates at origin |
| Transient warnings treated as errors | `wazuh-remoted: WARNING: (1246): Unable to send file 'merged.mg'` during restart | from `remoted` only `ERROR`/`CRITICAL` count |

**Learn:** logtest tests **one** session from **one** origin. Everything that depends on multiple agents,
real-time (`ignore`, reloads) or the agent's filesystem only surfaces with real agents.

### What only the live lab caught (T490, 22/11/2026)

| Defect | How it was found | Fix |
|---|---|---|
| The "all origins" mode of `ssle-ratelimit` (110101/110110) **never engaged**, in any run since 12/11 | T1 with **3 origins on 3 sites** (`threats/t1-ddos/evidence-ddos/run-11`): `web-01` was never limited; `active-responses.log` has only `abort` and `del` for "all origins", never an `add`. 110100 always puts the attacker's IP in the interval set first, and `0.0.0.0/0` overlaps it: `nft` refuses (`interval overlaps with an existing one`), the script dies under `set -e` **before logging**, and `wazuh-execd` keeps the key as active, answering `abort` from then on. Silent: with one origin the outcome did not change | own set `limited_all` for the "all" mode, both sets `goto` the same `rl` chain (one bucket per packet); every `nft` failure is now logged (`RATELIMIT add FAILED`); regression case in `test-ar.sh` (origin already limited + 110110); re-run with 3 origins (`run-12`): all three limited |
| **110202 false positives** every few minutes on the sensors and on `mail-01`, with no port change | the attack-free window (`evaluation/fp-window.sh`): the agent package's default `ossec.conf` also runs `netstat -tulpn` under the alias `netstat listening ports` (every 360 s); with two commands on one alias, `check_diff` compares one's output with the other's | `install-agent.sh` removes the default block (the only port check is the `role-sensor` one); static check in `it-agents.sh` |

**Learn:** the cases and the agents proved that each rule **fires**; only a run shaped like the real
attack (several origins) and an hours-long window **without** attacks showed what fires wrongly or acts on nothing.

## 5. What can only be tested in the lab (T490, full profile)

- **Real `incus pause`** (the responder's restricted certificate, `infra/deploy.sh` → `siem_responder`) and the
  `delete` at the end of the `timeout` (600 s / 300 s).
- **The Prometheus → correlator → Wazuh chain** with real anomalies (in `it-agents.sh` the correlator line is
  hand-written) and T1 response timings (MTTD/MTTR).
- **`wazuh-install.sh -a -i`** (manager + indexer + dashboard) on the `core/wazuh` container (ubuntu/22.04).
