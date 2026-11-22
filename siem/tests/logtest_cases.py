#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Runs siem/tests/cases.json against the REAL wazuh-analysisd (logtest socket) and compares
rule/level/decoder/fields with the expected values. Runs INSIDE the manager (run-logtest.sh handles
that), with the Python bundled with Wazuh:

    /var/ossec/framework/python/bin/python3 logtest_cases.py cases.json

Each case is a logtest SESSION (one token): events are sent in order and state
(frequency/timeframe/if_matched_sid) accumulates, as in the real manager. Case format:
  {"name": "...", "log_format": "syslog|json", "location": "...",
   "events": ["line", ...]            # or {"line": "...", "repeat": N}  or list of both
                                      # (a dict can override "log_format"/"location" per event:
                                      #  the meta-correlation mixes correlator JSON with syslog)
   "expect": {"rule": "110001", "level": 10, "decoder": "json", "fields": {"field": "value"}},
   "fires_within": 130}              # optional: the rule must appear in SOME of the first N events
Without "fires_within", "expect" applies to the LAST event. "expect": {"rule": null} = no alert.
"""
import json, socket, struct, sys

SOCK = "/var/ossec/queue/sockets/logtest"


def call(command, parameters):
    msg = json.dumps({"version": 1, "origin": {"name": "ssle-tests", "module": "ssle"},
                      "command": command, "parameters": parameters}).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.send(struct.pack("<I", len(msg)) + msg)
    size = struct.unpack("<I", s.recv(4, socket.MSG_WAITALL))[0]
    reply = json.loads(s.recv(size, socket.MSG_WAITALL))
    s.close()
    if reply.get("error"):
        raise RuntimeError("%s: %s" % (reply["error"], reply.get("message")))
    return reply["data"]


def expand(events):
    """[(line, {log_format/location overrides}), ...] in sending order."""
    out = []
    for e in events if isinstance(events, list) else [events]:
        if isinstance(e, dict):
            over = {k: e[k] for k in ("log_format", "location") if k in e}
            out += [(e["line"], over)] * int(e.get("repeat", 1))
        else:
            out.append((e, {}))
    return out


def get(d, dotted):
    for k in dotted.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def check(out, exp):
    """List of differences between alert 'out' and the expected 'exp' (empty = passed)."""
    rule = get(out, "rule.id") if out else None
    errs = []
    if "rule" in exp and str(exp["rule"] or "") != str(rule or ""):
        errs.append("rule %s (expected %s)" % (rule, exp["rule"]))
    if "level" in exp and get(out, "rule.level") != exp["level"]:
        errs.append("level %s (expected %s)" % (get(out, "rule.level"), exp["level"]))
    if "decoder" in exp and get(out, "decoder.name") != exp["decoder"] and get(out, "decoder.parent") != exp["decoder"]:
        errs.append("decoder %s/%s (expected %s)" % (get(out, "decoder.parent"), get(out, "decoder.name"), exp["decoder"]))
    for k, v in exp.get("fields", {}).items():
        got = get(out, "data." + k)
        if got is None:
            got = get(out, k)
        if str(got) != str(v):
            errs.append("field %s=%r (expected %r)" % (k, got, v))
    return errs


def run_case(c):
    token, outs = None, []
    params = {"location": c.get("location", "stdin"), "log_format": c.get("log_format", "syslog")}
    for line, over in expand(c["events"]):
        p = dict(params, event=line, **over)
        if token:
            p["token"] = token
        data = call("log_processing", p)
        token = data["token"]
        o = data.get("output", {})
        outs.append(o if data.get("alert") or get(o, "rule.id") else o)
    if token:
        try:
            call("remove_session", {"token": token})
        except RuntimeError:
            pass
    exp = c.get("expect", {})
    if "fires_within" in c:
        n = int(c["fires_within"])
        hits = [i for i, o in enumerate(outs[:n]) if str(get(o, "rule.id")) == str(exp.get("rule"))]
        if not hits:
            seen = sorted({str(get(o, "rule.id")) for o in outs})
            return ["rule %s did not fire in %d events (rules seen: %s)" % (exp.get("rule"), n, ",".join(seen))], None
        return check(outs[hits[0]], exp), hits[0] + 1
    return check(outs[-1] if outs else {}, exp), len(outs)


def main(path):
    with open(path, encoding="utf-8") as fh:
        cases = json.load(fh)
    fails = 0
    for c in cases:
        try:
            errs, at = run_case(c)
        except Exception as e:      # noqa: BLE001 — any socket error counts as a failure
            errs, at = ["erro: %s" % e], None
        exp = c.get("expect", {})
        tag = "rule %s" % exp.get("rule") if exp.get("rule") else "no alert"
        where = " (at event %d)" % at if at and "fires_within" in c else ""
        if errs:
            fails += 1
            print("  ✗ %s — %s: %s" % (c["name"], tag, "; ".join(errs)))
        else:
            print("  ✓ %s — %s%s" % (c["name"], tag, where))
    print("\n%d/%d cases passed" % (len(cases) - fails, len(cases)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "cases.json"))
