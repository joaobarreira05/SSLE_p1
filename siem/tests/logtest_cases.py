#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Corre os casos de siem/tests/cases.json contra o wazuh-analysisd REAL (socket do logtest) e
compara regra/nível/decoder/campos com o esperado. Corre DENTRO do manager (o run-logtest.sh trata
disso), com o Python que vem com o Wazuh:

    /var/ossec/framework/python/bin/python3 logtest_cases.py cases.json

Cada caso é uma SESSÃO do logtest (um token): os eventos são enviados por ordem e o estado
(frequency/timeframe/if_matched_sid) acumula-se, como no manager a sério. Formato de um caso:
  {"name": "...", "log_format": "syslog|json", "location": "...",
   "events": ["linha", ...]           # ou {"line": "...", "repeat": N}  ou lista dos dois
   "expect": {"rule": "110001", "level": 10, "decoder": "json", "fields": {"campo": "valor"}},
   "fires_within": 130}              # opcional: a regra tem de aparecer em ALGUM dos primeiros N eventos
Sem "fires_within", o "expect" aplica-se ao ÚLTIMO evento. "expect": {"rule": null} = não alerta.
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
    out = []
    for e in events if isinstance(events, list) else [events]:
        if isinstance(e, dict):
            out += [e["line"]] * int(e.get("repeat", 1))
        else:
            out.append(e)
    return out


def get(d, dotted):
    for k in dotted.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def check(out, exp):
    """Lista de diferenças entre o alerta 'out' e o esperado 'exp' (vazia = passou)."""
    rule = get(out, "rule.id") if out else None
    errs = []
    if "rule" in exp and str(exp["rule"] or "") != str(rule or ""):
        errs.append("regra %s (esperada %s)" % (rule, exp["rule"]))
    if "level" in exp and get(out, "rule.level") != exp["level"]:
        errs.append("nível %s (esperado %s)" % (get(out, "rule.level"), exp["level"]))
    if "decoder" in exp and get(out, "decoder.name") != exp["decoder"] and get(out, "decoder.parent") != exp["decoder"]:
        errs.append("decoder %s/%s (esperado %s)" % (get(out, "decoder.parent"), get(out, "decoder.name"), exp["decoder"]))
    for k, v in exp.get("fields", {}).items():
        got = get(out, "data." + k)
        if got is None:
            got = get(out, k)
        if str(got) != str(v):
            errs.append("campo %s=%r (esperado %r)" % (k, got, v))
    return errs


def run_case(c):
    token, outs = None, []
    params = {"location": c.get("location", "stdin"), "log_format": c.get("log_format", "syslog")}
    for line in expand(c["events"]):
        p = dict(params, event=line)
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
            return ["a regra %s não disparou em %d eventos (regras vistas: %s)" % (exp.get("rule"), n, ",".join(seen))], None
        return check(outs[hits[0]], exp), hits[0] + 1
    return check(outs[-1] if outs else {}, exp), len(outs)


def main(path):
    with open(path, encoding="utf-8") as fh:
        cases = json.load(fh)
    fails = 0
    for c in cases:
        try:
            errs, at = run_case(c)
        except Exception as e:      # noqa: BLE001 — qualquer erro do socket conta como falha
            errs, at = ["erro: %s" % e], None
        exp = c.get("expect", {})
        tag = "regra %s" % exp.get("rule") if exp.get("rule") else "sem alerta"
        where = " (no evento %d)" % at if at and "fires_within" in c else ""
        if errs:
            fails += 1
            print("  ✗ %s — %s: %s" % (c["name"], tag, "; ".join(errs)))
        else:
            print("  ✓ %s — %s%s" % (c["name"], tag, where))
    print("\n%d/%d casos passaram" % (len(cases) - fails, len(cases)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "cases.json"))
