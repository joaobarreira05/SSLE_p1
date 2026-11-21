#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Merges the RENDERED fragment (infra/inventory.py wazuh-manager) into the manager's ossec.conf, idempotent:

    python3 siem/manager/apply.py <ossec.conf> <ossec-ssle.rendered.conf> > ossec.conf.new

Why merge instead of just appending another <ossec_config> at the end: proven on the real manager
4.14.10 (siem/tests/run-logtest.sh), a 2nd <ruleset> block REPLACES the default lists
(etc/lists/amazon/aws-eventnames, ...) and analysisd silently ignores the rules that use them, with
no fatal error — a SIEM with silent holes. Therefore:
  - <white_list> → INSIDE the 1st existing <global>;
  - <list>       → INSIDE the 1st existing <ruleset>;
  - <command>/<active-response> (additive sections) → in their own <ossec_config> at the end.
Each insertion sits between <!-- SSLE:BEGIN --> and <!-- SSLE:END -->: running again removes the
previous version before adding the new one (applying 2x equals applying 1x).
Fail-closed: without <global> or <ruleset> in ossec.conf, exits != 0 and writes nothing.
"""
import re, sys

BEGIN, END = "<!-- SSLE:BEGIN -->", "<!-- SSLE:END -->"


def strip_previous(conf):
    return re.sub(r"[ \t]*%s.*?%s\n?" % (re.escape(BEGIN), re.escape(END)), "", conf, flags=re.S)


def section(frag, tag):
    m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), frag, flags=re.S)
    return m.group(1) if m else ""


def merge(conf, frag):
    frag = re.sub(r"<!--.*?-->", "", frag, flags=re.S)            # comentários do template ficam no Git
    wl = re.findall(r"<white_list>[^<]+</white_list>", section(frag, "global"))
    lists = re.findall(r"<list>[^<]+</list>", section(frag, "ruleset"))
    body = re.sub(r"<global>.*?</global>|<ruleset>.*?</ruleset>", "", section(frag, "ossec_config"), flags=re.S)
    body = "\n".join(l for l in body.splitlines() if l.strip())
    conf = strip_previous(conf)
    for tag, items in (("global", wl), ("ruleset", lists)):
        if "</%s>" % tag not in conf:
            raise SystemExit("ossec.conf sem <%s>: recuso aplicar (falha fechada)" % tag)
        block = "    %s\n%s\n    %s\n" % (BEGIN, "\n".join("    " + i for i in items), END)
        conf = conf.replace("  </%s>" % tag, block + "  </%s>" % tag, 1) if "  </%s>" % tag in conf \
            else conf.replace("</%s>" % tag, block + "</%s>" % tag, 1)
    if not conf.endswith("\n"):
        conf += "\n"
    return conf + "%s\n<ossec_config>\n%s\n</ossec_config>\n%s\n" % (BEGIN, body, END)


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    with open(argv[1], encoding="utf-8") as fh:
        conf = fh.read()
    with open(argv[2], encoding="utf-8") as fh:
        frag = fh.read()
    sys.stdout.write(merge(conf, frag))


if __name__ == "__main__":
    main(sys.argv)
