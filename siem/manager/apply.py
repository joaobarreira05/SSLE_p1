#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Funde o fragmento RENDERIZADO (infra/inventory.py wazuh-manager) no ossec.conf do manager, idempotente:

    python3 siem/manager/apply.py <ossec.conf> <ossec-ssle.renderizado.conf> > ossec.conf.novo

Porquê fundir e não só acrescentar outro <ossec_config> no fim: provado no manager 4.14.10 real
(siem/tests/run-logtest.sh), um 2.º bloco <ruleset> SUBSTITUI as listas por omissão
(etc/lists/amazon/aws-eventnames, …) e o analysisd passa a ignorar as regras que as usam, sem erro
fatal — um SIEM com buracos silenciosos. Por isso:
  · <white_list> → DENTRO do 1.º <global> existente;
  · <list>       → DENTRO do 1.º <ruleset> existente;
  · <command>/<active-response> (secções aditivas) → num <ossec_config> próprio no fim.
Cada inserção fica entre <!-- SSLE:BEGIN --> e <!-- SSLE:END -->: correr outra vez tira a versão anterior
antes de pôr a nova (o resultado de aplicar 2× é igual ao de aplicar 1×).
Falha fechada: sem <global> ou <ruleset> no ossec.conf, sai ≠ 0 e não escreve nada.
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
