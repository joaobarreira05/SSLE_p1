#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Figura de ARQUITETURA (fluxos) gerada do inventário — SVG escrito à mão, sem Graphviz:

    python3 report/figures/build_architecture.py     # → report/figures/arquitetura.svg (+ .png com rsvg-convert)

Em cima o SOC (core), em baixo um cartão por site com os elementos do inventário. Quatro fluxos, cada um com a
sua cor: métricas (Prometheus de site → global, SÓ agregados), alertas e incidentes (Alertmanager → correlator →
incidents.json → Wazuh), logs/telemetria dos agentes (→ manager) e respostas (tracejado: rate-limit, quarentena
via o responder e a API do Incus, firewall-drop).
"""
import importlib.util, os, shutil, subprocess
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
_spec = importlib.util.spec_from_file_location("inventory", os.path.join(ROOT, "infra", "inventory.py"))
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)

W, H = 1240, 690
C = {"metric": "#2563eb", "alert": "#ea580c", "log": "#7c3aed", "resp": "#dc2626", "ink": "#0f172a",
     "muted": "#475569", "core": "#eef2ff", "site": "#f8fafc", "box": "#ffffff"}


def box(x, y, w, h, title, lines=(), fill=C["box"], stroke="#94a3b8", bold=True):
    out = ['<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="1.3"/>'
           % (x, y, w, h, fill, stroke)]
    out.append('<text x="%d" y="%d" font-size="12" font-weight="%s" fill="%s">%s</text>'
               % (x + 8, y + 17, "bold" if bold else "normal", C["ink"], escape(title)))
    for i, l in enumerate(lines):
        out.append('<text x="%d" y="%d" font-size="10.5" fill="%s">%s</text>' % (x + 8, y + 33 + 13 * i, C["muted"], escape(l)))
    return out


def arrow(x1, y1, x2, y2, kind, label=None, dx=0, dy=-4, curve=0):
    col = C[kind]
    dash = ' stroke-dasharray="6 4"' if kind == "resp" else ""
    if curve:
        mx, my = (x1 + x2) / 2 + curve, (y1 + y2) / 2
        d = "M %d %d Q %d %d %d %d" % (x1, y1, mx, my, x2, y2)
    else:
        d = "M %d %d L %d %d" % (x1, y1, x2, y2)
    out = ['<path d="%s" fill="none" stroke="%s" stroke-width="1.8"%s marker-end="url(#a-%s)"/>' % (d, col, dash, kind)]
    if label:
        out.append('<text x="%d" y="%d" font-size="10.5" fill="%s" text-anchor="middle">%s</text>'
                   % ((x1 + x2) / 2 + dx + (curve / 2 if curve else 0), (y1 + y2) / 2 + dy, col, escape(label)))
    return out


def main():
    m = inv.build("t490", staging=False)
    nets = {n["site"]: n for n in m["networks"]}
    by_site = {}
    for e in m["elements"]:
        by_site.setdefault(e["site"], []).append(e)
    p = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
         'font-family="DejaVu Sans, Arial, sans-serif">' % (W, H, W, H),
         '<defs>' + "".join('<marker id="a-%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                            'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="%s"/></marker>' % (k, C[k])
                            for k in ("metric", "alert", "log", "resp")) + '</defs>',
         '<rect width="100%" height="100%" fill="#ffffff"/>',
         '<text x="20" y="28" font-size="16" font-weight="bold" fill="%s">Arquitetura e fluxos — SSLE P1 (gerada de inventory/sites.yaml)</text>' % C["ink"]]

    # ── SOC / core ──
    core = nets.get("core", {})
    p += box(20, 44, W - 40, 190, "SOC — core (%s, net-core)" % core.get("subnet", ""), fill=C["core"], stroke="#6366f1")
    p += box(40, 72, 340, 96, "obs  10.10.0.10", ["Prometheus global (só agregados site:*)", "Alertmanager (rotas por team, inibição)",
                                                 "correlator: causa raiz por grafo", "Grafana (SOC + Geomap) · agente Wazuh"])
    p += box(450, 72, 340, 96, "wazuh  10.10.0.30", ["manager: regras 1100xx–1109xx", "meta-correlação 110900 entre agentes",
                                                    "indexer + dashboard (túnel SSH)", "ossec-ssle.conf gerado do inventário"])
    p += box(860, 72, 340, 96, "responder  10.10.0.20", ["agente Wazuh + cliente incus", "certificado RESTRITO aos site-*",
                                                        "ssle-quarantine: incus pause", "(só sensores; não vê o core)"])
    p += arrow(380, 120, 450, 120, "alert")
    p.append('<text x="415" y="185" font-size="10.5" fill="%s" text-anchor="middle">incidentes →</text>' % C["alert"])
    p += arrow(790, 120, 860, 120, "resp")
    p.append('<text x="825" y="185" font-size="10.5" fill="%s" text-anchor="middle">110210/110900 →</text>' % C["resp"])

    # ── faixa do host: todo o tráfego entre bridges passa pelo encaminhamento do T490 ──
    BY, BH = 262, 34
    p.append('<rect x="20" y="%d" width="%d" height="%d" rx="4" fill="#f1f5f9" stroke="#cbd5e1"/>' % (BY, W - 40, BH))
    p.append('<text x="%d" y="%d" font-size="11.5" fill="%s" text-anchor="middle">host t490 — encaminhamento entre as '
             'bridges dos sites e a net-core (sem NAT durante as PoCs) · API do Incus só em 10.10.0.1:8443</text>'
             % (W / 2, BY + 21, C["ink"]))
    # da faixa para o SOC: métricas e alertas → obs, logs → wazuh, e a API do Incus ← responder
    p += arrow(150, BY, 150, 168, "metric")
    p.append('<text x="156" y="%d" font-size="10.5" fill="%s">federation (agregados)</text>' % (BY - 8, C["metric"]))
    p += arrow(300, BY, 300, 168, "alert")
    p.append('<text x="306" y="%d" font-size="10.5" fill="%s">alertas</text>' % (BY - 8, C["alert"]))
    p += arrow(620, BY, 620, 168, "log")
    p.append('<text x="626" y="%d" font-size="10.5" fill="%s">agentes Wazuh (1514/1515)</text>' % (BY - 8, C["log"]))
    p += arrow(1030, 168, 1030, BY, "resp")
    p.append('<text x="1036" y="%d" font-size="10.5" fill="%s">incus pause (API do Incus)</text>' % (BY - 8, C["resp"]))

    # ── sites ──
    sites = [s for s in ("avr", "opo", "lis") if s in by_site]
    top = BY + BH + 46
    cw = (W - 40 - 20 * (len(sites) - 1)) / len(sites)
    ch = 36 + max(len(v) for k, v in by_site.items() if k != "core") * 48
    roles = {"prometheus": "regras: z robusto, SLO cliente, OutboundAnomaly", "registry": "leases TTL + HTTP SD + site_info",
             "ingestion": "RED + log de acesso → ssle-ratelimit (nft)", "sensor": "telemetria → ing-01@avr; FIM, auth.log",
             "storage": "dependência do ing-01 / ana-01", "analytics": "RED", "web": "RED + log de acesso → ssle-ratelimit",
             "mail": "Postfix + spamd → firewall-drop"}
    for i, s in enumerate(sites):
        x = 20 + i * (cw + 20)
        n = nets[s]
        p += box(x, top, cw, ch, "site %s — %s (%s, %s)" % (s, n.get("city", ""), n.get("subnet", ""), n.get("team", "")),
                 fill=C["site"], stroke="#64748b")
        els = sorted(by_site[s], key=lambda e: (e["role"] != "prometheus", e["role"] != "registry", e["name"]))
        for k, e in enumerate(els):
            p += box(x + 12, top + 28 + k * 48, cw - 24, 42, "%s  %s  (%s)" % (e["name"], e["ip"], e["role"]),
                     [roles.get(e["role"], "")], bold=False)
        # do site para a faixa: métricas, alertas, logs (verticais, sem cruzamentos)
        for off, kind in ((-90, "metric"), (-40, "alert"), (60, "log")):
            p += arrow(x + cw / 2 + off, top, x + cw / 2 + off, BY + BH, kind)
        if s == "opo":   # a quarentena desce ao site dos sensores
            p += arrow(x + cw - 50, BY + BH, x + cw - 50, top, "resp")
    # ── legenda ──
    lx, ly = 20, H - 16
    for kind, label in (("metric", "métricas (pull; o global só recebe agregados)"), ("alert", "alertas → correlator → incidente"),
                        ("log", "logs/telemetria dos agentes → SIEM"), ("resp", "resposta (proporcional, com timeout)")):
        p += arrow(lx, ly - 4, lx + 34, ly - 4, kind)
        p.append('<text x="%d" y="%d" font-size="11" fill="%s">%s</text>' % (lx + 40, ly, C["muted"], escape(label)))
        lx += 60 + 6.2 * len(label)
    p.append("</svg>")
    path = os.path.join(HERE, "arquitetura.svg")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p) + "\n")
    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-z", "1.6", "-o", path[:-4] + ".png", path], check=True)
    print(os.path.relpath(path), "(+ .png)" if shutil.which("rsvg-convert") else "")


if __name__ == "__main__":
    main()
