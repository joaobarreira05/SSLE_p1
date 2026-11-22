#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name-topology figure GENERATED from the inventory (single source of truth) — hand-written SVG, no Graphviz:

    python3 report/figures/build_topology.py        # → report/figures/topology.svg (+ .png via chromium)

One column per Incus project/network (core and each site: city, subnet, team), one box per element with
its canonical identity ssle:<region>:<site>:<host>:<inst>, and inventory dependencies as arrows
(the cross-site edge — opo sensor depends on avr ingestion — in orange: the one the correlator follows).
"""
import importlib.util, os, shutil, subprocess, tempfile
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
_spec = importlib.util.spec_from_file_location("inventory", os.path.join(ROOT, "infra", "inventory.py"))
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)

COLW, BOXW, BOXH, GAP, TOP, PAD = 300, 264, 58, 16, 96, 18
ROLE_COLOR = {"observability": "#dbeafe", "siem": "#fee2e2", "responder": "#fde68a", "prometheus": "#e0e7ff",
              "registry": "#ede9fe", "storage": "#dcfce7", "ingestion": "#bbf7d0", "analytics": "#d1fae5",
              "sensor": "#fef3c7", "web": "#cffafe", "mail": "#fce7f3"}


def main():
    m = inv.build("t490", staging=False)
    g = inv.graph(m)
    nets = {n["site"]: n for n in m["networks"]}
    cols = ["core"] + [s for s in ("avr", "opo", "lis") if s in nets]
    pos, parts = {}, []
    rows = max(sum(1 for e in m["elements"] if e["site"] == c) for c in cols)
    W = PAD * 2 + COLW * len(cols)
    H = TOP + rows * (BOXH + GAP) + 90
    parts.append('<rect x="0" y="0" width="%d" height="%d" fill="#ffffff"/>' % (W, H))
    parts.append('<text x="%d" y="28" font-size="17" font-weight="700" fill="#111827">Name topology '
                 '— generated from inventory/sites.yaml (full profile, physical host t490)</text>' % PAD)
    for ci, c in enumerate(cols):
        x0 = PAD + ci * COLW
        n = nets.get(c, {})
        title = "core (SOC)" if c == "core" else "site-%s · %s" % (c, n.get("city", ""))
        sub = "%s · net-%s · %s" % (n.get("subnet", ""), c, "soc" if c == "core" else n.get("team", ""))
        parts.append('<rect x="%d" y="44" width="%d" height="%d" rx="12" fill="#f9fafb" stroke="#d1d5db"/>'
                     % (x0 + 6, COLW - 12, H - 84))
        parts.append('<text x="%d" y="66" font-size="14" font-weight="700" fill="#111827">%s</text>'
                     % (x0 + 18, escape(title)))
        parts.append('<text x="%d" y="84" font-size="11" fill="#4b5563">%s</text>' % (x0 + 18, escape(sub)))
        els = [e for e in m["elements"] if e["site"] == c]
        for ri, e in enumerate(els):
            bx, by = x0 + (COLW - BOXW) // 2, TOP + ri * (BOXH + GAP)
            pos[e["identity"]] = (bx, by)
            parts.append('<rect x="%d" y="%d" width="%d" height="%d" rx="8" fill="%s" stroke="#6b7280"/>'
                         % (bx, by, BOXW, BOXH, ROLE_COLOR.get(e["role"], "#f3f4f6")))
            parts.append('<text x="%d" y="%d" font-size="13" font-weight="700" fill="#111827">%s '
                         '<tspan font-weight="400" fill="#374151">· %s · %s</tspan></text>'
                         % (bx + 10, by + 21, escape(e["name"]), escape(e["role"]), escape(e["ip"])))
            parts.append('<text x="%d" y="%d" font-size="11" font-family="monospace" fill="#1f2937">%s</text>'
                         % (bx + 10, by + 42, escape(e["identity"])))
    for ed in g["edges"]:
        (fx, fy), (tx, ty) = pos[ed["from"]], pos[ed["to"]]
        cross = ed["from"].split(":")[2] != ed["to"].split(":")[2]
        if cross:   # across columns: from the left of the dependent to the right of the dependency
            x1, y1, x2, y2 = fx, fy + BOXH / 2, tx + BOXW, ty + BOXH / 2
            d = "M%d,%d C%d,%d %d,%d %d,%d" % (x1, y1, x1 - 20, y1, x2 + 20, y2, x2 + 8, y2)
            color, dash = "#ea580c", ' stroke-dasharray="6 4"'
        else:       # same column: along the LEFT of the box (the right is kept for cross-site edges)
            x1, y1, x2, y2 = fx, fy + BOXH / 2, tx, ty + BOXH / 2
            bend = 16 + 3 * abs(y1 - y2) / (BOXH + GAP)
            d = "M%d,%d C%d,%d %d,%d %d,%d" % (x1, y1, x1 - bend, y1, x2 - bend, y2, x2 - 8, y2)
            color, dash = "#374151", ""
        parts.append('<path d="%s" fill="none" stroke="%s" stroke-width="2"%s marker-end="url(#a-%s)"/>'
                     % (d, color, dash, "x" if cross else "n"))
    parts.append('<text x="%d" y="%d" font-size="11" fill="#4b5563">Arrow = "depends on" (inventory). '
                 'Dashed orange = cross-site dependency, followed by the correlator (root cause). '
                 'Physical: all containers run on host t490 (host label); logical: Incus project + network '
                 'per site.</text>' % (PAD, H - 14))
    defs = ''.join('<marker id="a-%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                   'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="%s"/></marker>' % (k, c)
                   for k, c in (("n", "#374151"), ("x", "#ea580c")))
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
           'font-family="Inter, DejaVu Sans, Arial, sans-serif"><defs>%s</defs>%s</svg>\n'
           % (W, H, W, H, defs, "".join(parts)))
    out = os.path.join(HERE, "topology.svg")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(os.path.relpath(out, ROOT))
    chrome = shutil.which("chromium") or shutil.which("google-chrome")
    if chrome:
        with tempfile.TemporaryDirectory() as prof:
            png = os.path.join(HERE, "topology.png")
            subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--user-data-dir=" + prof, "--window-size=%d,%d" % (W, H),
                            "--screenshot=" + png, "file://" + out],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(os.path.relpath(png, ROOT))


if __name__ == "__main__":
    main()
