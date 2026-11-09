#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
As 3 ADTrees (Attack-Defense Trees, Kordy et al.; notação da aula 5) GERADAS de código — SVG escrito à mão:

    python3 report/figures/build_adtrees.py      # → report/figures/adtree-t{1,2,3}.svg (+ .png com rsvg-convert)

Notação: ataque = elipse vermelha · defesa = retângulo verde · refinamento OR = arestas simples ·
AND = arco a atravessar as arestas dos filhos · contramedida = aresta TRACEJADA para o papel oposto.
Cada defesa diz onde vive no repositório e o seu estado — ✓ testada (logtest/integração/medição) ou
○ planeada —, para a figura não prometer mais do que o lab mostra.
"""
import os, shutil, subprocess
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
NODE_W, LINE_H, VGAP, HGAP, PAD = 170, 14, 46, 14, 20


def A(label, *kids, op="OR", cm=None):
    """Nó de ataque. kids = refinamento (op OR/AND); cm = contramedida (um nó D)."""
    return {"t": "A", "label": label, "kids": list(kids), "op": op, "cm": cm}


def D(label, state="✓", cm=None):
    """Nó de defesa (state ✓ testada / ○ planeada); cm = contra-ataque que a contorna (um nó A)."""
    return {"t": "D", "label": "%s %s" % (state, label), "kids": [], "op": "OR", "cm": cm}


TREES = {
    "t1": ("T1 — DoS/DDoS contra a ingestão (Disponibilidade)",
           A("Indisponibilizar a ingestão (ing-01@avr)",
             A("Esgotar o serviço (camada aplicação)",
               A("Inundar /work de uma só origem",
                 cm=D("Rate-limit por origem: 110100 → ssle-ratelimit (nft)",
                      cm=A("Distribuir por muitas origens (DDoS)",
                           A("Controlar N bots", cm=D("Ver T2 (quarentena dos bots)")),
                           A("Coordenar o envio"), op="AND",
                           cm=D("Limite a TODAS as origens: 110110 (causa raiz) + 110101")))),
               A("Degradar sem derrubar (latência)",
                 cm=D("SLO do cliente: ClientLatencySLO (o servidor mede 23 ms, o cliente 242 ms)"))),
             A("Volume anómalo sustentado",
               cm=D("TrafficAnomaly: z-score robusto (mediana+IQR), MTTD 82 s",
                    cm=A("Subir devagar e envenenar a baseline",
                         cm=D("Janela de baseline ≥ 20 min + limites absolutos", state="○")))),
             A("Derrubar a dependência (sto-01)",
               cm=D("Correlator: causa raiz = sto-01, não o ing-01 (N alertas → 1 incidente)"))),
           ),
    "t2": ("T2 — Botnet sobre a frota IoT (Integridade → Disponibilidade)",
           A("Controlar sensores IoT (sen-0x@opo)",
             A("Acesso inicial",
               A("Força bruta SSH (credenciais fracas)",
                 cm=D("110200 (filha das 5712/5720/5763), 8 falhas → alerta")),
               A("Explorar serviço exposto",
                 cm=D("Superfície mínima: só :8000 e :9100", state="○"))),
             A("Persistência",
               A("cron.d / unidade systemd"),
               A("Chave em /root/.ssh"),
               cm=D("FIM em tempo real (role-sensor) → 110201")),
             A("Comando e controlo",
               A("Beaconing periódico",
                 cm=D("OutboundAnomaly (z robusto) → correlator → 110210 → quarentena (incus pause)",
                      cm=A("C2 lento, em 443, com jitter",
                           cm=D("Meta 110900: causa raiz E origem de impacto", state="✓")))),
               A("Porta nova à escuta (backdoor)",
                 cm=D("533 'netstat listening ports' → 110202"))),
             op="AND"),
           ),
    "t3": ("T3 — Junk e-mail a partir da infraestrutura (Disponibilidade / Confidencialidade)",
           A("Usar a infraestrutura para spam (mail-01@lis)",
             A("Usar o MTA como relay aberto",
               cm=D("Relay só para mynetworks → 3301 → 110302 → firewall-drop",
                    cm=A("Rodar de IP de origem",
                         cm=D("Reputação: CDB ssle-reputation → 110310 (+ RBL)")))),
             A("Inundar caixas internas",
               A("Conteúdo de spam"),
               A("Volume"),
               op="AND",
               cm=D("SpamAssassin: 110301 / 110304 + vaga 110300",
                    cm=A("Evadir o filtro (Bayes poisoning)",
                         cm=D("Bayes treinado + regras locais", state="○")))),
             A("Falsificar o remetente (spoofing)",
               cm=D("SPF / DKIM / DMARC", state="○"))),
           ),
}


def wrap(text, width=24):
    out, cur = [], ""
    for w in text.split():
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur); cur = w
        else:
            cur = (cur + " " + w).strip()
    return out + ([cur] if cur else [])


def height(n):
    return max(2, len(wrap(n["label"]))) * LINE_H + 16


def layout(n):
    """Largura da subárvore (filhos + contramedida ao lado deles)."""
    kids = n["kids"] + ([n["cm"]] if n["cm"] else [])
    for k in kids:
        layout(k)
    n["w"] = max(NODE_W, sum(k["w"] for k in kids) + HGAP * (len(kids) - 1)) if kids else NODE_W


def place(n, x, y, out):
    n["x"], n["y"] = x + n["w"] / 2, y
    kids = n["kids"] + ([n["cm"]] if n["cm"] else [])
    cx = x + (n["w"] - (sum(k["w"] for k in kids) + HGAP * (len(kids) - 1))) / 2
    ny = y + height(n) + VGAP
    for k in kids:
        place(k, cx, ny, out)
        cx += k["w"] + HGAP
    out.append(n)


def node_svg(n):
    lines = wrap(n["label"])
    h = height(n)
    x, y = n["x"], n["y"]
    if n["t"] == "A":
        shape = '<ellipse cx="%.1f" cy="%.1f" rx="%d" ry="%.1f" fill="#fee2e2" stroke="#b91c1c" stroke-width="1.6"/>' % (
            x, y + h / 2, NODE_W / 2, h / 2)
        col = "#7f1d1d"
    else:
        planned = n["label"].startswith("○")
        shape = '<rect x="%.1f" y="%.1f" width="%d" height="%d" rx="3" fill="%s" stroke="#15803d" stroke-width="1.6"%s/>' % (
            x - NODE_W / 2, y, NODE_W, h, "#f0fdf4" if planned else "#dcfce7",
            ' stroke-dasharray="5 3"' if planned else "")
        col = "#14532d"
    t0 = y + h / 2 - (len(lines) - 1) * LINE_H / 2 + 4
    text = "".join('<text x="%.1f" y="%.1f" text-anchor="middle" font-size="11" fill="%s">%s</text>' % (
        x, t0 + i * LINE_H, col, escape(l)) for i, l in enumerate(lines))
    return shape + text


def edges_svg(n):
    out = []
    y0 = n["y"] + height(n)
    for k in n["kids"]:
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#334155" stroke-width="1.3"/>' % (
            n["x"], y0, k["x"], k["y"]))
    if n["op"] == "AND" and len(n["kids"]) > 1:   # arco a atravessar as arestas dos filhos
        r = VGAP * 0.55
        a, b = n["kids"][0], n["kids"][-1]
        def at(k):
            dx, dy = k["x"] - n["x"], k["y"] - y0
            d = (dx * dx + dy * dy) ** 0.5
            return n["x"] + dx / d * r, y0 + dy / d * r
        (x1, y1), (x2, y2) = at(a), at(b)
        out.append('<path d="M %.1f %.1f A %.1f %.1f 0 0 0 %.1f %.1f" fill="none" stroke="#334155" stroke-width="1.6"/>' % (
            x1, y1, r, r, x2, y2))
    if n["cm"]:
        k = n["cm"]
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1.4" stroke-dasharray="4 3"/>' % (
            n["x"], y0, k["x"], k["y"], "#15803d" if k["t"] == "D" else "#b91c1c"))
    for k in n["kids"] + ([n["cm"]] if n["cm"] else []):
        out += edges_svg(k)
    return out


def legend(x, y):
    items = [('<ellipse cx="%d" cy="%d" rx="16" ry="8" fill="#fee2e2" stroke="#b91c1c"/>', "ataque"),
             ('<rect x="%d" y="%d" width="30" height="14" fill="#dcfce7" stroke="#15803d"/>', "defesa ✓ testada"),
             ('<rect x="%d" y="%d" width="30" height="14" fill="#f0fdf4" stroke="#15803d" stroke-dasharray="5 3"/>', "defesa ○ planeada"),
             ('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#15803d" stroke-dasharray="4 3" stroke-width="1.4"/>', "contramedida"),
             (None, "arco = AND · sem arco = OR")]
    out, cx = [], x
    for shape, label in items:
        if shape is None:
            out.append('<text x="%d" y="%d" font-size="11" fill="#334155">%s</text>' % (cx, y + 4, escape(label)))
            continue
        if shape.startswith("<ellipse"):
            out.append(shape % (cx + 16, y))
        elif shape.startswith("<rect"):
            out.append(shape % (cx, y - 7))
        else:
            out.append(shape % (cx, y, cx + 30, y))
        out.append('<text x="%d" y="%d" font-size="11" fill="#334155">%s</text>' % (cx + 38, y + 4, escape(label)))
        cx += 38 + 7 * len(label) + 18
    return out


def build(key):
    title, root = TREES[key]
    layout(root)
    nodes = []
    place(root, PAD, 56, nodes)
    W = int(root["w"] + 2 * PAD)
    H = int(max(n["y"] + height(n) for n in nodes) + 56)
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
             'font-family="DejaVu Sans, Arial, sans-serif">' % (W, H, W, H),
             '<rect width="100%" height="100%" fill="#ffffff"/>',
             '<text x="%d" y="28" font-size="15" font-weight="bold" fill="#0f172a">%s</text>' % (PAD, escape(title))]
    parts += edges_svg(root)
    parts += [node_svg(n) for n in nodes]
    parts += legend(PAD, H - 22)
    parts.append("</svg>")
    path = os.path.join(HERE, "adtree-%s.svg" % key)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts) + "\n")
    png = path[:-4] + ".png"
    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-z", "2", "-o", png, path], check=True)
    return path, W, H


if __name__ == "__main__":
    for k in TREES:
        p, w, h = build(k)
        print("%s (%dx%d)%s" % (os.path.relpath(p), w, h, " + .png" if shutil.which("rsvg-convert") else ""))
