#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Leitor da fonte única inventory/sites.yaml e gerador dos artefactos derivados
(alvos do Prometheus, federation, grafo de dependências, listas para o deploy).

Portável: usa PyYAML se existir; senão cai para um mini-parser de YAML em
"block style" (stdlib), suficiente para o nosso sites.yaml. Assim o deploy
corre tanto nesta VM (sem yq/PyYAML) como no T490.
"""
import json, os, sys, argparse, platform

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INV = os.path.join(ROOT, "inventory", "sites.yaml")

NODE_PORT = 9100
FLASK_PORT = 8000
PROM_PORT = 9090
ALERT_PORT = 9093
CORRELATOR_PORT = 9095


# ── parsing ───────────────────────────────────────────────────────────────────
def _scalar(v):
    v = v.strip()
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _split_kv(s):
    i = s.find(":")
    return s[:i].strip(), s[i + 1:].strip()


class _Mini:
    """Mini-parser de YAML block-style (mapas, listas, listas-de-mapas, escalares)."""
    def __init__(self, text):
        self.lines = []
        for line in text.splitlines():
            h = line.find("#")
            if h != -1:
                before = line[:h]
                if before.strip() == "" or before.endswith(" "):
                    line = before
            if line.strip() == "":
                continue
            indent = len(line) - len(line.lstrip(" "))
            self.lines.append([indent, line.strip()])
        self.pos = 0

    def _peek(self):
        if self.pos < len(self.lines):
            return self.lines[self.pos]
        return [None, None]

    def parse(self):
        return self._block(0)

    def _block(self, indent):
        ind, content = self._peek()
        if ind is None or ind < indent:
            return None
        if content.startswith("- "):
            return self._list(indent)
        return self._map(indent)

    def _map(self, indent):
        d = {}
        while True:
            ind, content = self._peek()
            if ind is None or ind < indent or ind > indent or content.startswith("- "):
                break
            key, val = _split_kv(content)
            self.pos += 1
            if val == "":
                nind, _ = self._peek()
                if nind is not None and nind > indent:
                    d[key] = self._block(nind)
                else:
                    d[key] = None
            else:
                d[key] = _scalar(val)
        return d

    def _list(self, indent):
        lst = []
        while True:
            ind, content = self._peek()
            if ind is None or ind != indent or not content.startswith("- "):
                break
            rest = content[2:]
            if ":" in rest:
                # item-mapa: reescreve a linha do traço como entrada de mapa a indent+2
                self.lines[self.pos] = [indent + 2, rest.strip()]
                lst.append(self._map(indent + 2))
            else:
                self.pos += 1
                lst.append(_scalar(rest.strip()))
        return lst


def load_inventory():
    with open(INV, encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # noqa
        return yaml.safe_load(text)
    except Exception:
        return _Mini(text).parse()


# ── modelo ──────────────────────────────────────────────────────────────────
def default_host():
    m = platform.machine().lower()
    return "t490" if m in ("x86_64", "amd64") else "mac-m2"


def net_name(site):
    return "net-core" if site == "core" else "net-%s" % site


def project_name(site):
    return "core" if site == "core" else "site-%s" % site


def dns_domain(site):
    return "%s.ssle.lab" % site


def build(host, staging):
    inv = load_inventory()
    region = inv.get("region", "pt")

    teams = {c: s.get("team") for c, s in inv.get("sites", {}).items()}
    teams["core"] = "soc"

    # que sites entram (depois do filtro staging)?
    used = set()
    for e in inv.get("elements", []):
        if staging and not e.get("staging", False):
            continue
        used.add(e["site"])

    networks = []
    core = inv.get("core", {})
    if "core" in used:
        networks.append({
            "bridge": "net-core", "site": "core",
            "subnet": core.get("subnet"), "gateway": core.get("gateway"),
            "dns": dns_domain("core"),
        })
    for code, s in inv.get("sites", {}).items():
        if code not in used:
            continue
        networks.append({
            "bridge": net_name(code), "site": code,
            "subnet": s.get("subnet"), "gateway": s.get("gateway"),
            "dns": dns_domain(code), "team": s.get("team"),
            "city": s.get("city"), "lat": s.get("lat"), "lon": s.get("lon"),
        })

    elements = []
    for e in inv.get("elements", []):
        if staging and not e.get("staging", False):
            continue
        site = e["site"]
        name = e["name"]
        elements.append({
            "name": name,
            "site": site,
            "role": e.get("role"),
            "ip": e.get("ip"),
            "exporter": e.get("exporter", "node"),
            "deps": e.get("deps") or [],
            "project": project_name(site),
            "network": net_name(site),
            "team": teams.get(site, "soc"),
            "fqdn": "%s.%s" % (name, dns_domain(site)),
            "identity": "ssle:%s:%s:%s:%s" % (region, site, host, name),
            "labels": {
                "region": region, "site": site, "host": host,
                "instance_name": name, "role": e.get("role"),
                "team": teams.get(site, "soc"), "project": project_name(site),
            },
        })
    return {"region": region, "host": host, "networks": networks, "elements": elements}


def _resolve_dep(dep, site, by_key):
    if "@" in dep:
        nm, st = dep.split("@", 1)
    else:
        nm, st = dep, site
    return by_key.get((st, nm))


def graph(model):
    by_key = {(e["site"], e["name"]): e for e in model["elements"]}
    nodes, edges = [], []
    for e in model["elements"]:
        nodes.append({"identity": e["identity"], "site": e["site"],
                      "instance_name": e["name"], "role": e["role"]})
        for d in e["deps"]:
            tgt = _resolve_dep(d, e["site"], by_key)
            if tgt:
                edges.append({"from": e["identity"], "to": tgt["identity"]})
    return {"nodes": nodes, "edges": edges}


def site_targets(model, site):
    """file_sd por site: um bloco por elemento, com todas as labels."""
    node, flask = [], []
    for e in model["elements"]:
        if e["site"] != site:
            continue
        if e["exporter"] in ("node", "flask", "global"):
            node.append({"targets": ["%s:%d" % (e["ip"], NODE_PORT)], "labels": e["labels"]})
        if e["exporter"] == "flask":
            lbl = dict(e["labels"])
            lbl["service"] = e["role"]      # os agregados RED agrupam por service
            flask.append({"targets": ["%s:%d" % (e["ip"], FLASK_PORT)], "labels": lbl})
    return {"node": node, "flask": flask}


def federate_targets(model):
    """alvos do Prometheus global: o prom-01 de cada site."""
    out = []
    for e in model["elements"]:
        if e["role"] == "prometheus":
            out.append({"targets": ["%s:%d" % (e["ip"], PROM_PORT)],
                        "labels": {"site": e["site"], "region": model["region"]}})
    return out


def obs_element(model):
    for e in model["elements"]:
        if e["exporter"] == "global":
            return e
    return None


# ── render ────────────────────────────────────────────────────────────────────
def render(model, out):
    os.makedirs(out, exist_ok=True)
    tdir = os.path.join(out, "targets")
    os.makedirs(tdir, exist_ok=True)

    sites = sorted({e["site"] for e in model["elements"] if e["site"] != "core"})
    for site in sites:
        st = site_targets(model, site)
        sdir = os.path.join(tdir, site)
        os.makedirs(sdir, exist_ok=True)
        with open(os.path.join(sdir, "node.json"), "w") as fh:
            json.dump(st["node"], fh, indent=2)
        with open(os.path.join(sdir, "flask.json"), "w") as fh:
            json.dump(st["flask"], fh, indent=2)

    with open(os.path.join(out, "federate.json"), "w") as fh:
        json.dump(federate_targets(model), fh, indent=2)
    with open(os.path.join(out, "graph.json"), "w") as fh:
        json.dump(graph(model), fh, indent=2)

    # networks.tsv : bridge subnet gateway dns
    with open(os.path.join(out, "networks.tsv"), "w") as fh:
        for n in model["networks"]:
            fh.write("\t".join(str(x) for x in
                     [n["bridge"], n["subnet"], n["gateway"], n["dns"]]) + "\n")

    # containers.tsv : name project network ip exporter role site team deps-csv
    with open(os.path.join(out, "containers.tsv"), "w") as fh:
        for e in model["elements"]:
            fh.write("\t".join(str(x) for x in [
                e["name"], e["project"], e["network"], e["ip"], e["exporter"],
                e["role"], e["site"], e["team"], ",".join(e["deps"]) or "-",
            ]) + "\n")

    obs = obs_element(model)
    with open(os.path.join(out, "obs.tsv"), "w") as fh:
        if obs:
            fh.write("\t".join([obs["name"], obs["project"], obs["ip"]]) + "\n")
    return out


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Leitor do inventário SSLE P1")
    ap.add_argument("cmd", choices=["model", "graph", "render", "federate", "targets"])
    ap.add_argument("--host", default=default_host())
    ap.add_argument("--staging", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "build"))
    ap.add_argument("--site", default=None)
    a = ap.parse_args()

    m = build(a.host, a.staging)
    if a.cmd == "model":
        print(json.dumps(m, indent=2, ensure_ascii=False))
    elif a.cmd == "graph":
        print(json.dumps(graph(m), indent=2, ensure_ascii=False))
    elif a.cmd == "federate":
        print(json.dumps(federate_targets(m), indent=2, ensure_ascii=False))
    elif a.cmd == "targets":
        print(json.dumps(site_targets(m, a.site), indent=2, ensure_ascii=False))
    elif a.cmd == "render":
        print(render(m, a.out))


if __name__ == "__main__":
    main()
