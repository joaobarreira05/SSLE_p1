#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Registry de site (reg-01) — camada HTTP sobre registry/core.py. Porta 5050, como na aula 2.

  POST   /register             {"name","role","ip"}  + "Authorization: Bearer <token>"  → lease de TTL s
  DELETE /register/<name>      (token)
  GET    /sd/node | /sd/services   HTTP SD do Prometheus (só os registados dinamicamente)
  GET    /services/<role>      descoberta round-robin (aula 2)
  GET    /metrics              contagens + site_info{city,lat,lon} (Geomap do Grafana)
  GET    /healthz | /

Configuração (gerada pelo infra/deploy.sh a partir do inventário — fonte única):
  SSLE_REGISTRY_CONFIG      JSON: region, site, subnet, team, host, city, lat, lon, static[]
  SSLE_REGISTRY_TOKEN_FILE  ficheiro (0600) com o token de escrita do site; nunca no Git.
                            Sem token, o registry só aceita leituras (falha fechada).
"""
import json, os, sys
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import SiteRegistry, RegistryError  # noqa: E402

CONF_PATH = os.environ.get("SSLE_REGISTRY_CONFIG", "/opt/registry/registry.json")
TOKEN_FILE = os.environ.get("SSLE_REGISTRY_TOKEN_FILE", "/etc/ssle/registry.token")
TTL_S = int(os.environ.get("SSLE_REGISTRY_TTL", "30"))

with open(CONF_PATH) as fh:
    CONF = json.load(fh)
try:
    with open(TOKEN_FILE) as fh:
        TOKEN = fh.read().strip()
except OSError:
    TOKEN = ""

REG = SiteRegistry(CONF["region"], CONF["site"], CONF["subnet"], CONF.get("team", "?"), CONF["host"],
                   TOKEN, CONF.get("static", []), ttl_s=TTL_S)
app = Flask(__name__)


def _token():
    h = request.headers.get("Authorization", "")
    return h[7:] if h.startswith("Bearer ") else ""


@app.errorhandler(RegistryError)
def _err(e):
    return jsonify({"error": e.reason}), e.status


@app.route("/register", methods=["POST"])
def register():
    res = REG.register(request.get_json(silent=True) or {}, _token())
    return jsonify(res), 200 if res["renewed"] else 201


@app.route("/register/<name>", methods=["DELETE"])
def unregister(name):
    return jsonify({"removed": REG.unregister(name, _token())})


@app.route("/sd/<job>")
def sd(job):
    return jsonify(REG.http_sd(job))


@app.route("/services/<role>")
def discover(role):
    d = REG.discover(role)
    return (jsonify(d), 200) if d else (jsonify({"error": "sem instâncias vivas de '%s'" % role}), 404)


@app.route("/metrics")
def metrics():
    s = REG.snapshot()
    site = 'region="%s",site="%s"' % (CONF["region"], CONF["site"])
    lines = [
        "# HELP site_info Localização do site (Geomap do Grafana). Valor sempre 1.",
        "# TYPE site_info gauge",
        'site_info{%s,city="%s",lat="%s",lon="%s"} 1' % (site, CONF.get("city", ""), CONF.get("lat", ""), CONF.get("lon", "")),
        "# HELP ssle_registry_instances Instâncias conhecidas pelo registry do site.",
        "# TYPE ssle_registry_instances gauge",
        'ssle_registry_instances{%s,kind="static"} %d' % (site, len(s["static"])),
        'ssle_registry_instances{%s,kind="dynamic"} %d' % (site, len(s["dynamic"])),
        "# HELP ssle_registry_registrations_total Registos novos aceites.",
        "# TYPE ssle_registry_registrations_total counter",
        "ssle_registry_registrations_total{%s} %d" % (site, s["counters"]["registrations_total"]),
        "# HELP ssle_registry_renewals_total Renovações de lease (heartbeats) aceites.",
        "# TYPE ssle_registry_renewals_total counter",
        "ssle_registry_renewals_total{%s} %d" % (site, s["counters"]["renewals_total"]),
        "# HELP ssle_registry_rejections_total Pedidos de escrita recusados, por motivo.",
        "# TYPE ssle_registry_rejections_total counter",
    ]
    for reason in ("auth", "name", "role", "site", "ip", "subnet", "identity", "ip-in-use"):
        lines.append('ssle_registry_rejections_total{%s,reason="%s"} %d' % (site, reason, s["rejections"].get(reason, 0)))
    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "site": CONF["site"], "writable": bool(TOKEN)})


@app.route("/")
def index():
    return jsonify(REG.snapshot())


if __name__ == "__main__":
    # no lab escuta na rede do site; nos testes locais BIND=127.0.0.1 (não expor por omissão)
    app.run(host=os.environ.get("BIND", "0.0.0.0"), port=int(os.environ.get("PORT", "5050")), threaded=True)
