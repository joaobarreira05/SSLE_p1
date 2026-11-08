#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboards do Grafana como CÓDIGO: este ficheiro é a fonte; os JSON em dashboards/ são gerados
(e versionados, porque é o que o Grafana carrega pelo provider em providers/ssle.yml).

    python3 monitoring/grafana/build_dashboards.py      # reescreve dashboards/*.json

Datasources (uids estáveis, geradas do inventário por `infra/inventory.py grafana`):
  prom-global (só agregados federados) · prom-<site> (drill-down por instância) · alertmanager

  ssle-soc  — visão do SOC: mapa dos sites (Geomap de site:info:last), disponibilidade, incidentes do
              correlator, alertas a disparar em todos os sites, custo da federation (R5), registry (R2)
  ssle-t1   — Ameaça 1 (DoS) no ing-01: taxa (R), latência servidor vs CLIENTE com o SLO, estado das
              regras (pending/firing), leituras dos sensores. É a figura "Grafana durante uma PoC".
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "dashboards")
MIXED = {"type": "datasource", "uid": "-- Mixed --"}


def ds(uid):
    return {"type": "prometheus", "uid": uid}


def q(uid, expr, legend="", ref="A", instant=False, table=False):
    t = {"refId": ref, "datasource": ds(uid), "expr": expr, "legendFormat": legend or "__auto",
         "range": not instant, "instant": instant}
    if table:
        t["format"] = "table"
    return t


def thr(*steps):
    """thr(("green", None), ("red", 0.1)) → thresholds absolutos."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


class Board:
    def __init__(self, uid, title, description, tags, refresh="10s", span="now-30m"):
        self.d = {"uid": uid, "title": title, "description": description, "tags": tags,
                  "editable": False, "schemaVersion": 39, "version": 1, "refresh": refresh,
                  "time": {"from": span, "to": "now"}, "timezone": "browser",
                  "annotations": {"list": []}, "templating": {"list": []}, "panels": []}

    def add(self, ptype, title, x, y, w, h, targets, datasource=None, unit=None, desc="",
            thresholds=None, options=None, custom=None, transformations=None, mappings=None,
            overrides=None, minmax=None):
        fd = {"custom": custom or {}}
        if unit:
            fd["unit"] = unit
        if thresholds:
            fd["thresholds"] = thresholds
            fd["color"] = {"mode": "thresholds"}
        if mappings:
            fd["mappings"] = mappings
        if minmax:
            for k, v in zip(("min", "max"), minmax):
                if v is not None:
                    fd[k] = v
        uids = {t["datasource"]["uid"] for t in targets}
        p = {"id": len(self.d["panels"]) + 1, "type": ptype, "title": title, "description": desc,
             "gridPos": {"x": x, "y": y, "w": w, "h": h},
             "datasource": datasource or (ds(uids.pop()) if len(uids) == 1 else MIXED),
             "targets": targets, "fieldConfig": {"defaults": fd, "overrides": overrides or []},
             "options": options or {}}
        if transformations:
            p["transformations"] = transformations
        self.d["panels"].append(p)
        return p

    def write(self):
        path = os.path.join(OUT, self.d["uid"] + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.d, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        return path


LEGEND = {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
          "tooltip": {"mode": "multi", "sort": "desc"}}
STAT = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        "colorMode": "background", "graphMode": "none", "textMode": "value_and_name",
        "justifyMode": "auto", "orientation": "auto"}


def soc():
    b = Board("ssle-soc", "SSLE — SOC (visão global)",
              "Vista do SOC no core/obs: só agregados federados dos sites (R5) + incidentes do correlator.",
              ["ssle", "soc", "fcaps"])
    G = "prom-global"
    b.add("geomap", "Sites — disponibilidade", 0, 0, 10, 11,
          [q(G, "site:info:last", ref="A", instant=True, table=True),
           q(G, "site:up:ratio", ref="B", instant=True, table=True)],
          unit="percentunit", minmax=(0, 1),
          thresholds=thr(("red", None), ("orange", 0.5), ("green", 0.99)),
          desc="Posição de cada site (lat/lon do inventário, servida pelo reg-01 como site_info) e a "
               "fração de elementos 'up'. Sem Internet no lab o mapa de fundo não carrega; os marcadores sim.",
          transformations=[
              {"id": "joinByField", "options": {"byField": "site", "mode": "outer"}},
              {"id": "convertFieldType", "options": {"fields": {}, "conversions": [
                  {"targetField": "lat", "destinationType": "number"},
                  {"targetField": "lon", "destinationType": "number"}]}}],
          options={"view": {"id": "coords", "lat": 39.9, "lon": -8.6, "zoom": 6.4},
                   "controls": {"showZoom": True, "mouseWheelZoom": True},
                   "basemap": {"type": "default", "name": "Basemap"},
                   "tooltip": {"mode": "details"},
                   "layers": [{"type": "markers", "name": "Sites", "tooltip": True,
                               "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
                               "config": {"showLegend": True, "style": {
                                   "size": {"fixed": 14}, "color": {"field": "Value #B", "fixed": "green"},
                                   "text": {"mode": "field", "field": "site", "fixed": ""},
                                   "textConfig": {"fontSize": 13, "offsetY": -18, "textAlign": "center",
                                                  "textBaseline": "middle"}}}}]})
    b.add("stat", "Disponibilidade por site", 10, 0, 8, 5, [q(G, "site:up:ratio", "{{site}}")],
          unit="percentunit", thresholds=thr(("red", None), ("orange", 0.5), ("green", 0.99)), options=STAT,
          desc="site:up:ratio — média de up{job=\"node\"} no site (recording rule federada).")
    b.add("stat", "Incidentes abertos", 18, 0, 3, 5, [q(G, "correlator_open_incidents", "abertos")],
          thresholds=thr(("green", None), ("red", 1)), options=STAT)
    b.add("stat", "À espera (settle)", 21, 0, 3, 5, [q(G, "correlator_pending_incidents", "pendentes")],
          thresholds=thr(("green", None), ("orange", 1)), options=STAT,
          desc="Incidentes com causa raiz nova à espera da janela de estabilização (CORRELATOR_SETTLE).")
    b.add("stat", "Incidentes desde o arranque", 10, 5, 4, 6, [q(G, "correlator_incidents_total", "total")],
          thresholds=thr(("blue", None)), options=STAT)
    b.add("stat", "Redução de ruído (último)", 14, 5, 4, 6,
          [q(G, "correlator_last_noise_reduction", "alertas → 1 incidente")],
          thresholds=thr(("blue", None)), options=STAT,
          desc="Alertas em bruto que o correlator juntou no último incidente (N alertas → 1).")
    b.add("stat", "Elementos registados dinamicamente", 18, 5, 6, 6,
          [q(G, 'sum by (site) (site:registry_instances:sum{kind="dynamic"})', "{{site}}")],
          thresholds=thr(("blue", None)), options=STAT,
          desc="R2: elementos que entraram pelo reg-01 do site (fora do inventário).")
    b.add("table", "Alertas a disparar (todos os sites)", 0, 11, 12, 9,
          [q(G, "site:alerts:firing", instant=True, table=True)],
          desc="ALERTS{alertstate=\"firing\"} federado dos Prometheus de site (renomeado no global).",
          transformations=[{"id": "organize", "options": {
              "excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True,
                                "job": True, "instance": True, "level": True, "region": True,
                                "host": True, "project": True},
              "indexByName": {"site": 0, "alertname": 1, "instance_name": 2, "severity": 3, "kind": 4}}}])
    b.add("timeseries", "Elementos em baixo por site", 12, 11, 12, 9, [q(G, "site:down:count", "{{site}}")],
          custom={"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10}, options=LEGEND)
    b.add("timeseries", "Federation — amostras por recolha, por site (R5)", 0, 20, 12, 8,
          [q(G, 'scrape_samples_scraped{job="federate"}', "{{site}}")],
          custom={"drawStyle": "line", "lineWidth": 2}, options=LEGEND,
          desc="Quantas séries o global puxa de cada site a cada 30 s: só agregados (site.*:.*), up e "
               "alertas ativos — não as séries em bruto. É o custo de banda da monitorização por localização.")
    b.add("timeseries", "Pedidos por serviço e site (agregado)", 12, 20, 12, 8,
          [q(G, "site_service:http_requests:rate5m", "{{site}} / {{service}}")],
          unit="reqps", custom={"drawStyle": "line", "lineWidth": 2}, options=LEGEND)
    return b.write()


def t1():
    b = Board("ssle-t1", "SSLE — T1 DoS (ing-01)",
              "Ameaça 1: taxa no ing-01 (avr), latência vista pelo servidor e pelo CLIENTE (sensores de opo) "
              "contra o SLO de 100 ms, e o estado das regras. Ver threats/t1-ddos/post-mortem.md.",
              ["ssle", "t1", "dos"], refresh="5s", span="now-15m")
    A, O = "prom-avr", "prom-opo"
    ing = 'instance_name="ing-01"'
    b.add("timeseries", "Taxa de pedidos no ing-01 (R de RED)", 0, 0, 12, 8,
          [q(A, "instance:http_requests:rate1m{%s}" % ing, "ing-01 (pedidos/s)")],
          unit="reqps", custom={"drawStyle": "line", "lineWidth": 2, "fillOpacity": 15}, options=LEGEND,
          desc="Entrada do TrafficAnomaly (z-score robusto: mediana + IQR da última hora).")
    b.add("timeseries", "z robusto do TrafficAnomaly (limiar 3)", 12, 0, 12, 8,
          [q(A, "abs(instance:http_requests:rate1m{%(s)s} - quantile_over_time(0.5, instance:http_requests:rate1m{%(s)s}[1h]))"
                " / clamp_min((quantile_over_time(0.75, instance:http_requests:rate1m{%(s)s}[1h])"
                " - quantile_over_time(0.25, instance:http_requests:rate1m{%(s)s}[1h])) / 1.349, 0.5)" % {"s": ing},
             "z robusto")],
          thresholds=thr(("green", None), ("red", 3)), options=LEGEND,
          custom={"drawStyle": "line", "lineWidth": 2, "thresholdsStyle": {"mode": "dashed"},
                  "scaleDistribution": {"type": "log", "log": 10}},
          minmax=(0.01, None),
          desc="A mesma expressão da regra (monitoring/site/rules/anomalies.yml). Escala log; abaixo de "
               "0,1 é ruído de repouso.")
    b.add("timeseries", "Latência p95 — servidor vs cliente (SLO 100 ms)", 0, 8, 12, 9,
          [q(A, "instance:http_request_duration_seconds:p95_1m{%s}" % ing, "servidor (ing-01, medido no Flask)", "A"),
           q(O, 'instance:ssle_sensor_upstream_duration_seconds:p95_1m{role="sensor"}', "cliente ({{instance_name}})", "B")],
          unit="s", thresholds=thr(("green", None), ("red", 0.1)), options=LEGEND,
          custom={"drawStyle": "line", "lineWidth": 2, "thresholdsStyle": {"mode": "dashed"}},
          overrides=[{"matcher": {"id": "byFrameRefID", "options": "A"},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
                     {"matcher": {"id": "byFrameRefID", "options": "B"},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}},
                                     {"id": "custom.lineWidth", "value": 3}]}],
          desc="A lição da T1: o servidor mede ~23 ms enquanto o cliente sente ~242 ms (a fila antes de o "
               "Flask atender). Por isso o SLO tem de ser medido do lado do cliente (ClientLatencySLO).")
    rules = "TrafficAnomaly|ServiceLatencyHigh"
    st = ('max by (alertname, instance_name) (ALERTS{alertname=~"%s",alertstate="firing"}) * 2'
          ' or max by (alertname, instance_name) (ALERTS{alertname=~"%s",alertstate="pending"})')
    # série em degraus e não state-timeline: o state-timeline prolonga o último estado até ao fim do
    # gráfico quando a série acaba (alerta resolvido), o que desenharia um "firing" que já não existe
    b.add("timeseries", "Estado das regras (1 = pending · 2 = firing)", 12, 8, 12, 9,
          [q(A, st % (rules, rules), "{{alertname}} · {{instance_name}}", "A"),
           q(O, st % ("ClientLatencySLO|ClientUpstreamErrors", "ClientLatencySLO|ClientUpstreamErrors"),
             "{{alertname}} · {{instance_name}}", "B")],
          options=LEGEND, minmax=(0, 2.2),
          mappings=[{"type": "value", "options": {"1": {"text": "pending", "index": 0},
                                                   "2": {"text": "firing", "index": 1}}}],
          thresholds=thr(("orange", None), ("red", 1.5)),
          custom={"drawStyle": "line", "lineInterpolation": "stepAfter", "lineWidth": 2, "fillOpacity": 35,
                  "gradientMode": "scheme", "spanNulls": False, "axisLabel": "estado"},
          desc="MTTD = instante em que passa a firing − início do estímulo (for: 1m depois do 1.º sinal).")
    b.add("timeseries", "Leituras dos sensores (ok / erro)", 0, 17, 12, 7,
          [q(O, 'sum by (result) (rate(ssle_sensor_readings_total{role="sensor"}[1m]))', "{{result}}")],
          unit="reqps", custom={"drawStyle": "bars", "fillOpacity": 60, "stacking": {"mode": "normal"}},
          options=LEGEND, overrides=[
              {"matcher": {"id": "byName", "options": "error"},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]},
              {"matcher": {"id": "byName", "options": "ok"},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}],
          desc="Dano colateral: leituras perdidas (timeout 5 s) durante o ataque e durante a resposta.")
    b.add("timeseries", "Latência servida — distribuição (p95 do ing-01 vs SLO)", 12, 17, 12, 7,
          [q(A, 'histogram_quantile(0.5, sum by (le) (rate(http_request_duration_seconds_bucket{%s}[1m])))' % ing, "p50", "A"),
           q(A, 'histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{%s}[1m])))' % ing, "p99", "B")],
          unit="s", options=LEGEND, custom={"drawStyle": "line", "lineWidth": 1},
          desc="Mesmo durante o ataque, o servidor 'acha' que está rápido: o tempo de fila não entra aqui.")
    return b.write()


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for f in (soc(), t1()):
        print(os.path.relpath(f, os.path.dirname(HERE)))
