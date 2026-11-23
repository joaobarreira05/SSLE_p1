#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Grafana dashboards as CODE: this file is the source; JSONs in dashboards/ are generated
(and versioned, because that is what Grafana loads via the provider in providers/ssle.yml).

    python3 monitoring/grafana/build_dashboards.py      # rewrites dashboards/*.json

Datasources (stable uids, generated from inventory by `infra/inventory.py grafana`):
  prom-global (federated aggregates only) · prom-<site> (per-instance drill-down) · alertmanager

  ssle-soc  — SOC view: site map (Geomap from site:info:last), availability, correlator incidents,
              firing alerts across all sites, federation cost (R5), registry (R2)
  ssle-t1   — Threat 1 (DoS) on ing-01: rate (R), server vs CLIENT latency against SLO, rule state
              (pending/firing), sensor readings. The "Grafana during a PoC" figure.
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
    b = Board("ssle-soc", "SSLE — SOC (global view)",
              "SOC view on core/obs: federated site aggregates only (R5) + correlator incidents.",
              ["ssle", "soc", "fcaps"])
    G = "prom-global"
    b.add("geomap", "Sites — availability", 0, 0, 10, 11,
          [q(G, "site:info:last", ref="A", instant=True, table=True),
           q(G, "site:up:ratio", ref="B", instant=True, table=True)],
          unit="percentunit", minmax=(0, 1),
          thresholds=thr(("red", None), ("orange", 0.5), ("green", 0.99)),
          desc="Position of each site (lat/lon from inventory, served by reg-01 as site_info) and the "
               "fraction of 'up' elements. Without Internet in the lab the base map does not load; markers do.",
          transformations=[
              {"id": "joinByField", "options": {"byField": "site", "mode": "outer"}},
              {"id": "convertFieldType", "options": {"fields": {}, "conversions": [
                  {"targetField": "lat", "destinationType": "number"},
                  {"targetField": "lon", "destinationType": "number"}]}}],
          options={"view": {"id": "coords", "lat": 39.9, "lon": -8.6, "zoom": 6.4},
                   "controls": {"showZoom": True, "mouseWheelZoom": True},
                   "basemap": {"type": "xyz", "name": "OpenStreetMap",
                                        "config": {"url": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
                                                   "attribution": "© OpenStreetMap"}},
                   "tooltip": {"mode": "details"},
                   "layers": [{"type": "markers", "name": "Sites", "tooltip": True,
                               "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
                               "config": {"showLegend": True, "style": {
                                   "size": {"fixed": 14}, "color": {"field": "Value #B", "fixed": "green"},
                                   "text": {"mode": "field", "field": "site", "fixed": ""},
                                   "textConfig": {"fontSize": 13, "offsetY": -18, "textAlign": "center",
                                                  "textBaseline": "middle"}}}}]})
    b.add("stat", "Availability per site", 10, 0, 8, 5, [q(G, "site:up:ratio", "{{site}}")],
          unit="percentunit", thresholds=thr(("red", None), ("orange", 0.5), ("green", 0.99)), options=STAT,
          desc="site:up:ratio — mean of up{job=\"node\"} on the site (federated recording rule).")
    b.add("stat", "Open incidents", 18, 0, 3, 5, [q(G, "correlator_open_incidents", "open")],
          thresholds=thr(("green", None), ("red", 1)), options=STAT)
    b.add("stat", "Pending (settle)", 21, 0, 3, 5, [q(G, "correlator_pending_incidents", "pending")],
          thresholds=thr(("green", None), ("orange", 1)), options=STAT,
          desc="Incidents with a new root cause waiting for the settle window (CORRELATOR_SETTLE).")
    b.add("stat", "Incidents since start", 10, 5, 4, 6, [q(G, "correlator_incidents_total", "total")],
          thresholds=thr(("blue", None)), options=STAT)
    b.add("stat", "Noise reduction (last)", 14, 5, 4, 6,
          [q(G, "correlator_last_noise_reduction", "alerts → 1 incident")],
          thresholds=thr(("blue", None)), options=STAT,
          desc="Raw alerts the correlator merged into the last incident (N alerts → 1).")
    b.add("stat", "Dynamically registered elements", 18, 5, 6, 6,
          [q(G, 'sum by (site) (site:registry_instances:sum{kind="dynamic"})', "{{site}}")],
          thresholds=thr(("blue", None)), options=STAT,
          desc="R2: elements that entered via the site reg-01 (outside inventory).")
    b.add("table", "Firing alerts (all sites)", 0, 11, 12, 9,
          [q(G, "site:alerts:firing", instant=True, table=True)],
          desc="ALERTS{alertstate=\"firing\"} federated from site Prometheus instances (renamed on global).",
          transformations=[{"id": "organize", "options": {
              "excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True,
                                "job": True, "instance": True, "level": True, "region": True,
                                "host": True, "project": True},
              "indexByName": {"site": 0, "alertname": 1, "instance_name": 2, "severity": 3, "kind": 4}}}])
    b.add("timeseries", "Elements down per site", 12, 11, 12, 9, [q(G, "site:down:count", "{{site}}")],
          custom={"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10}, options=LEGEND)
    b.add("timeseries", "Federation — samples per scrape, per site (R5)", 0, 20, 12, 8,
          [q(G, 'scrape_samples_scraped{job="federate"}', "{{site}}")],
          custom={"drawStyle": "line", "lineWidth": 2}, options=LEGEND,
          desc="How many series the global pulls from each site every 30 s: aggregates only (site.*:.*), up and "
               "active alerts — not raw series. This is the bandwidth cost of monitoring by location.")
    b.add("timeseries", "Requests per service and site (aggregated)", 12, 20, 12, 8,
          [q(G, "site_service:http_requests:rate5m", "{{site}} / {{service}}")],
          unit="reqps", custom={"drawStyle": "line", "lineWidth": 2}, options=LEGEND)
    return b.write()


def t1():
    b = Board("ssle-t1", "SSLE — T1 DoS (ing-01)",
              "Threat 1: request rate on ing-01 (avr), latency as seen by the server and the CLIENT (opo sensors) "
              "against the 100 ms SLO, and rule state. See threats/t1-ddos/post-mortem.md.",
              ["ssle", "t1", "dos"], refresh="5s", span="now-15m")
    A, O = "prom-avr", "prom-opo"
    ing = 'instance_name="ing-01"'
    b.add("timeseries", "Request rate on ing-01 (R of RED)", 0, 0, 12, 8,
          [q(A, "instance:http_requests:rate1m{%s}" % ing, "ing-01 (req/s)")],
          unit="reqps", custom={"drawStyle": "line", "lineWidth": 2, "fillOpacity": 15}, options=LEGEND,
          desc="Input to TrafficAnomaly (robust z-score: median + IQR of the last hour).")
    b.add("timeseries", "Robust z-score of TrafficAnomaly (threshold 3)", 12, 0, 12, 8,
          [q(A, "abs(instance:http_requests:rate1m{%(s)s} - quantile_over_time(0.5, instance:http_requests:rate1m{%(s)s}[1h]))"
                " / clamp_min((quantile_over_time(0.75, instance:http_requests:rate1m{%(s)s}[1h])"
                " - quantile_over_time(0.25, instance:http_requests:rate1m{%(s)s}[1h])) / 1.349, 0.5)" % {"s": ing},
             "robust z")],
          thresholds=thr(("green", None), ("red", 3)), options=LEGEND,
          custom={"drawStyle": "line", "lineWidth": 2, "thresholdsStyle": {"mode": "dashed"},
                  "scaleDistribution": {"type": "log", "log": 10}},
          minmax=(0.01, None),
          desc="Same expression as the rule (monitoring/site/rules/anomalies.yml). Log scale; below "
               "0.1 is resting noise.")
    b.add("timeseries", "p95 latency — server vs client (SLO 100 ms)", 0, 8, 12, 9,
          [q(A, "instance:http_request_duration_seconds:p95_1m{%s}" % ing, "server (ing-01, measured in Flask)", "A"),
           q(O, 'instance:ssle_sensor_upstream_duration_seconds:p95_1m{role="sensor"}', "client ({{instance_name}})", "B")],
          unit="s", thresholds=thr(("green", None), ("red", 0.1)), options=LEGEND,
          custom={"drawStyle": "line", "lineWidth": 2, "thresholdsStyle": {"mode": "dashed"}},
          overrides=[{"matcher": {"id": "byFrameRefID", "options": "A"},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
                     {"matcher": {"id": "byFrameRefID", "options": "B"},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}},
                                     {"id": "custom.lineWidth", "value": 3}]},
                     # second sensor in another colour, or the two client lines are indistinguishable
                     {"matcher": {"id": "byName", "options": "client (sen-02)"},
                      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}}]}],
          desc="The T1 lesson: the server measures ~23 ms while the client feels ~242 ms (the queue before "
               "Flask starts serving). Hence the SLO must be measured on the client side (ClientLatencySLO).")
    rules = "TrafficAnomaly|ServiceLatencyHigh"
    st = ('max by (alertname, instance_name) (ALERTS{alertname=~"%s",alertstate="firing"}) * 2'
          ' or max by (alertname, instance_name) (ALERTS{alertname=~"%s",alertstate="pending"})')
    b.add("timeseries", "Rule state (1 = pending · 2 = firing)", 12, 8, 12, 9,
          [q(A, st % (rules, rules), "{{alertname}} · {{instance_name}}", "A"),
           q(O, st % ("ClientLatencySLO|ClientUpstreamErrors", "ClientLatencySLO|ClientUpstreamErrors"),
             "{{alertname}} · {{instance_name}}", "B")],
          options=LEGEND, minmax=(0, 2.2),
          mappings=[{"type": "value", "options": {"1": {"text": "pending", "index": 0},
                                                   "2": {"text": "firing", "index": 1}}}],
          thresholds=thr(("orange", None), ("red", 1.5)),
          custom={"drawStyle": "line", "lineInterpolation": "stepAfter", "lineWidth": 2, "fillOpacity": 35,
                  "gradientMode": "scheme", "spanNulls": False, "axisLabel": "state"},
          desc="MTTD = instant it switches to firing − stimulus start (for: 1m after the 1st signal).")
    b.add("timeseries", "Sensor readings (ok / error)", 0, 17, 12, 7,
          [q(O, 'sum by (result) (rate(ssle_sensor_readings_total{role="sensor"}[1m]))', "{{result}}")],
          unit="reqps", custom={"drawStyle": "bars", "fillOpacity": 60, "stacking": {"mode": "normal"}},
          options=LEGEND, overrides=[
              {"matcher": {"id": "byName", "options": "error"},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]},
              {"matcher": {"id": "byName", "options": "ok"},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}],
          desc="Collateral damage: lost readings (timeout 5 s) during the attack and during the response.")
    b.add("timeseries", "Served latency — distribution (ing-01 p95 vs SLO)", 12, 17, 12, 7,
          [q(A, 'histogram_quantile(0.5, sum by (le) (rate(http_request_duration_seconds_bucket{%s}[1m])))' % ing, "p50", "A"),
           q(A, 'histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{%s}[1m])))' % ing, "p99", "B")],
          unit="s", options=LEGEND, custom={"drawStyle": "line", "lineWidth": 1},
          desc="Even during the attack, the server 'thinks' it is fast: queue time is not included here.")
    return b.write()


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for f in (soc(), t1()):
        print(os.path.relpath(f, os.path.dirname(HERE)))
