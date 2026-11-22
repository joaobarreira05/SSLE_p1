#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests of the RCA core (stdlib only):   python3 -m unittest -v correlator/test_rca.py

The graph is the REAL INVENTORY's (infra/inventory.py, full profile, host t490) — if someone changes the
dependencies in inventory/sites.yaml, these tests tell whether the root cause is still right.
"""
import importlib.util, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rca import Graph, Correlator, root_causes, site_identity  # noqa: E402

_spec = importlib.util.spec_from_file_location("inventory", os.path.join(HERE, "..", "infra", "inventory.py"))
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)
GRAPH = Graph(inventory.graph(inventory.build("t490", staging=False)))


def ident(site, inst):
    return "ssle:pt:%s:t490:%s" % (site, inst)


def alert(name, site, inst=None, severity="warning", starts="2026-11-08T10:00:00Z", status="firing"):
    labels = {"alertname": name, "region": "pt", "site": site, "severity": severity}
    ann = {}
    if inst:
        labels.update(instance_name=inst, host="t490")
        ann["identity"] = ident(site, inst)
    return {"status": status, "labels": labels, "annotations": ann, "startsAt": starts,
            "fingerprint": "%s/%s/%s" % (name, site, inst)}


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(settle=30):
    out, clk = [], Clock()
    return Correlator(GRAPH, out.append, settle_s=settle, clock=clk), out, clk


class RootCauses(unittest.TestCase):
    def test_demo_sto01_explains_ing01(self):
        """The staging demo: ElementDown(sto-01) + ServiceDegraded(ing-01) → 1 incident, cause sto-01."""
        g = root_causes([alert("ElementDown", "avr", "sto-01", "critical"),
                         alert("ServiceDegraded", "avr", "ing-01")], GRAPH)
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0][0], ident("avr", "sto-01"))
        self.assertEqual(g[0][1], {ident("avr", "sto-01"), ident("avr", "ing-01")})

    def test_cross_site_client_symptom_points_to_server(self):
        """T1: the opo sensor feels the latency, the avr ing-01 has the anomalous traffic → cause ing-01."""
        g = root_causes([alert("ClientLatencySLO", "opo", "sen-01", "critical"),
                         alert("TrafficAnomaly", "avr", "ing-01")], GRAPH)
        self.assertEqual([x[0] for x in g], [ident("avr", "ing-01")])

    def test_two_sensors_one_server(self):
        g = root_causes([alert("ClientLatencySLO", "opo", "sen-01", "critical"),
                         alert("ClientLatencySLO", "opo", "sen-02", "critical"),
                         alert("TrafficAnomaly", "avr", "ing-01")], GRAPH)
        self.assertEqual(len(g), 1)
        self.assertEqual(len(g[0][1]), 3)

    def test_independent_failures_give_two_incidents(self):
        """Before: 1 incident per site, and whatever the best candidate did not explain was left out."""
        g = root_causes([alert("ElementDown", "avr", "sto-01", "critical"),
                         alert("ElementDown", "lis", "web-01", "critical")], GRAPH)
        self.assertEqual({x[0] for x in g}, {ident("avr", "sto-01"), ident("lis", "web-01")})

    def test_site_unreachable_explains_remote_clients(self):
        """The whole avr site goes down: the opo sensors (which depend on ing-01@avr) are its symptoms."""
        g = root_causes([alert("SiteUnreachable", "avr", None, "critical"),
                         alert("ClientUpstreamErrors", "opo", "sen-01")], GRAPH)
        self.assertEqual([x[0] for x in g], [site_identity("pt", "avr")])

    def test_unknown_identity_is_its_own_incident(self):
        g = root_causes([alert("ElementDown", "avr", "zzz-99", "critical")], GRAPH)
        self.assertEqual(g[0][0], ident("avr", "zzz-99"))


class Settle(unittest.TestCase):
    def test_client_first_never_blames_the_sensor(self):
        """The client symptom arrives 10 s before the server alert: 'root cause = sensor' never comes out."""
        c, out, clk = make(settle=30)
        c.ingest({"alerts": [alert("ClientLatencySLO", "opo", "sen-01", "critical")]})
        self.assertEqual(out, [])                       # pending
        clk.t += 10
        c.ingest({"alerts": [alert("TrafficAnomaly", "avr", "ing-01")]})
        self.assertEqual(out, [])
        clk.t += 20                                     # 30 s after the 1st symptom
        c.tick()
        self.assertEqual(len(out), 1)
        inc = out[0]
        self.assertEqual(inc["root_cause"], ident("avr", "ing-01"))
        self.assertEqual(inc["root_cause_role"], "ingestion")
        self.assertEqual(inc["site"], "avr")
        self.assertEqual(inc["sites"], ["avr", "opo"])
        self.assertTrue(inc["cross_site"])
        self.assertEqual(inc["severity"], "critical")
        self.assertEqual(inc["status"], "open")
        self.assertEqual(inc["noise_reduction"], 2.0)
        self.assertFalse(any(o.get("root_cause_role") == "sensor" for o in out))
        self.assertEqual(inc["srcip"], "10.10.1.30")    # ing-01 IP in the inventory → same_source_ip in Wazuh
        self.assertEqual(inc["root_cause_ip"], "10.10.1.30")

    def test_without_settle_the_sensor_would_be_blamed(self):
        """Counterproof: with settle=0 (the old behaviour) an incident blaming the sensor comes out first."""
        c, out, clk = make(settle=0)
        c.ingest({"alerts": [alert("ClientLatencySLO", "opo", "sen-01", "critical")]})
        self.assertEqual(out[0]["root_cause_role"], "sensor")
        self.assertEqual(out[0]["srcip"], "10.10.2.50")

    def test_beaconing_sensor_is_root_cause_with_wazuh_fields(self):
        """T2: OutboundAnomaly only on sen-01 → incident with the fields Wazuh 110210 requires for quarantine."""
        c, out, clk = make(settle=30)
        c.ingest({"alerts": [alert("OutboundAnomaly", "opo", "sen-01", "critical")]})
        clk.t += 30
        c.tick()
        self.assertEqual(len(out), 1)
        inc = out[0]
        self.assertEqual(inc["root_cause"], ident("opo", "sen-01"))
        self.assertEqual(inc["root_cause_role"], "sensor")        # 110210: root_cause_role ^sensor$
        self.assertIn("OutboundAnomaly", inc["alert_names"])     # 110210: alert_names OutboundAnomaly
        self.assertEqual(inc["severity"], "critical")             # 110001: severity ^critical$
        self.assertEqual(inc["srcip"], "10.10.2.50")              # 110900: same_source_ip with the impact

    def test_growth_updates_same_incident_and_resolves(self):
        c, out, clk = make(settle=30)
        c.ingest({"alerts": [alert("TrafficAnomaly", "avr", "ing-01")]})
        clk.t += 30
        c.tick()
        self.assertEqual([o["status"] for o in out], ["open"])
        clk.t += 5
        c.ingest({"alerts": [alert("ClientLatencySLO", "opo", "sen-01", "critical")]})
        self.assertEqual([o["status"] for o in out], ["open", "updated"])
        self.assertEqual(out[0]["incident_id"], out[1]["incident_id"])
        self.assertEqual(out[1]["severity"], "critical")
        c.tick()                                        # nothing changed → nothing new
        self.assertEqual(len(out), 2)
        clk.t += 60
        c.ingest({"alerts": [alert("TrafficAnomaly", "avr", "ing-01", status="resolved"),
                             alert("ClientLatencySLO", "opo", "sen-01", "critical", status="resolved")]})
        self.assertEqual(out[-1]["status"], "resolved")
        self.assertEqual(out[-1]["root_cause"], ident("avr", "ing-01"))
        self.assertEqual(out[-1]["incident_id"], out[0]["incident_id"])
        self.assertEqual(out[-1]["srcip"], "10.10.1.30")
        self.assertEqual(c.metrics["open_incidents"], 0)
        self.assertEqual(c.metrics["incidents_total"], 1)


if __name__ == "__main__":
    unittest.main()
