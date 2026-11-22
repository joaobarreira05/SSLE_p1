#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Site registry tests (stdlib only):   python3 -m unittest -v registry/test_core.py
Configuration is from the REAL INVENTORY (site opo, full profile, host t490).
"""
import importlib.util, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from core import SiteRegistry, RegistryError  # noqa: E402

_spec = importlib.util.spec_from_file_location("inventory", os.path.join(HERE, "..", "infra", "inventory.py"))
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)
CONF = inventory.registry_config(inventory.build("t490", staging=False), "opo")
TOKEN = "test-t0ken-not-a-secret"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make(token=TOKEN, ttl=30):
    clk = Clock()
    r = SiteRegistry(CONF["region"], CONF["site"], CONF["subnet"], CONF["team"], CONF["host"],
                     token, CONF["static"], ttl_s=ttl, clock=clk)
    return r, clk


NEW = {"name": "sen-07", "role": "sensor", "ip": "10.10.2.57"}


class Write(unittest.TestCase):
    def assertRejects(self, status, reason, fn):
        with self.assertRaises(RegistryError) as cm:
            fn()
        self.assertEqual((cm.exception.status, cm.exception.reason), (status, reason))

    def test_new_sensor_registers_and_gets_identity(self):
        r, _ = make()
        res = r.register(NEW, TOKEN)
        self.assertEqual(res["identity"], "ssle:pt:opo:t490:sen-07")
        self.assertFalse(res["renewed"])
        self.assertTrue(r.register(NEW, TOKEN)["renewed"])

    def test_wrong_or_missing_token_is_refused(self):
        r, _ = make()
        self.assertRejects(403, "auth", lambda: r.register(NEW, "wrong"))
        self.assertRejects(403, "auth", lambda: r.register(NEW, None))
        self.assertEqual(r.snapshot()["rejections"], {"auth": 2})

    def test_no_token_configured_means_read_only(self):
        """Fail-closed: with no token configured nobody writes (not even with an empty token)."""
        r, _ = make(token="")
        self.assertRejects(403, "auth", lambda: r.register(NEW, ""))

    def test_validation(self):
        r, _ = make()
        self.assertRejects(400, "name", lambda: r.register(dict(NEW, name="../etc"), TOKEN))
        self.assertRejects(400, "role", lambda: r.register(dict(NEW, role="root"), TOKEN))
        self.assertRejects(400, "ip", lambda: r.register(dict(NEW, ip="not-an-ip"), TOKEN))

    def test_delegation_only_own_site_and_subnet(self):
        r, _ = make()
        self.assertRejects(403, "site", lambda: r.register(dict(NEW, site="avr"), TOKEN))
        self.assertRejects(403, "subnet", lambda: r.register(dict(NEW, ip="10.10.1.57"), TOKEN))

    def test_cannot_claim_a_known_identity_with_another_ip(self):
        """A container cannot impersonate sen-01 from the inventory."""
        r, _ = make()
        self.assertRejects(409, "identity", lambda: r.register(dict(NEW, name="sen-01", ip="10.10.2.99"), TOKEN))
        r.register(dict(NEW, name="sen-01", ip="10.10.2.50"), TOKEN)

    def test_ip_already_leased_to_another_name(self):
        r, _ = make()
        r.register(NEW, TOKEN)
        self.assertRejects(409, "ip-in-use", lambda: r.register(dict(NEW, name="sen-08"), TOKEN))


class Read(unittest.TestCase):
    def test_http_sd_only_dynamic_and_with_full_labels(self):
        r, _ = make()
        r.register(NEW, TOKEN)
        r.register(dict(NEW, name="sen-01", ip="10.10.2.50"), TOKEN)
        node = r.http_sd("node")
        self.assertEqual([t["targets"] for t in node], [["10.10.2.57:9100"]])
        self.assertEqual(node[0]["labels"]["instance_name"], "sen-07")
        self.assertEqual(node[0]["labels"]["registered"], "dynamic")
        svc = r.http_sd("services")
        self.assertEqual(svc[0]["targets"], ["10.10.2.57:8000"])
        self.assertEqual(svc[0]["labels"]["service"], "sensor")

    def test_lease_expires_without_heartbeat(self):
        r, clk = make(ttl=30)
        r.register(NEW, TOKEN)
        clk.t += 29
        self.assertEqual(len(r.http_sd("node")), 1)
        clk.t += 2
        self.assertEqual(r.http_sd("node"), [])
        self.assertEqual(r.snapshot()["dynamic"], [])

    def test_heartbeat_keeps_it_alive(self):
        r, clk = make(ttl=30)
        for _ in range(5):
            r.register(NEW, TOKEN)
            clk.t += 20
        self.assertEqual(len(r.http_sd("node")), 1)

    def test_round_robin_static_and_dynamic(self):
        r, _ = make()
        r.register(NEW, TOKEN)
        got = [r.discover("sensor")["name"] for _ in range(6)]
        self.assertEqual(got, ["sen-01", "sen-02", "sen-07"] * 2)
        self.assertIsNone(r.discover("mail"))

    def test_unknown_sd_job(self):
        r, _ = make()
        with self.assertRaises(RegistryError):
            r.http_sd("../../etc")


if __name__ == "__main__":
    unittest.main()
