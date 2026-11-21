#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Site registry core (R2: scalable identification/registration) — stdlib only, testable without Flask
(tests in registry/test_core.py). Extends the lecture-2 service_registry.py:

  lecture 2                      →  here
  unauthenticated registration   →  writes require site token (constant-time comparison)
  any name/URL                   →  name, role, site and IP VALIDATED (fail-closed: 400/403/409)
  active health-check every 5 s  →  TTL LEASE renewed by the element itself (heartbeat): scales better
                                     (the registry makes no N requests) and an element that dies
                                     disappears on its own after TTL s
  round-robin for clients        →  kept (/services/<role>) and adds HTTP SD for Prometheus

Delegation (R4): each site has ITS OWN registry (reg-01), which only accepts elements from that site
and subnet. INVENTORY elements are static (file_sd); HTTP SD returns only those that REGISTERED
dynamically and are not in the inventory. Thus, if the registry goes down, the base fleet remains
monitored (fail-safe) and there are no duplicate targets.

Identity: ssle:<region>:<site>:<host>:<name> — the same as in Prometheus and Wazuh. A registration
claiming the identity of an inventory element with a DIFFERENT IP is refused (409): prevents a
compromised container from impersonating a known element.
"""
import hmac, ipaddress, re, threading, time

NAME_RE = re.compile(r"^[a-z]{3}-\d{2}$")          # sen-07, ing-02, …
ROLES = {"sensor", "ingestion", "storage", "analytics", "web", "mail", "prometheus", "registry"}
PORTS = {"node": 9100, "services": 8000}
FLASK_ROLES = {"sensor", "ingestion", "analytics", "web"}


class RegistryError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


class SiteRegistry:
    def __init__(self, region, site, subnet, team, host, token, static=(), ttl_s=30, clock=time.time):
        self.region, self.site, self.team, self.host = region, site, team, host
        self.subnet = ipaddress.ip_network(subnet)
        self._token = token or ""
        self.ttl, self.clock = ttl_s, clock
        self.static = {e["name"]: e for e in static}
        self.leases = {}
        self.lock = threading.Lock()
        self.counters = {"registrations_total": 0, "renewals_total": 0}
        self.rejections = {}
        self._rr = {}

    # ── writes (authenticated and validated) ────────────────────────────────
    def _reject(self, status, reason):
        self.rejections[reason] = self.rejections.get(reason, 0) + 1
        raise RegistryError(status, reason)

    def _auth(self, presented):
        # no token configured → nobody writes (fail-closed, never "open by default")
        if not self._token or not hmac.compare_digest(str(presented or ""), self._token):
            self._reject(403, "auth")

    def register(self, data, token):
        with self.lock:
            self._auth(token)
            name, role, ip = data.get("name", ""), data.get("role", ""), data.get("ip", "")
            if not NAME_RE.match(str(name)):
                self._reject(400, "name")
            if role not in ROLES:
                self._reject(400, "role")
            if data.get("site", self.site) != self.site:
                self._reject(403, "site")
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self._reject(400, "ip")
            if addr not in self.subnet:
                self._reject(403, "subnet")
            st = self.static.get(name)
            if st and st.get("ip") != ip:
                self._reject(409, "identity")
            for other, lease in self.leases.items():
                if other != name and lease["ip"] == ip and lease["expires"] > self.clock():
                    self._reject(409, "ip-in-use")
            now = self.clock()
            renew = name in self.leases
            self.leases[name] = {"ip": ip, "role": role, "expires": now + self.ttl,
                                 "registered_at": self.leases.get(name, {}).get("registered_at", now)}
            self.counters["renewals_total" if renew else "registrations_total"] += 1
            return {"identity": self.identity(name), "ttl_s": self.ttl, "renewed": renew}

    def unregister(self, name, token):
        with self.lock:
            self._auth(token)
            return self.leases.pop(name, None) is not None

    # ── reads ────────────────────────────────────────────────────────────────
    def identity(self, name):
        return "ssle:%s:%s:%s:%s" % (self.region, self.site, self.host, name)

    def _live(self):
        now = self.clock()
        for n in [n for n, l in self.leases.items() if l["expires"] <= now]:
            del self.leases[n]
        return self.leases

    def labels(self, name, role):
        return {"region": self.region, "site": self.site, "host": self.host, "instance_name": name,
                "role": role, "team": self.team, "project": "site-%s" % self.site,
                "registered": "dynamic"}

    def http_sd(self, job):
        """Prometheus HTTP SD format: [{"targets": ["ip:port"], "labels": {...}}] (dynamic only)."""
        if job not in PORTS:
            raise RegistryError(404, "job")
        out = []
        with self.lock:
            for name, l in sorted(self._live().items()):
                if name in self.static:
                    continue
                if job == "services" and l["role"] not in FLASK_ROLES:
                    continue
                lbl = self.labels(name, l["role"])
                if job == "services":
                    lbl["service"] = l["role"]
                out.append({"targets": ["%s:%d" % (l["ip"], PORTS[job])], "labels": lbl})
        return out

    def discover(self, role):
        """Round-robin across LIVE instances with this role (static + dynamic)."""
        with self.lock:
            cands = sorted({(n, e["ip"]) for n, e in self.static.items() if e.get("role") == role} |
                           {(n, l["ip"]) for n, l in self._live().items() if l["role"] == role})
            if not cands:
                return None
            i = self._rr.get(role, 0) % len(cands)
            self._rr[role] = i + 1
            name, ip = cands[i]
            return {"name": name, "ip": ip, "identity": self.identity(name), "of": len(cands)}

    def snapshot(self):
        with self.lock:
            live = self._live()
            return {"site": self.site, "ttl_s": self.ttl,
                    "static": sorted(self.static), "dynamic": sorted(n for n in live if n not in self.static),
                    "counters": dict(self.counters), "rejections": dict(self.rejections)}
