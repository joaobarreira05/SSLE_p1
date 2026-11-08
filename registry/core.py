#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Núcleo do registry de site (R2: identificação/registo escalável) — só stdlib, testável sem Flask
(testes em registry/test_core.py). Estende o service_registry.py da aula 2:

  aula 2                         →  aqui
  registo sem autenticação       →  escrita só com token do site (comparação em tempo constante)
  qualquer nome/URL              →  nome, papel, site e IP VALIDADOS (falha fechada: 400/403/409)
  health-check ativo a cada 5 s  →  LEASE com TTL renovado pelo próprio elemento (heartbeat): escala
                                     melhor (o registry não faz N pedidos) e um elemento que morre
                                     desaparece sozinho ao fim de TTL s
  round-robin para clientes      →  mantém-se (/services/<role>) e acrescenta HTTP SD para o Prometheus

Delegação (R4): cada site tem o SEU registry (reg-01), que só aceita elementos desse site e da sua
sub-rede. Os elementos do INVENTÁRIO são estáticos (file_sd); o HTTP SD devolve só os que se
REGISTARAM dinamicamente e não estão no inventário. Assim, se o registry cair, a frota de base
continua a ser monitorizada (falha segura) e não há alvos duplicados.

Identidade: ssle:<region>:<site>:<host>:<name> — a mesma do Prometheus e do Wazuh. Um registo que
reclame a identidade de um elemento do inventário com OUTRO IP é recusado (409): impede que um
contentor comprometido se faça passar por um elemento conhecido.
"""
import hmac, ipaddress, re, threading, time

NAME_RE = re.compile(r"^[a-z]{3}-\d{2}$")          # sen-07, ing-02, …
ROLES = {"sensor", "ingestion", "storage", "analytics", "web", "mail", "prometheus", "registry"}
PORTS = {"node": 9100, "services": 8000}
FLASK_ROLES = {"sensor", "ingestion", "analytics", "web"}   # os que expõem /metrics do serviço em :8000


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
        self.static = {e["name"]: e for e in static}     # elementos do inventário deste site
        self.leases = {}                                  # name -> {ip, role, expires, registered_at}
        self.lock = threading.Lock()
        self.counters = {"registrations_total": 0, "renewals_total": 0}
        self.rejections = {}                              # motivo -> contagem
        self._rr = {}

    # ── escrita (autenticada e validada) ─────────────────────────────────────
    def _reject(self, status, reason):
        self.rejections[reason] = self.rejections.get(reason, 0) + 1
        raise RegistryError(status, reason)

    def _auth(self, presented):
        # sem token configurado → ninguém escreve (falha fechada, nunca "aberto por omissão")
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
                self._reject(403, "site")                 # delegação: só o próprio site
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self._reject(400, "ip")
            if addr not in self.subnet:
                self._reject(403, "subnet")
            st = self.static.get(name)
            if st and st.get("ip") != ip:
                self._reject(409, "identity")             # reclamar uma identidade conhecida com outro IP
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

    # ── leitura ──────────────────────────────────────────────────────────────
    def identity(self, name):
        return "ssle:%s:%s:%s:%s" % (self.region, self.site, self.host, name)

    def _live(self):
        now = self.clock()
        for n in [n for n, l in self.leases.items() if l["expires"] <= now]:
            del self.leases[n]                            # lease expirado: sai sozinho
        return self.leases

    def labels(self, name, role):
        return {"region": self.region, "site": self.site, "host": self.host, "instance_name": name,
                "role": role, "team": self.team, "project": "site-%s" % self.site,
                "registered": "dynamic"}

    def http_sd(self, job):
        """Formato HTTP SD do Prometheus: [{"targets": ["ip:porta"], "labels": {...}}] (só dinâmicos)."""
        if job not in PORTS:
            raise RegistryError(404, "job")
        out = []
        with self.lock:
            for name, l in sorted(self._live().items()):
                if name in self.static:
                    continue                              # já está no file_sd do inventário
                if job == "services" and l["role"] not in FLASK_ROLES:
                    continue
                lbl = self.labels(name, l["role"])
                if job == "services":
                    lbl["service"] = l["role"]
                out.append({"targets": ["%s:%d" % (l["ip"], PORTS[job])], "labels": lbl})
        return out

    def discover(self, role):
        """Round-robin entre as instâncias VIVAS com este papel (estáticas + dinâmicas), como na aula 2."""
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
