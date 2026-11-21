# Site registry (R2) — dynamic registration + HTTP SD

> **Requirement R2:** *scalable identification and registration* of elements. In lecture 2 the registry was an
> in-memory dictionary with active *health-check* and *round-robin*. Here it is the **`reg-01` of each site**,
> which adds what is missing for large scale and security. The identity is the same everywhere:
> `ssle:<region>:<site>:<host>:<name>`.

## How it fits

```
 new element (outside inventory)                 site reg-01 (registry/app.py :5050)
  services/app.py  ── POST /register (token) ──►   validates name/role/site/subnet/identity
  (heartbeat 10 s)                                   TTL 30 s lease  ──►  GET /sd/node, /sd/services
                                                                                     │ HTTP SD (15 s)
 INVENTORY elements ── file_sd (static) ──►  site prom-01  ◄──────────────┘
                                              (relabel → job="node"/"services": the SAME rules)
```

| Lecture 2 | Here | Why |
|---|---|---|
| unauthenticated registration | writes require **site token** (`hmac.compare_digest`), generated at deploy (`build/secrets/`, outside Git; `0600` in the container) | every write requires authentication; with no token configured the registry is **read-only** (fail-closed) |
| any name/URL | name `^[a-z]{3}-\d{2}$`, role from a whitelist, **site = the registry's own**, IP **in the site subnet** | delegation (R4): a site cannot register elements from another; invalid input → reject |
| — | claiming the identity of an inventory element with a **different IP** → `409` | a compromised container cannot impersonate `sen-01` |
| active *health-check* every 5 s | **TTL lease** renewed by the element itself | scale: the registry does not make N requests per cycle; an element that dies disappears on its own |
| round-robin for clients | kept (`/services/<role>`) **+ HTTP SD** for Prometheus | the same registration serves both service discovery **and** monitoring |
| — | `/metrics`: `site_info{city,lat,lon}`, static/dynamic instances, rejections by reason | Geomap in Grafana; `auth` rejections are a security signal |

**Fail-safe:** inventory elements are read by `file_sd` and HTTP SD returns **only** dynamically registered
ones. If `reg-01` goes down, the base fleet remains monitored and Prometheus keeps the last SD targets —
at most, discovery of **new** elements is lost.

## Proof (integration test, no lab) — `bash registry/it-local.sh`

Real registry + real `services/app.py` (dynamic sensor `sen-07`) + **real Prometheus 2.53.5** with the
`prometheus.yml` of site `opo` rendered by the inventory (`infra/inventory.py siteprom`), all on
`127.0.0.1`. Real output (08/11/2026):

```text
[it] site opo registry on 127.0.0.1:15050 (TTL 10 s)
[it] (1) write without token:
      HTTP 403
[it] Prometheus 2.53.5 on 127.0.0.1:19090 with the opo site prometheus.yml (SD every 3 s)
[it] (2) start sen-07 (services/app.py) — NOT in the inventory
      node sen-07 opo sensor http://10.10.2.57:9100/metrics
      services sen-07 opo sensor http://10.10.2.57:8000/metrics
      site_info{region="pt",site="opo",city="Porto",lat="41.15",lon="-8.61"} 1
      ssle_registry_instances{region="pt",site="opo",kind="static"} 4
      ssle_registry_instances{region="pt",site="opo",kind="dynamic"} 1
      ssle_registry_rejections_total{region="pt",site="opo",reason="auth"} 1
[it] (3) sen-07 dies → the lease expires (10 s) and leaves the targets
      left the targets 9 s after dying
RESULT: R2 — dynamic registration → Prometheus discovery → expiration ✅
```

(The targets show `down` in this test because `10.10.2.57` only exists in the lab; what is proven here is
the **discovery** and labels. On the T490 `sen-07` is a container and scraping works.)

Unit tests (12): `python3 -m unittest -v registry/test_core.py` — token, validation, delegation,
identity, IP in use, TTL, heartbeat, round-robin, HTTP SD with dynamic only.

## Limitations (by design)

- The token is **shared per site**, not per element: whoever has it can register any free name on the site.
  Next step would be a per-element token (or mTLS with the Incus certificate).
- The registry trusts the **declared** IP (validates the subnet, not the request origin): behind Incus NAT
  the origin would be the gateway. With NAT off during PoCs, it could require `declared IP == origin IP`.
- State is in-memory only (as in lecture 2): restarting `reg-01` forgets dynamic entries until the next
  heartbeat (≤ 10 s) — acceptable because elements re-register on their own.

## Takeaways

- **Dynamic registration ≠ inventory:** the inventory is the source of truth for the base fleet; the registry
  is what lets the fleet **grow** without editing files (scale) — and therefore must **authenticate and validate**.
- **Lease + heartbeat** scales better than active health-check and provides automatic cleanup.
- **HTTP SD + `job` relabel**: new elements inherit the same liveness/anomaly rules.
