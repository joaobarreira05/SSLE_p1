# Matriz de rastreabilidade (requisito → evidência)

> Estado: ✅ provado ao vivo no staging · 🧩 código pronto (corre no T490) · ✍️ a preencher nas PoCs.

| # | Requisito (slide) | Onde está | Estado |
|---|---|---|---|
| R1 | Arquitetura de serviços que escala | `inventory/sites.yaml`, `infra/deploy.sh` (frota por sites) | ✅ |
| R2 | Identificação/registo escalável (name construction) | convenção `ssle:region:site:host:inst` + labels; **registry de site** (`registry/`: leases com TTL, escrita autenticada, delegação por site/sub-rede, HTTP SD) — integração provada com Prometheus 2.53.5 real (`registry/it-local.sh`, output em `registry/README.md`); no lab: `reg-01` em avr/opo 🧩 | ✅ (integração) / 🧩 (lab) |
| R3 | Físico vs lógico | labels `host` (t490/mac-m2), `instance_name`, `project`, `role` | ✅ |
| R4 | Localização geográfica + delegação | projetos/redes Incus por site; grupos/`agent.conf` Wazuh; rotas Alertmanager por `team` | ✅ / 🧩 |
| R5 | (Bónus) monitorizar por localização poupando banda | Prometheus hierárquico; **federation só de agregados** (`site:up:ratio` visível no global); Grafana SOC com **Geomap** (`site:info:last`) e o custo da federation por site; drill-down vai ao `prom-01` do site (`monitoring/grafana/README.md`) | ✅ (falta medir bytes com/sem agregação — F4) |
| R6 | Localizar rapidamente a origem | labels em todos os alertas + **causa raiz** no `incidents.json` | ✅ |
| R7 | Prometheus (anomalias) + correlação p/ causa raiz | regras site (`TrafficAnomaly` z robusto + `ServiceLatencyHigh`, `monitoring/tests/anomaly_test.yml`); Alertmanager (inibição); **correlator** (RCA por grafo); T1 ao vivo: 3/3 detetados, 0 FP, causa raiz `ing-01` 3/3 (`threats/t1-ddos/evidence/results.md`) | ✅ |
| R8 | FCAPS detetar→diagnosticar→correlacionar→resolver→post-mortem | detetar/correlacionar ✅ (T1: MTTD 82 s / SOC 93 s); resolver (active-response) 🧩; post-mortem T1 ✅ (`threats/t1-ddos/post-mortem.md`), T2/T3 ✍️ | parcial |
| R9 | SIEM: 3 tipos de incidente + action-response | `siem/rules` (1101/1102/1103xx) + `siem/active-response` | 🧩 |
| R10 | SIEM: log management | `siem/shared/*/agent.conf` (localfile, FIM, portas) | 🧩 |
| R11 | Por ameaça: descrição…post-mortem | T1: `threats/t1-ddos/post-mortem.md` (6 subtítulos do slide 12 + 3 execuções medidas) ✅ · T2/T3: `threats/t2,t3/README.md` 🧩 / ✍️ | parcial |
| R12 | Conclusões (porque não é perfeita, futuro) | `report/` | ✍️ |
| R13 | Relatório estilo artigo/tese | `report/` | ✍️ |
| R14 | Demo + repositórios | este repo + `infra/demo.sh` | ✅ |

**Nota staging:** o SIEM (Wazuh, 4–6 GiB) e os sites `lis`/`opo`-extra não entram no perfil `staging`
para poupar RAM na VM arm64. Correm no T490 com `SSLE_PROFILE=full`.
