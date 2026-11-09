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
| R8 | FCAPS detetar→diagnosticar→correlacionar→resolver→post-mortem | detetar/correlacionar ✅ (T1: MTTD 82 s / SOC 93 s); resolver: respostas executadas por agentes reais (`siem/tests/it-agents.sh`: nft no `ing-01`, `incus pause` no responder) ✅, medição do MTTR no T490 🧩; post-mortem T1 ✅, T2/T3 ✍️ | parcial |
| R9 | SIEM: 3 tipos de incidente + action-response | `siem/rules` (1100–1109xx): **23/23 casos** no `wazuh-analysisd` real (`siem/tests/run-logtest.sh`) + integração com 4 agentes reais (`siem/tests/it-agents.sh`, incl. meta-correlação entre agentes); respostas `siem/active-response` (`test-ar.sh`) e `siem/manager/ossec-ssle.conf` gerado do inventário | ✅ (sem lab) / 🧩 (T490) |
| R10 | SIEM: log management | `siem/shared/*/agent.conf` por grupo (site/papel): auth.log, log de acesso *combined*, mail.log, `incidents.json`, FIM, comando de portas; labels de identidade em cada alerta (`it-agents.sh`) | ✅ (sem lab) / 🧩 (T490) |
| R11 | Por ameaça: descrição…post-mortem | T1: `threats/t1-ddos/post-mortem.md` (6 subtítulos do slide 12 + 3 execuções medidas) ✅ · T2/T3: deteção+resposta validadas com agentes reais (`report/sections/05-2-*`, `05-3-*`; MTA real em `threats/t3-spam/`) ✅, PoC e tempos no T490 🧩 | parcial |
| R12 | Conclusões (porque não é perfeita, futuro) | `report/` | ✍️ |
| R13 | Relatório estilo artigo/tese | `report/` | ✍️ |
| R14 | Demo + repositórios | este repo + `infra/demo.sh` | ✅ |

**Nota staging:** o SIEM (Wazuh, 4–6 GiB) e os sites `lis`/`opo`-extra não entram no perfil `staging`
para poupar RAM na VM arm64. Correm no T490 com `SSLE_PROFILE=full`.
