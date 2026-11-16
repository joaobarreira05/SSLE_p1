# Matriz de rastreabilidade (requisito → evidência)

> Estado: ✅ provado ao vivo (staging e/ou T490) · 🧩 código pronto (não testado ao vivo).

| # | Requisito (slide) | Onde está | Estado |
|---|---|---|---|
| R1 | Arquitetura de serviços que escala | `inventory/sites.yaml`, `infra/deploy.sh` (frota por sites) | ✅ |
| R2 | Identificação/registo escalável (name construction) | convenção `ssle:region:site:host:inst` + labels; **registry de site** (`registry/`: leases com TTL, escrita autenticada, delegação por site/sub-rede, HTTP SD) — integração provada com Prometheus 2.53.5 real (`registry/it-local.sh`); no lab T490: `reg-01` em avr/opo a correr | ✅ |
| R3 | Físico vs lógico | labels `host` (t490/mac-m2), `instance_name`, `project`, `role` | ✅ |
| R4 | Localização geográfica + delegação | projetos/redes Incus por site; grupos/`agent.conf` Wazuh; rotas Alertmanager por `team`; Grafana Geomap com coordenadas do inventário | ✅ |
| R5 | (Bónus) monitorizar por localização poupando banda | Prometheus hierárquico; **federation só de agregados** (`site:up:ratio` visível no global); Grafana SOC com **Geomap** (`site:info:last`) e o custo da federation por site; drill-down vai ao `prom-01` do site (`monitoring/grafana/README.md`) | ✅ · banda **medida**: 99,3–99,7 % menos bytes que sem hierarquia (N = 10/25/50; `evaluation/federation-bytes.md`) |
| R6 | Localizar rapidamente a origem | labels em todos os alertas + **causa raiz** no `incidents.json` | ✅ |
| R7 | Prometheus (anomalias) + correlação p/ causa raiz | regras site (`TrafficAnomaly` z robusto + `ServiceLatencyHigh`, `monitoring/tests/anomaly_test.yml`; T2: `OutboundAnomaly` sobre as ligações de saída dos sensores, `monitoring/tests/outbound_test.yml`); Alertmanager (inibição); **correlator** (RCA por grafo); T1 ao vivo: 3/3 detetados, 0 FP, causa raiz `ing-01` 3/3 (`threats/t1-ddos/evidence/results.md`) | ✅ |
| R8 | FCAPS detetar→diagnosticar→correlacionar→resolver→post-mortem | detetar/correlacionar ✅; resolver: respostas no T490 (nft ~6 s, quarentena ~140 s, firewall-drop <10 s); post-mortem T1/T2/T3 no relatório §5.1–5.3 | ✅ |
| R9 | SIEM: 3 tipos de incidente + action-response | `siem/rules` (1100–1109xx): **25/25 casos** no `wazuh-analysisd` real + integração com agentes reais (Docker + T490 14 agentes); respostas validadas ao vivo nos 3 tipos | ✅ |
| R10 | SIEM: log management | `siem/shared/*/agent.conf` por grupo (site/papel): auth.log, log de acesso *combined*, mail.log, `incidents.json`, FIM, comando de portas; labels de identidade em cada alerta; 14 agentes no T490 | ✅ |
| R11 | Por ameaça: descrição…post-mortem | T1–T3 com os 6 subtítulos do slide 12 no relatório §5.1–5.3; PoCs validadas no T490 (14/11) com evidência versionada | ✅ |
| R12 | Conclusões (porque não é perfeita, futuro) | relatório §7: limitações (8 pontos) + trabalho futuro (4 pontos) | ✅ |
| R13 | Relatório estilo artigo/tese | `report/latex/main.tex` → `main.pdf` (25 páginas, xelatex, inglês, 8 referências) | ✅ |
| R14 | Demo + repositórios | este repo + `infra/demo.sh` | ✅ |

**Nota staging:** o SIEM (Wazuh, 4–6 GiB) e os sites `lis`/`opo`-extra não entram no perfil `staging`
para poupar RAM na VM arm64. Correm no T490 com `SSLE_PROFILE=full`.
