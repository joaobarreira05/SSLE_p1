# Matriz de rastreabilidade (requisito → evidência)

> Estado: ✅ provado ao vivo no staging · 🧩 código pronto (corre no T490) · ✍️ a preencher nas PoCs.

| # | Requisito (slide) | Onde está | Estado |
|---|---|---|---|
| R1 | Arquitetura de serviços que escala | `inventory/sites.yaml`, `infra/deploy.sh` (frota por sites) | ✅ |
| R2 | Identificação/registo escalável (name construction) | convenção `ssle:region:site:host:inst` + labels; registry HTTP SD (aula 2) | ✅ / 🧩 |
| R3 | Físico vs lógico | labels `host` (t490/mac-m2), `instance_name`, `project`, `role` | ✅ |
| R4 | Localização geográfica + delegação | projetos/redes Incus por site; grupos/`agent.conf` Wazuh; rotas Alertmanager por `team` | ✅ / 🧩 |
| R5 | (Bónus) monitorizar por localização poupando banda | Prometheus hierárquico; **federation só de agregados** (`site:up:ratio` visível no global) | ✅ |
| R6 | Localizar rapidamente a origem | labels em todos os alertas + **causa raiz** no `incidents.json` | ✅ |
| R7 | Prometheus (anomalias) + correlação p/ causa raiz | regras site; Alertmanager (inibição); **correlator** (RCA por grafo) | ✅ |
| R8 | FCAPS detetar→diagnosticar→correlacionar→resolver→post-mortem | detetar/correlacionar ✅; resolver (active-response) 🧩; post-mortem ✍️ | parcial |
| R9 | SIEM: 3 tipos de incidente + action-response | `siem/rules` (1101/1102/1103xx) + `siem/active-response` | 🧩 |
| R10 | SIEM: log management | `siem/shared/*/agent.conf` (localfile, FIM, portas) | 🧩 |
| R11 | Por ameaça: descrição…post-mortem | `threats/t1,t2,t3/README.md` | 🧩 / ✍️ |
| R12 | Conclusões (porque não é perfeita, futuro) | `report/` | ✍️ |
| R13 | Relatório estilo artigo/tese | `report/` | ✍️ |
| R14 | Demo + repositórios | este repo + `infra/demo.sh` | ✅ |

**Nota staging:** o SIEM (Wazuh, 4–6 GiB) e os sites `lis`/`opo`-extra não entram no perfil `staging`
para poupar RAM na VM arm64. Correm no T490 com `SSLE_PROFILE=full`.
