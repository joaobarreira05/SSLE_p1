# SSLE — Projeto 1: deteção, monitorização e prevenção de ameaças

Infraestrutura de larga escala **como código**: frota multi-site em contentores Incus, monitorização
com Prometheus **hierárquico** (por site + global que só federa agregados), correlação para **causa raiz**
e SIEM (Wazuh) com *action-response*. Tudo nasce de uma fonte única: [`inventory/sites.yaml`](inventory/sites.yaml).

## Arquitetura numa página

```
            core/obs ─ Prometheus global (federa só agregados) ─ Alertmanager ─ correlator (RCA) ─► incidents.json ─► Wazuh
               ▲ /federate 30s (poupa banda)                         ▲ inibição topológica        │ causa raiz
     ┌─────────┴─────────┐                                           │                            ▼ action-response (core/responder)
   site-avr            site-opo            site-lis
   prom-01             prom-01             prom-01
   ing-01→sto-01       sen-01..N           web-01, mail-01
   (scrape 15s, agregados, regras de anomalia/liveness)
```

Identidade única em Prometheus e Wazuh: `ssle:<region>:<site>:<host>:<instância>` (ex.: `ssle:pt:avr:t490:sto-01`).

## Reproduzir em 3 comandos

```bash
# 1) perfil reduzido (pouca RAM): 2 sites + core, 6 contentores
SSLE_PROFILE=staging bash infra/deploy.sh
# 2) ver a frota
incus list --all-projects
# 3) correr a demo de deteção → correlação → causa raiz
bash infra/demo.sh
```

No T490 (24 GB): `SSLE_PROFILE=full bash infra/deploy.sh` acrescenta os restantes sites e o Wazuh.

## O que a demo prova (já validado em staging, arm64)

- **Federation que poupa banda (R5):** o global vê `site:up:ratio` de cada site sem federar as séries em bruto.
- **Causa raiz (R6/R7):** parar `sto-01` gera `ElementDown` (sto-01) **e** `ServiceDegraded` (ing-01, que
  depende dele). O Alertmanager inibe sintomas da mesma máquina; o **correlator** junta os 2 alertas num **único
  incidente** com causa raiz `sto-01` (`noise_reduction=2.0`) e escreve-o em `incidents.json` (ponte para o Wazuh).

## Mapa do repositório

| Pasta | Conteúdo |
|---|---|
| `inventory/` | `sites.yaml` — fonte única |
| `infra/` | `inventory.py` (leitor portável), `deploy.sh`, `destroy.sh`, `demo.sh` |
| `monitoring/` | `site/` (prometheus+regras), `global/` (federation, alertmanager, compose), `tests/` (promtool), `grafana/` |
| `correlator/` | webhook → RCA por grafo → `incidents.json` + `/metrics` |
| `services/` | serviço Flask do lab (RED + saúde de dependências) |
| `siem/` | regras 1100xx–1109xx, decoders, listas CDB, `agent.conf` por grupo, active-response, testes logtest |
| `threats/` | t1-ddos, t2-botnet, t3-spam (PoCs limitadas + post-mortem) |
| `evaluation/`, `docs/`, `report/` | medição, rastreabilidade/ADR/horas, relatório |

## Segurança do lab
Estímulos **limitados e com duração fixa**, só em bridges internas; a botnet é **emulação benigna** de indicadores.
Sem alvos externos, sem floods reais. Respostas proporcionais, reversíveis e registadas (IPs do SOC em allow-list).

> Por confirmar com o docente: as 3 ameaças, o "banco de 168 h" e 3 sites emulados num só host.
