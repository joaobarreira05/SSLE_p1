# ADR-0001 — Decisões de arquitetura do Projeto 1

- **T490 = produção/demo; Mac(VM arm64) = desenvolvimento/staging.** Não por ARM (Wazuh/Prometheus
  correm em arm64), mas por RAM/disco. Tudo é config-como-código, portável entre os dois.
- **Identidade única** `ssle:region:site:host:instância`, as mesmas labels em Prometheus e Wazuh.
- **Prometheus hierárquico:** um por site (scrape 15 s, agregados) + um global que **só federa agregados**
  (poupa banda — R5).
- **Correlação em 2 níveis:** Alertmanager (inibição topológica, mesma máquina/sítio) + **correlator**
  (RCA por grafo de dependências, entre elementos). Reduz N alertas a 1 incidente com causa raiz.
- **Ponte Prometheus→Wazuh:** o correlator escreve `incidents.json`; um agente Wazuh lê o ficheiro.
- **Respostas** no `core/responder` com certificado Incus **restrito** aos projetos dos sites (mínimo privilégio).
- **Staging:** IPs estáticos por NIC + encaminhamento entre bridges do host (evita DNS multi-bridge);
  stack global por **apt** (mais leve). Produção no T490 pode usar o **docker-compose** (Prometheus v3 + Grafana).
