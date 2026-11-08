# Ameaça 1 — Interrupção massiva por DoS/DDoS (Disponibilidade)

> Estímulo **limitado, dentro do lab, com duração fixa** (aula 7). Nunca alvos externos.

- **Descrição/relevância:** o `ing-01` é a porta de entrada de todos os sensores de um site
  (ponto único de falha da disponibilidade). O `/work` é um endpoint deliberadamente caro.
- **Deteção (Prometheus, por instância — [`monitoring/site/rules/anomalies.yml`](../../monitoring/site/rules/anomalies.yml)):**
  1. `TrafficAnomaly` — z-score **robusto** (mediana + IQR da última hora) de `instance:http_requests:rate1m` > 3;
  2. `ServiceLatencyHigh` — p95 da latência servida acima do **SLO de 100 ms** (camada absoluta, servidor);
  3. `ClientLatencySLO` / `ClientUpstreamErrors` — o mesmo SLO **visto pelo sensor** (o servidor não vê a fila
     antes de atender: 23 ms vs 242 ms na PoC). O correlator junta o sintoma do sensor (`opo`) ao incidente do
     `ing-01` (`avr`) seguindo o grafo do inventário: 1 incidente, causa raiz `ing-01`.
  Linha de base = telemetria legítima dos sensores (`sen-0x` → `POST /ingest` a cada ~5 s).
  Wazuh (perfil `full`) — frequência por origem (regra 110100) e volume (110101).
- **Resposta:** rate-limit por origem, `firewall-drop` com timeout, degradação graciosa (503), escalar réplica.
  ⚠️ As respostas **por origem** exigem que o tráfego entre sites **não** passe por NAT (ver post-mortem).
- **PoC medida:** `bash measure.sh <n> [duração_s=120] [concorrência=20]` — corre o [`run.sh`](run.sh), espera a
  recuperação e calcula MTTD/impacto/recuperação a partir da série `ALERTS` e das métricas do sensor.
- **Resultados e post-mortem:** [`post-mortem.md`](post-mortem.md) · evidência em [`evidence/`](evidence/)
  ([`results.csv`](evidence/results.csv) + JSON de cada execução).

## Executar
```bash
# baseline: deixar os sensores a enviar ≥ 20 min antes da 1.ª execução
bash threats/t1-ddos/measure.sh 1 120 20
# só o estímulo, sem medição:
bash threats/t1-ddos/run.sh 10.10.1.30 120 20
```
