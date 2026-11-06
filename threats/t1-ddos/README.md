# Ameaça 1 — Interrupção massiva por DoS/DDoS (Disponibilidade)

> Estímulo **limitado, dentro do lab, com duração fixa** (aula 7). Nunca alvos externos.

- **Descrição/relevância:** o `ing-01` é a porta de entrada de todos os sensores de um site
  (ponto único de falha da disponibilidade). O `/work` é um endpoint deliberadamente caro.
- **Deteção:** Prometheus — `site_service:http_requests:rate5m` sobe e o z-score (`TrafficAnomaly`)
  passa de 3; p95 e rácio 5xx acima do SLO. Wazuh — frequência por origem (regra 110100) e volume (110101).
- **Resposta:** rate-limit por origem, `firewall-drop` com timeout, degradação graciosa (503), escalar réplica.
- **PoC:** `bash run.sh <ip_do_ing-01> [duração_s] [concorrência]`
- **Post-mortem:** preencher `post-mortem.md` (MTTD, MTTR, dano colateral, falsos positivos).

## Executar
```bash
IP=$(incus list --project site-avr --format csv -c 4 ing-01 | cut -d' ' -f1)
bash run.sh "$IP" 120 20
# observar:
curl -s "http://$(cut -f3 ../../build/obs.tsv 2>/dev/null):9090/api/v1/query?query=site_service:http_requests:rate5m" | jq .
```
