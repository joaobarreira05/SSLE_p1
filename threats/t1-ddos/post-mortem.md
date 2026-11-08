# Post-mortem — Ameaça 1 (DoS de aplicação ao `avr/ing-01`) · staging arm64 · 2026-11-06

> *Blameless*, no molde do plano §4.7. Execuções medidas por [`measure.sh`](measure.sh); evidência bruta em
> [`evidence/`](evidence/) (um diretório por execução + [`results.csv`](evidence/results.csv)).
> **Ambiente:** perfil `staging` (VM Debian arm64, 6 contentores), **sem Wazuh** (só no perfil `full`, T490) —
> por isso aqui não há resposta automática: estas execuções são o **grupo de controlo** (deteção + impacto sem
> mitigação) contra o qual se mede a resposta no T490.

## Descrição
DoS **de aplicação** (aula 7): muitos pedidos concorrentes ao endpoint mais caro do serviço de ingestão
(`/work`, ~6 ms de CPU por pedido em repouso). Classificação nos 3 eixos da aula 7: camada **aplicação (L7)** ·
origem **única** (o host do lab; a variante distribuída fica para o T490 com `kali-01` + clientes em 2–3 sites) ·
padrão **constante** durante uma janela fixa.

## Relevância
O `ing-01` é a **porta de entrada de todos os sensores** (ponto único de falha da disponibilidade — CIA: **A**).
Se a ingestão abranda, a telemetria dos sites (aqui, `opo/sen-01`) atrasa ou perde-se, sem que nenhum sensor
esteja avariado — é exatamente o cenário em que um operador sem correlação procuraria o problema no sítio errado.

## Exploração / PoC
Estímulo **limitado e com duração fixa** ([`run.sh`](run.sh)): `CONC` ciclos `curl` em paralelo contra
`http://ing-01:8000/work` durante `DUR` segundos, só em bridges internas do lab. **Sem aumentar a carga do guião.**

## Métricas
| Sinal | Série | Porquê |
|---|---|---|
| Taxa (R de RED) | `instance:http_requests:rate1m` | entrada do z-score robusto (`TrafficAnomaly`) |
| Latência (D de RED) | `instance:http_request_duration_seconds:p95_1m` | o SLO de 100 ms (`ServiceLatencyHigh`) |
| Impacto no cliente legítimo | p95 de `ssle_sensor_upstream_duration_seconds` (sensor de `opo`) | o que a frota sente; define a **recuperação** |
| Erros vistos pelo cliente | `ssle_sensor_readings_total{result="error"}` | leituras perdidas (timeout 5 s) |
| Chegada ao SOC | `incidents.json` do correlator (`ts`, `root_cause`) | MTTD ponta-a-ponta |

**Definições.** **MTTD** = 1.º instante em que a regra está `firing` − T0 (início do estímulo).
**Recuperação** = último instante com p95 do sensor > SLO − T1 (fim do estímulo). Sem resposta automática, o
"MTTR" de staging é **o tempo que o sistema leva a recuperar sozinho depois de o ataque parar** — a linha de base
que a resposta automática (T490) tem de bater.

## Respostas / mitigação
**Staging:** nenhuma automática (grupo de controlo). **T490 (`full`):** por ordem de proporcionalidade —
(1) *rate-limit* por origem; (2) `firewall-drop` com `timeout`; (3) degradação graciosa (503 rápido em `/work`);
(4) 2.ª réplica atrás do registry. **Bloqueio encontrado nesta PoC (ver "O que correu mal"): as respostas
por origem não são seguras enquanto houver NAT entre sites.**

## Post-mortem da PoC

### Resumo
3 execuções iguais (120 s × 20 ciclos `curl`, ~160 pedidos/s contra uma linha de base de 0,2/s). O
`TrafficAnomaly` (z-score robusto) detetou **3/3** com **MTTD = 81,7 ± 2,9 s** e **0 falsos positivos** em 56 min
de observação; o correlator abriu **1 incidente por execução** com a **causa raiz certa** (`ing-01`) aos
**92,9 ± 0,1 s**. A camada absoluta (`ServiceLatencyHigh`) **falhou 3/3** — e a razão é a lição principal desta PoC.

### Linha temporal (execução 1; as outras diferem ≤ 5 s)
| Instante | Evento | Fonte |
|---|---|---|
| **T0** 15:24:10 | início do estímulo | `run.log` |
| T0 + 20 s | **impacto**: p95 visto pelo sensor passa o SLO (100 ms) | `p95-sensor.json` |
| T0 + 25 s | **1.º sinal**: `TrafficAnomaly` em *pending* (z ≈ 320) | `alerts-TrafficAnomaly-pending.json` |
| T0 + 85 s | **deteção**: `TrafficAnomaly` *firing* (`for: 1m`) → **MTTD** | `alerts-TrafficAnomaly-firing.json` |
| T0 + 93 s | **incidente no SOC**: correlator, causa raiz `ssle:pt:avr:mac-m2:ing-01` | `incidents.json` (correlator) |
| T2 | alerta no Wazuh | — (sem Wazuh em staging) |
| T3 | resposta aplicada | — (grupo de controlo) |
| **T1** = T0 + 120 s | fim do estímulo | `run.log` |
| T1 + 45 s | **recuperação**: p95 do sensor volta abaixo do SLO | `p95-sensor.json` |
| T1 + 65 s | alerta resolvido | série `ALERTS` |

### Resultados das 3 execuções
| execução | T0 | taxa pico (pedidos/s) | 1.º sinal (s) | **MTTD regra (s)** | **MTTD SOC (s)** | z robusto máx. | z média/desvio máx. | média/desvio dispararia? | p95 servidor máx. (ms) | `ServiceLatencyHigh` | **p95 sensor máx. (ms)** | recuperação após estímulo (s) | leituras perdidas | causa raiz (SOC) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 15:24:10 | 160,2 | 25 | 85 | 93,0 | 320,0 | 7,6 | **sim** | 23,0 | não | 242,5 | 45 | 0 | `ing-01` |
| 2 | 15:43:15 | 162,2 | 20 | 80 | 92,9 | 323,9 | 3,3 | **não** | 23,2 | não | 242,5 | 45 | 0 | `ing-01` |
| 3 | 15:53:15 | 157,9 | 20 | 80 | 92,9 | 315,4 | 2,8 | **não** | 23,3 | não | 242,5 | 45 | 0 | `ing-01` |
| **média ± σ** | | 160,1 ± 2,2 | 21,7 ± 2,9 | **81,7 ± 2,9** | **92,9 ± 0,1** | 319,8 ± 4,3 | 4,6 ± 2,6 | 1/3 | 23,2 ± 0,2 | 0/3 | 242,5 | 45,0 | 0 | 3/3 |

Gerada por [`analyze.py`](analyze.py) → [`evidence/results.md`](evidence/results.md). **Eficácia do `TrafficAnomaly`:
TP = 3 · FP = 0 · FN = 0** (todos os intervalos *firing* entre 15:10 e 16:06 caem dentro de uma execução —
[`evidence/alerts-1510-1606.json`](evidence/alerts-1510-1606.json)). **Precisão das medidas:** T0/T1 ao segundo,
consultas a 5 s, avaliação das regras a 15 s → ±15 s no MTTD. O MTTD é dominado pelo `for: 1m` (o 1.º sinal chega
aos ~22 s): é o preço, escolhido, de não alertar por um pico de um minuto.

### Deteção — o que disparou, o que não disparou e porquê
1. **`TrafficAnomaly` (relativa) — 3/3.** z ≈ 320 ≫ 3: com uma linha de base de 0,2 pedidos/s e o mínimo de
   dispersão de 0,5, este estímulo não é subtil. ✅
2. **Contraprova ao vivo — a versão média/desvio-padrão só teria detetado a 1.ª execução.** Na 2.ª (19 min depois)
   e na 3.ª (29 min depois) o ataque anterior ainda estava dentro da janela de 1 h e tinha inflacionado o σ:
   z máx. 3,3 e 2,8, nunca acima de 3 durante 1 min → **2 falsos negativos evitados** pela mediana + IQR. É o
   que o teste [`anomaly_test.yml`](../../monitoring/tests/anomaly_test.yml) prova em laboratório (z 39,6 vs ≈2,0);
   aqui confirma-se com tráfego real. *(Um atacante que repete o ataque ganharia invisibilidade com a versão antiga.)*
3. **`ServiceLatencyHigh` (absoluta) — 0/3. Ponto cego.** O p95 **medido dentro da app** nunca passou de 23 ms,
   mas o sensor viu **242,5 ms** (≈ 27× a média em repouso, 8,8 ms). O histograma do servidor começa a contar
   quando o Flask já está a tratar o pedido; a espera **antes** disso (aceitar a ligação, criar a *thread*,
   disputar o GIL com 20 pedidos caros) fica de fora — e é precisamente essa fila que o cliente sente.
   🎓 **Lição:** um SLO de latência tem de ser medido **do lado do cliente** (sondas *blackbox* ou a telemetria do
   próprio cliente), não só pela instrumentação do servidor.

### Impacto
Degradação, não indisponibilidade: o p95 dos sensores subiu de ~10–46 ms para **242,5 ms** desde T0 + 20 s e
**nenhuma leitura se perdeu** (o *timeout* do sensor é 5 s). Recuperação **45 s depois do fim do estímulo** (as
janelas de 1 min das taxas). ⚠️ O valor 242,5 ms é igual nas 3 execuções porque o `histogram_quantile` interpola
dentro do *bucket* 100–250 ms: a resolução do p95 está limitada pelos *buckets*.

### Resposta
Nenhuma automática (grupo de controlo). **O que a resposta no T490 tem de bater:** recuperação = fim do ataque
+ 45 s; dano colateral = 0 leituras perdidas.

### Causa raiz — a calculada e a verdadeira
O correlator apontou `ssle:pt:avr:mac-m2:ing-01` nas 3 execuções: **certo quanto ao elemento afetado**. A causa
verdadeira é a **carga externa** que chega ao `ing-01`, e essa origem o sistema **não consegue atribuir** (ver 1.
abaixo): o correlator responde "*onde* dói", não "*quem* bate".

### O que correu mal ou é frágil
1. **NAT entre sites esconde a origem.** O tráfego entre bridges passa pelo *masquerade* do Incus
   (`ipv4.nat=true`): o `ing-01` vê o sensor de `opo` **e** o atacante como `10.10.1.1`. Uma resposta por origem
   (`firewall-drop`, *rate-limit*) **cortaria também a frota legítima**, e o Wazuh não conseguiria atribuir o ataque.
   ➜ Tirar o NAT do tráfego **interno** 10.10.0.0/16 (mantê-lo só para a Internet). Mexe na firewall do host →
   decidir com o João antes.
2. **Ponto cego do SLO do lado do servidor** (acima, Deteção 3).
3. **Antes desta PoC havia um falso negativo total:** o `ing-01` não tinha tráfego e o contador só nascia no 1.º
   pedido, por isso a 1.ª amostra do ataque era também a baseline (z ≈ 0). Corrigido com a telemetria dos
   sensores e o contador pré-inicializado (commit `be88daa`).
4. **Correlação só dentro do site.** Se o sensor de `opo` alertasse (o sintoma do cliente), o correlator abriria
   um 2.º incidente em `opo` com causa raiz errada (`sen-01`), porque não segue a aresta `sen-01 → ing-01@avr`
   entre sites.
5. **Flash crowd vs ataque.** Com a dispersão mínima de 0,5 pedidos/s, um aumento legítimo da frota (p. ex., +10
   sensores) também dispararia. O plano (§4.2) previa exigir **3 sinais** (z + p95 + 5xx), mas o servidor de
   desenvolvimento do Flask **não devolve 5xx sob carga** (faz fila): não há o 3.º sinal.
6. **Lab num só host.** O atacante (o host) e o alvo partilham CPU; e a VM esteve em pausa entre 15:37 e 15:41
   (buraco nas séries) — **fora** das janelas medidas, mas é um lembrete de que o staging não é a produção.

### Ações futuras
- [x] **SLO do lado do cliente** (08/11, T490): regra `ClientLatencySLO` (p95 do sensor > 100 ms durante 1 min) e
      `ClientUpstreamErrors` (> 50 % das leituras falham) em
      [`anomalies.yml`](../../monitoring/site/rules/anomalies.yml), testadas do histograma em bruto até ao alerta
      ([`client_slo_test.yml`](../../monitoring/tests/client_slo_test.yml): reproduz os 242,5 ms). **Análise
      retroativa** sobre a evidência guardada (`analyze.py --offline`): teria disparado em **T0 + 80 s nas 3/3**
      execuções (contra 0/3 do `ServiceLatencyHigh`); em repouso o p95 do sensor nunca passou de 38,7 ms.
      ⚠️ É uma simulação do `for: 1m` sobre a série a 5 s, **não** uma medição ao vivo — mede-se no T490.
- [x] **Correlação entre sites** (08/11): o núcleo do correlator ([`rca.py`](../../correlator/rca.py)) deixou de
      agrupar por `site` e passou a fazer **cobertura gulosa do grafo** (que atravessa sites): o sintoma do sensor
      de `opo` junta-se ao incidente do `ing-01` de `avr` → **1 incidente, causa `ing-01`, `cross_site=true`**.
      Bónus: duas falhas independentes passam a dar dois incidentes (antes, o que o melhor candidato não explicava
      ficava de fora). Testes em [`test_rca.py`](../../correlator/test_rca.py).
- [x] **Risco novo encontrado ao fazer o ponto anterior** (08/11): se o alerta do sensor chegar ao SOC antes do
      alerta do servidor, o correlator emitia "causa raiz = sensor" — e a regra Wazuh 110210 trata isso como
      candidato a **quarentena** (um sensor legítimo isolado por causa de um DoS ao servidor). Corrigido com uma
      **janela de estabilização** (`CORRELATOR_SETTLE=30` s): uma causa raiz nova só sai quando o sintoma mais
      antigo tem 30 s. Custo: +≤ 30 s no MTTD do SOC (troca escolhida: precisão > rapidez). O teste
      `test_without_settle_the_sensor_would_be_blamed` prova o problema e `test_client_first_never_blames_the_sensor`
      prova a correção.
- [ ] **NAT só para a Internet** (preserva o IP de origem dentro do lab) — com confirmação.
- [ ] **T490 (`full`):** Wazuh 110100/110101 + resposta proporcional (*rate-limit* → `firewall-drop` com
      `timeout`) e comparar a recuperação com estes 45 s; variante **distribuída** a partir do `kali-01` e de
      clientes em 2–3 sites; `limits.cpu=1` no `ing-01`, como na aula 7.
- [ ] Servir com `gunicorn` (respostas 503 sob saturação) para ter o 3.º sinal e distinguir *flash crowd*.
