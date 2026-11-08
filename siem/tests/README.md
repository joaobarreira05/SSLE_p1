# Validar o SIEM-como-código

## 1. Carregamento no manager real (sem lab) — `run-logtest.sh`

```bash
bash siem/tests/run-logtest.sh                 # ou: SSLE_LOGTEST=1 bash tools/test-all.sh
```

Sobe um `wazuh/wazuh-manager:4.14.10` **descartável** (`--network none`, `--memory 1g`), copia
`siem/rules`, `siem/decoders` e `siem/lists`, reinicia o manager e **falha** se o `wazuh-analysisd` se queixar.
Se existir `siem/tests/cases.json`, corre-o pelo socket do logtest (`logtest_cases.py`, sessões com estado).

🧠 **Porquê isto importa:** uma única regra inválida faz o analysisd **recusar o `local_rules.xml` inteiro**
(`CRITICAL: (1220): Error loading the rules`). No T490 isso seria um SIEM a correr **sem nenhuma** regra do
projeto — e sem erro visível no dashboard. Foi o que esta validação apanhou em 08/11/2026 (output real):

```text
wazuh-analysisd: ERROR: Failure to read rule 110002. Field 'status' is static.
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
   → corrigido: <status>^resolved$</status> (status, srcip, id, url… são campos ESTÁTICOS: etiqueta própria)

wazuh-analysisd: ERROR: (5107): Syntax error on tag 'root_cause_role' in rule 110110
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
   → corrigido: ^ingestion$|^web$ (o OS_Regex não tem grupos ( ) nem classes [ ]); a 110301 passou a PCRE2
```

Depois das correções:

```text
[logtest] a carregar siem/ no manager (v4.14.10)
  ✓ regras, decoders e listas carregados sem erros nem avisos
wazuh-analysisd: INFO: Total rules enabled: '8468'
```

🎓 **Aprende:** o motor por omissão das regras Wazuh é o **OS_Regex** (herdado do OSSEC): `\d`, `\w`, `\S`, `\.`
(qualquer carácter), `^`, `$` e `|` entre padrões inteiros — **sem** `[...]`, `(...)` nem *backtracking*. Para
mais do que isso: `type="pcre2"` no `<field>`/`<regex>`/`<match>`.

## 2. Casos de regra — `cases.json` (23 casos, com asserções)

O `run-logtest.sh` corre cada caso numa **sessão** do logtest (o estado de `frequency`/`if_matched_*` acumula-se
como no manager a sério) e compara regra, nível, decoder e campos. Há casos **negativos** (o que NÃO pode
alertar) ao lado de cada positivo — sem eles, uma regra que dispara sempre passaria no teste.

```text
  ✓ T1: 100 pedidos da mesma origem em 10 s — regra 110100 (no evento 100)
  ✓ T1: 60 pedidos da mesma origem não chegam (sem falso positivo) — regra 110105
  ✓ T2: 8 passwords erradas da mesma origem (como o threats/t2-botnet/run.sh) — regra 110200
  ✓ T2: porta nova à escuta (533 → 110202) — regra 110202
  ✓ T3: GTUBE (score 1000) → alta confiança — regra 110304
  ✓ T3: linha 'identified spam' não duplica o alerta — sem alerta
  ✓ meta: sensor comprometido E origem de relay → uma botnet, dois impactos — regra 110900
  ✓ meta: relay de OUTRA origem não correlaciona com o sensor — regra 110302
  …
23/23 casos passaram
```

### Defeitos que os casos apanharam (08/11/2026, manager 4.14.10 real)

| Regra | Sintoma no logtest | Causa | Correção |
|---|---|---|---|
| 110301 (spam) | o `spamd` dava sempre **3501, nível 0**, campos vazios | (1) o decoder procurava `score=… required=…`, que o `spamd` não escreve; (2) a raiz **3500** do ruleset casa `^spamd` primeiro, por isso uma regra de topo com `decoded_as` nunca ganhava | decoder para `result: Y 6 - TESTES …required_score=5.0` e `identified spam (6.2/5.0)`; 110301 passa a **filha da 3501** e usa o veredito `Y` do próprio SpamAssassin |
| 110100/110101 (T1) | 120 pedidos e **nunca** disparava | os pedidos 200 acabam na **31108 (nível 0)** e o analysisd **descarta eventos de nível 0** antes de os guardar para `if_matched_sid` | regra-base **110105 de nível 1** (guarda-se, mas fica abaixo do `log_alert_level`=3: não enche o `alerts.json`) |
| 110100 (T1) | o log do Flask não decodificava | o werkzeug escreve `[08/Nov/2026 20:00:00]`; o decoder `web-accesslog` quer o formato *combined* | `SSLE_ACCESS_LOG` no `services/app.py` (formato combined, rodado a 10 MiB × 2) |
| 110200 (T2) | apontava à 5710 sozinha; o `run.sh` usava `logger` sem `-t sshd` | sem etiqueta, o `program_name` é `root` e o decoder sshd nunca a vê | filha das compostas **5712/5720/5763** (dispara ao 8.º evento, provado) + `logger -t sshd` |
| 110202 (T2) | o comando corria mas nenhuma regra o via | a 533 só casa o alias exato `netstat listening ports` | `agent.conf` do `role-sensor` com esse alias, só TCP e sem pid (evita falsos positivos do `check_diff`) |
| 110900 (meta) | contava 2 incidentes do **mesmo** sensor (não juntava ameaças) | — | padrão da **40112**: `if_group ssle_impact` + `if_matched_group ssle_botnet_host` + `same_source_ip`; o correlator passou a pôr `srcip` = IP da causa raiz |
| `ossec-ssle.conf` | ao **acrescentar** outro `<ossec_config>` com `<ruleset>`, `WARNING: (7616): List 'etc/lists/amazon/aws-eventnames' could not be loaded. Rule '80202' will be ignored.` | um 2.º `<ruleset>` **substitui** as listas por omissão — o SIEM fica com buracos **sem erro fatal** | `siem/manager/apply.py` **funde** `white_list`/`list` nas secções existentes (entre marcadores, idempotente); só `command`/`active-response` vão num bloco à parte |

🎓 **Aprende:** num SIEM, "a regra carrega" não quer dizer "a regra dispara". Dos 7 defeitos acima, **só 2**
davam erro ao carregar (secção 1); os outros 5 eram regras válidas que **nunca** disparavam — o pior tipo de
falha num sistema de deteção, porque não se vê.

## 3. Respostas (active-response) — `siem/active-response/test-ar.sh`

Sem root e sem lab: `ssle-quarantine` com um `incus` **falso** no PATH (só regista os argumentos) e o mapa da
frota real do inventário; `ssle-ratelimit` com **nft real** num namespace de rede próprio (`unshare -rn`: só
é root lá dentro, a firewall do host não é tocada). Output real:

```text
[ssle-quarantine] incus falso + mapa da frota do inventário
  ✓ 110210 sensor sen-01 (opo) → incus pause t490:sen-01 --project site-opo
  ✓ 110900 meta por srcip 10.10.2.51 → incus pause t490:sen-02 --project site-opo
  ✓ causa raiz no storage (sto-01) é RECUSADA (nada executado)
  ✓ nome injetado ('sen-01; reboot') não resolve (nada executado)
  ✓ execd não responde (falha fechada) (nada executado)
[ssle-ratelimit] nft real num namespace de rede próprio (unshare -rn)
  ✓ sem limite: 40/40 ligações aceites
  ✓ com limite (5/s, burst 10): 29/40 aceites em 4 s (teto do balde: 31) — o excesso foi descartado
  ✓ delete → set vazio e 40/40 outra vez
  ✓ 110110 para web-01 no ing-01 → ignorado
```

🧠 **Porquê a 110110 (T1) limita e não isola:** na T1 a causa raiz é a **vítima** (`ing-01`). Pô-la em
quarentena seria fazer o DoS pelo atacante. A quarentena (`incus pause`, preserva o estado para a forense)
fica só para **sensores** (110210, 110900) — e o script confirma-o no mapa da frota, não no que vem no alerta.

## 4. O que só se testa no lab (T490, perfil full)

- **110201 (FIM):** o logtest não injeta eventos de syscheck. No lab: `bash threats/t2-botnet/run.sh sen-01
  site-opo` cria `/etc/cron.d/ssle-marker` → alerta 110201 no `alerts.json` do manager.
- **Respostas a sério:** `active-responses.log` no `core/responder` (`incus pause`) e no `ing-01` (`nft list
  table inet ssle_rl`), e o `delete` ao fim do `timeout`.
- **`white_list`:** confirmar que um alerta com `srcip` do core não gera resposta.
