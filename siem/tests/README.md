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

## 2. Casos de regra — `cases.json` (25 casos, com asserções)

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
25/25 casos passaram      (desde 09/11: + vaga só com GTUBE; + sensor vítima da T1 SEM quarentena → 110211)
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

## 4. Integração com agentes reais — `it-agents.sh` (sem o lab Incus)

```bash
bash siem/tests/it-agents.sh            # ou: SSLE_IT=1 bash tools/test-all.sh   (~8 min, Docker + rede)
```

Manager `wazuh/wazuh-manager:4.14.10` + 5 contentores Debian trixie com **`wazuh-agent` 4.14.10 real**
(`core-obs`, `core-responder`, `avr-ing-01`, `opo-sen-01` e `lis-mail-01` com **Postfix + `spamd` reais** montados
por `threats/t3-spam/mail-setup.sh`) numa rede Docker própria, sem portas publicadas no host. Cada nó é instalado com **os mesmos scripts do `infra/deploy.sh`** — `siem/manager/configure-manager.sh`
(2 passagens: grupos antes das inscrições, respostas depois, com os IDs do `client.keys`) e
`siem/agent/install-agent.sh` — por isso o teste vale pelo deploy. O `incus` do responder é falso (regista os
argumentos). Output real (09/11/2026):

```text
[it] T2 no sensor (opo-sen-01)
  ✓ força bruta SSH (logger -t sshd, …) → 110200 L11 agent=opo-sen-01 labels=host=t490,instance=sen-01,region=pt,role=sensor,site=opo srcip=10.10.99.66 (tentativa 2)
  ✓ FIM em tempo real: marcador de persistência em /etc/cron.d → 110201 L12 agent=opo-sen-01 … path=/etc/cron.d/ssle-marker
  ✓ porta nova à escuta (31337) via comando remoto do agent.conf → 110202 L10 agent=opo-sen-01
[it] T1 no ing-01: white_list primeiro, depois a resposta (o ignore=60 da 110100 é por regra)
  ✓ o padrão de DoS vindo do prom-01 (10.10.1.10, na white_list) → 110100 L10 agent=avr-ing-01 srcip=10.10.1.10
  ✓ white_list: 10.10.1.10 alertou mas NÃO foi limitado
  ✓ 100 pedidos da mesma origem em 10 s (10.10.9.10) → 110100 L10 agent=avr-ing-01 srcip=10.10.9.10
  ✓ resposta executada NO ing-01: 10.10.9.10 no set nft inet ssle_rl limited
      2026-11-09T08:29:13+00:00 ssle-ratelimit[ing-01]: RATELIMIT add rule=110100 origem 10.10.9.10 → 20 lig./s (burst 40) na porta 8000
[it] T2 → quarentena (correlator no obs → 110210 → ssle-quarantine no responder)
  ✓ incidente do correlator: sensor sen-01 é a causa raiz → 110210 L12 agent=core-obs srcip=10.10.2.50
  ✓ resposta executada NO responder: incus pause t490:sen-01 --project site-opo
[it] meta-correlação ENTRE agentes (obs + ing-01): uma botnet, dois impactos
  ✓ sen-02 é causa raiz (obs) E origem de DoS (ing-01) → 110900 L14 agent=avr-ing-01 srcip=10.10.2.51
  ✓ quarentena do sen-02
[it] T3 no mail-01 (Postfix + spamd reais) + firewall-drop
      [t3] 1 spam + 0 relay para 172.19.0.7 → 250×1
  ✓ GTUBE aceite e marcada pelo spamd (score 1000) → 110304 L10 agent=lis-mail-01 | … (score 1002; testes ALL_TRUSTED,GTUBE,MISSING_DATE,…)
      [t3] 10 spam + 0 relay para 172.19.0.7 → 250×10
  ✓ vaga: mais 10 GTUBE em 2 min → 110300 L10 agent=lis-mail-01
      [t3] 0 spam + 5 relay para 172.19.0.7 → 554×5
  ✓ 5 relays recusados (554) a partir do obs → 110302 L10 agent=lis-mail-01 srcip=172.19.0.3
  ✓ firewall-drop executado NO mail-01: 172.19.0.3 bloqueado
        [t3] 1 spam + 0 relay para 172.19.0.7 → sem-ligação×1
[it] meta-correlação por relay (obs + mail-01): o sensor comprometido tenta usar o MTA
  ✓ sen-01 é a causa raiz (agente obs, srcip 172.19.0.6) → 110210 L12 agent=core-obs
  ✓ sen-01 é causa raiz (obs) E tenta relay no mail-01 → 110900 L14 agent=lis-mail-01 srcip=172.19.0.6
  ✓ firewall-drop NO mail-01 também pela 110900: 172.19.0.6 bloqueado
RESULTADO: integração SIEM OK ✅        (34 verificações; o desbloqueio automático, alerta 652, chega 600 s depois)
```

### O que a integração apanhou e o logtest não podia apanhar

| Defeito | Como se viu | Correção |
|---|---|---|
| A 110900 **nunca** correlacionava entre agentes | 110210 (agente `obs`) e 110100 (agente `ing-01`) com o mesmo `srcip`, 6 s de distância, e nada | no manager o estado das compostas é **por agente**: `<global_frequency/>` na 110900 (provado ao vivo) |
| O `ignore="60"` da 110100 é **por regra**, não por origem | a 2.ª origem em menos de 60 s não alertou (no logtest alertava: lá era o contador a esvaziar-se) | a 110101 (volume total) passou a ativar o modo "todas as origens" do `ssle-ratelimit` |
| A regex que tira as respostas sem agente engolia os `<command>` | 1.ª passagem: `ERROR: (1303): Invalid command 'ssle-ratelimit'` — o `configure-manager.sh` repôs o último estado bom | blocos ancorados ao início da linha + teste de regressão no `tools/test-all.sh` |
| FIM sem pasta para vigiar | `cannot create /etc/cron.d/ssle-marker: Directory nonexistent` | `install-agent.sh` cria `/etc/cron.d`, `/etc/systemd/system`, `/root/.ssh` nos sensores |
| Linhas perdidas no arranque | o rsyslog só cria o `auth.log` na 1.ª mensagem e o logcollector só lê o que chega depois de abrir | `touch` dos logs de cada papel antes de arrancar o agente; o teste repete o estímulo e di-lo ("tentativa 2") |
| A meta de um bot tapava a de **outro** durante 5 min | 110900 do `sen-02` (DoS) e, 2 min depois, nada para o relay do `sen-01` | o `ignore="300"` da 110900 é por regra: tirado (a quarentena já é deduplicada pelo `check_keys`) |
| Com a meta, o bot **continuava a enviar** | o alerta da filha 110900 substitui o da 110302 → o `firewall-drop` da 110302 não corria (`250×1` depois da meta) | `firewall-drop` (local) ligado também à 110900: bloqueia no alvo E isola na origem |
| Avisos transitórios tratados como erro | `wazuh-remoted: WARNING: (1246): Unable to send file 'merged.mg'` durante o restart | do `remoted` só contam `ERROR`/`CRITICAL` |

🎓 **Aprende:** o logtest testa **uma** sessão de **uma** origem. Tudo o que depende de vários agentes, do
tempo real (`ignore`, recargas) ou do sistema de ficheiros do agente só aparece com agentes a sério.

## 5. O que só se testa no lab (T490, perfil full)

- **`incus pause` a sério** (o certificado restrito do `responder`, `infra/deploy.sh` → `siem_responder`) e o
  `delete` ao fim do `timeout` (600 s / 300 s).
- **A cadeia Prometheus → correlator → Wazuh** com anomalias reais (no `it-agents.sh` a linha do correlator é
  escrita à mão) e os tempos (MTTD/MTTR) da T1 com resposta.
- **`wazuh-install.sh -a -i`** (manager + indexer + dashboard) no contentor `core/wazuh` (ubuntu/22.04).
