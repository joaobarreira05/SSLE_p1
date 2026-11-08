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

## 2. Casos de regra (no manager do lab)

```bash
# 110000/110001: incidente crítico do correlator
cat incidents.jsonl | while read -r l; do echo "$l" | /var/ossec/bin/wazuh-logtest; done

# 110200: login falhado (repetir para passar a frequência)
echo "Jan  1 00:00:00 sen-01 sshd[1]: Failed password for root from 10.10.99.66 port 2222 ssh2" \
  | /var/ossec/bin/wazuh-logtest

# 110301: score do SpamAssassin
echo "Jan  1 00:00:00 mail-01 spamd[1]: spamd: result: Y 12 - ... score=12.3 required=5.0" \
  | /var/ossec/bin/wazuh-logtest
```
