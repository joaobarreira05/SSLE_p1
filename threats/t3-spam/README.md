# Ameaça 3 — Junk e-mail (spam) + reputação

> Reaproveita a aula 8 (Postfix + SpamAssassin) no `lis/mail-01`, que **não** entra no perfil `staging`
> (poupa RAM). Tudo como código aqui; corre no T490 (`SSLE_PROFILE=full`) e é **provado sem o lab** pelo
> `siem/tests/it-agents.sh` (MTA e agente Wazuh reais em Docker).

| Ficheiro | O que faz |
|---|---|
| [`mail-setup.sh`](mail-setup.sh) | monta o MTA dentro do contentor (o deploy chama-o no papel `mail`): relay só para `mynetworks` (`reject_unauth_destination` → **554**), *content filter* `spamc`/`spamd` (utilizador `debian-spamd`), `anvil` (60 mensagens/ligações por minuto por cliente), **saída para fora desligada** (`default_transport = error`), fila do Postfix para o Prometheus (*textfile collector*, `postfix_queue_messages`) |
| [`smtp-poc.sh`](smtp-poc.sh) | cliente SMTP em **bash puro** (`/dev/tcp`), corre num sensor sem instalar nada: N mensagens com a **GTUBE** (cadeia de teste do SpamAssassin, inofensiva) + M tentativas de relay para `external.example` |
| [`run.sh`](run.sh) | a PoC no lab: `bash threats/t3-spam/run.sh sen-01 site-opo 10.10.3.70 11 5` |

## Deteção (Wazuh, validada no `wazuh-analysisd` real e com agente real)

| Sinal no `mail.log` | Regra |
|---|---|
| `spamd: result: Y 1000 - GTUBE,…` | 3501 → **110301** (spam) → **110304** (alta confiança, score ≥ 15) |
| ≥ 10 mensagens marcadas em 2 min | **110300** (vaga; conta pelo grupo `ssle_spam_msg`, porque a GTUBE acaba na 110304) |
| `NOQUEUE: reject: RCPT … 554 5.7.1 … Relay access denied` × 5 da mesma origem | 3301 → **110302** → `firewall-drop` (600 s) |
| rejeição a uma origem da lista `ssle-reputation` | **110310** (CDB) |
| a origem do relay é um sensor que o correlador apontou como causa raiz | **110900** (meta, entre agentes) → quarentena |

🧠 **Porquê o `reject_unauth_destination` explícito:** o Postfix vem com `defer_unauth_destination`, que
responde **450** (tenta mais tarde). Isso casa com a 3303 do *ruleset* e não com a 3301 em que a 110302 se
apoia: o relay seria recusado e o SIEM nunca o saberia.

## Resposta e prevenção

`firewall-drop` com *timeout* no `mail-01` (bloqueio temporário da origem), lista de reputação (CDB + RBL) e
*rate-limit* no MTA (`anvil`). Planeado: SPF/DKIM/DMARC contra o *spoofing*.

## Limites (post-mortem antecipado)

- **Caminho local:** a GTUBE prova a cadeia, não a qualidade do filtro. Spam real com Bayes por treinar tem
  falsos negativos, e baixar o `required_score` troca-os por falsos positivos (ham → spam).
- **Atacante que roda de IP:** o `firewall-drop` é por origem; contra isso, a reputação e o `anvil`.
- **After-queue:** o MTA aceita primeiro e filtra depois, por isso o spam já está na fila quando é detetado.
