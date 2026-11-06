# Ameaça 3 — Junk e-mail (spam) + reputação

> Reaproveita a aula 8 (Postfix + SpamAssassin). Só é montada a stack no site `lis` (mail-01),
> que **não** faz parte do perfil `staging` (poupa RAM). Config como código aqui; corre no T490.

- **Deteção:** score do SpamAssassin (decoder `siem/decoders/ssle_spamassassin.xml`, regra 110301);
  frequência por remetente/IP no Postfix (110300); rejeições (110302). Prometheus: fila via
  *textfile collector* do node_exporter + molde de anomalia.
- **Resposta:** rate-limit no MTA (`anvil`, `smtpd_client_message_rate_limit`), recusa temporária
  (firewall-drop com timeout), lista de reputação (CDB `siem/lists/ssle-reputation` + RBL local),
  prevenção SPF/DKIM/DMARC.
- **PoC:** mensagens de teste ao próprio servidor, em volume limitado (ver aula 8 §5.2).
- **Post-mortem:** falsos positivos (ham→spam), efeito do rate-limit nos envios legítimos, caminho local como limitação.
