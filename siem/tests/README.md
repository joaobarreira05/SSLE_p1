# Validar as regras com wazuh-logtest (no manager)

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
