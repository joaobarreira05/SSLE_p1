# Ameaça 2 — Botnet sobre a frota IoT (Integridade → Disponibilidade)

> **Emulação benigna dos indicadores** (estilo purple-team/atomic). Sem código malicioso
> nem capacidade real de controlo. Objetivo: validar deteção → correlação → resposta.

- **Indicadores emulados num `sen-0x`:**
  1. logins SSH falhados repetidos (credenciais fracas) → Wazuh 110200;
  2. ficheiro "marcador" numa pasta de persistência (`/etc/cron.d/ssle-marker`) → FIM, Wazuh 110201;
  3. processo inofensivo com *beaconing* periódico a um endpoint interno que só responde 200
     → z-score de ligações/bytes no Prometheus; e, como o sensor passa a ser causa-raiz, Wazuh 110210.
- **Resposta:** `ssle-quarantine` (incus pause / mover para `net-quarentena`), bloquear destino (CDB),
  rodar credenciais, reimagem a partir do golden snapshot.
- **PoC:** `bash run.sh <sen-01> <projeto>`  (corre os 3 indicadores, com duração fixa).
- **Meta-correlação (1109xx):** o mesmo `sen-0x` aparece como origem de tráfego da Ameaça 1 → "uma botnet, dois impactos".
