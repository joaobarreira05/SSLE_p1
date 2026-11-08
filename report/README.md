# Relatório — estado das secções

Estrutura de artigo (plano §8; template e limite de páginas **por confirmar com o docente**). As secções são
Markdown em `sections/`, para converter depois (pandoc → LaTeX/PDF) para o template que o docente indicar.
Esqueleto completo em [`outline.md`](outline.md).

| Secção | Ficheiro | Estado |
|---|---|---|
| 1. Introdução | — | ✍️ por escrever |
| 2. Estado da arte | — | ✍️ por escrever |
| 3. Arquitetura de serviços | [`sections/03-arquitetura.md`](sections/03-arquitetura.md) | 🟡 rascunho (08/11) |
| 4. Gestão e mitigação de risco (ADTrees) | — | ✍️ por escrever |
| 5.1 Ameaça 1 — DoS/DDoS | [`sections/05-1-ameaca-dos.md`](sections/05-1-ameaca-dos.md) | 🟡 rascunho com dados de staging; falta a resposta (T490) |
| 5.2 Ameaça 2 — botnet | — | ✍️ depois da PoC |
| 5.3 Ameaça 3 — spam | — | ✍️ depois da PoC |
| 6. Avaliação | — | ✍️ (F4: eficácia, escala, largura de banda) |
| 7. Conclusões | — | ✍️ (as limitações já estão nos post-mortems e nos "Limites" de cada README) |

## Figuras (obrigatórias no plano §8)

| Figura | Ficheiro | Como se gera | Estado |
|---|---|---|---|
| Arquitetura | — | — | ✍️ |
| Topologia de nomes | [`figures/topologia.png`](figures/topologia.png) (+ `.svg`) | `python3 report/figures/build_topology.py` (do inventário) | ✅ |
| 3 ADTrees | — | — | ✍️ |
| Linha temporal de cada PoC | T1: tabela no post-mortem | — | 🟡 |
| Grafana durante uma PoC | [`figures/t1-replay-run1-dashboard.png`](figures/t1-replay-run1-dashboard.png) | `bash monitoring/grafana/replay-t1.sh 1` (**replay** de staging) | 🟡 (a definitiva sai do T490) |
| Largura de banda (federation) | — | F4 | ✍️ |
| Tabela de escala (10/25/50) | — | F4 | ✍️ |
