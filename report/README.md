# Relatório — estado das secções

Estrutura de artigo. As secções originais estão em Markdown em `sections/` (português).
O relatório final está em **LaTeX** (inglês) em [`latex/main.tex`](latex/main.tex) → `latex/main.pdf` (25 páginas).
Esqueleto original em [`outline.md`](outline.md).

| Secção | Ficheiro | Estado |
|---|---|---|
| 1. Introdução | [`sections/01-introducao.md`](sections/01-introducao.md) | 🟢 atualizado (14/11) |
| 2. Estado da arte | [`sections/02-estado-da-arte.md`](sections/02-estado-da-arte.md) | 🟢 revisto e traduzido (14/11) |
| 3. Arquitetura de serviços | [`sections/03-arquitetura.md`](sections/03-arquitetura.md) | 🟢 revisto e traduzido (14/11) |
| 4. Gestão e mitigação de risco (ADTrees) | [`sections/04-risco.md`](sections/04-risco.md) | 🟢 revisto e traduzido (14/11) |
| 5.1 Ameaça 1 — DoS/DDoS | [`sections/05-1-ameaca-dos.md`](sections/05-1-ameaca-dos.md) | 🟢 staging + T490 (14/11): resposta SIEM ~6 s, 6/6 TP |
| 5.2 Ameaça 2 — botnet | [`sections/05-2-ameaca-botnet.md`](sections/05-2-ameaca-botnet.md) | 🟢 Docker + T490 (14/11): cadeia completa, quarentena ~140 s |
| 5.3 Ameaça 3 — spam | [`sections/05-3-ameaca-spam.md`](sections/05-3-ameaca-spam.md) | 🟢 Docker + T490 (14/11): firewall-drop + 110900 |
| 6. Avaliação | [`sections/06-avaliacao.md`](sections/06-avaliacao.md) | 🟢 T490 (14/11): eficácia T1-T3, correlação, SIEM, escala + banda |
| 7. Conclusões | [`sections/07-conclusoes.md`](sections/07-conclusoes.md) | 🟢 atualizado com números do T490 (14/11) |

## Figuras (obrigatórias no plano §8)

| Figura | Ficheiro | Como se gera | Estado |
|---|---|---|---|
| Arquitetura | [`figures/arquitetura.png`](figures/arquitetura.png) (+ `.svg`) | `python3 report/figures/build_architecture.py` (do inventário: 4 fluxos) | ✅ |
| Topologia de nomes | [`figures/topologia.png`](figures/topologia.png) (+ `.svg`) | `python3 report/figures/build_topology.py` (do inventário) | ✅ |
| 3 ADTrees | [`figures/adtree-t1.png`](figures/adtree-t1.png), [`t2`](figures/adtree-t2.png), [`t3`](figures/adtree-t3.png) (+ `.svg`) | `python3 report/figures/build_adtrees.py` (notação Kordy et al.; defesas ✓ testadas / ○ planeadas) | ✅ |
| Linha temporal de cada PoC | T1: tabela no post-mortem | — | 🟡 |
| Grafana durante uma PoC | [`figures/t1-replay-run1-dashboard.png`](figures/t1-replay-run1-dashboard.png) | `bash monitoring/grafana/replay-t1.sh 1` (**replay** de staging) | 🟡 (a definitiva sai do T490) |
| Largura de banda (federation) | tabela em [`../evaluation/federation-bytes.md`](../evaluation/federation-bytes.md) e §6.4 | `bash evaluation/federation-bytes.sh` (Prometheus + exporters reais, N = 10/25/50) | ✅ (tabela; gráfico opcional) |
| Tabela de escala (lab, T490) | [`../evaluation/scale-t490-14nov.md`](../evaluation/scale-t490-14nov.md) | medição ao vivo | ✅ |
