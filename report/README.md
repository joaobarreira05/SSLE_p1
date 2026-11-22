# Report — section status

Article-style structure. The final report is in **LaTeX** (English) in [`latex/main.tex`](latex/main.tex) → `latex/main.pdf` (25 pages).

| Section | Status |
|---|---|
| 1. Introduction | updated (14/11) |
| 2. State of the art | reviewed and translated (14/11) |
| 3. Service architecture | reviewed and translated (14/11) |
| 4. Risk management and mitigation (ADTrees) | reviewed and translated (14/11) |
| 5.1 Threat 1 — DoS/DDoS | staging + T490 (14/11): SIEM response ~6 s, 6/6 TP |
| 5.2 Threat 2 — botnet | Docker + T490 (14/11): full chain, quarantine ~140 s |
| 5.3 Threat 3 — spam | Docker + T490 (14/11): firewall-drop + 110900 |
| 6. Evaluation | T490 (14/11): effectiveness T1-T3, correlation, SIEM, scale + bandwidth |
| 7. Conclusions | updated with T490 numbers (14/11) |

## Figures

| Figure | File | How to generate | Status |
|---|---|---|---|
| Architecture | [`figures/architecture.png`](figures/architecture.png) (+ `.svg`) | `python3 report/figures/build_architecture.py` (from inventory: 4 flows) | ✅ |
| Name topology | [`figures/topology.png`](figures/topology.png) (+ `.svg`) | `python3 report/figures/build_topology.py` (from inventory) | ✅ |
| 3 ADTrees | [`figures/adtree-t1.png`](figures/adtree-t1.png), [`t2`](figures/adtree-t2.png), [`t3`](figures/adtree-t3.png) (+ `.svg`) | `python3 report/figures/build_adtrees.py` (Kordy et al. notation; defences ✓ tested / ○ planned) | ✅ |
| Timeline per PoC | T1: table in post-mortem | — | — |
| Grafana during a PoC | [`figures/t1-replay-run1-dashboard.png`](figures/t1-replay-run1-dashboard.png) | `bash monitoring/grafana/replay-t1.sh 1` (**replay** from staging) | — (definitive from T490) |
| Federation bandwidth | table in [`../evaluation/federation-bytes.md`](../evaluation/federation-bytes.md) and §6.4 | `bash evaluation/federation-bytes.sh` (real Prometheus + exporters, N = 10/25/50) | ✅ |
| Lab scale (T490) | [`../evaluation/scale-t490-14nov.md`](../evaluation/scale-t490-14nov.md) | live measurement | ✅ |
