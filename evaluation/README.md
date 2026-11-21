# Evaluation (F4)
- **Effectiveness:** FP/TP per threat (baseline without attack vs with attack).
- **Scale:** repeat with 10/25/50 elements (add lines to the inventory) and measure CPU/RAM/scrape usage.
- **Bandwidth (bonus):** federated `bytes` with vs without aggregation (compare `/federate` with direct scrape).
- **MTTD/MTTR:** `measure.sh <epoch>` after each PoC; mean of 3 runs.
