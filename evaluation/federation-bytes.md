# F4 — banda da federação: só agregados vs todas as séries

> Gerado por `bash evaluation/federation-bytes.sh` em 2026-11-09T10:56Z. Prometheus 2.53.5,
> regras de site reais, exporters reais (node_exporter + serviço Flask), N elementos por site. Método e limites
> no cabeçalho do script. Um pedido do global a cada 15 s = 4 pedidos/min por site.

| N elementos | séries (agregados) | séries (todas) | bytes/pedido agregados (texto · gzip) | bytes/pedido todas (texto · gzip) | poupança (gzip) | kB/min por site, agregados (gzip) |
|---|---|---|---|---|---|---|
| 10 | 25 | 8225 | 4075 · 443 | 1735507 · 64814 | 99.3 % | 1.8 |
| 25 | 55 | 20555 | 9220 · 689 | 4314936 · 150740 | 99.5 % | 2.8 |
| 50 | 105 | 41105 | 17795 · 1039 | 8614128 · 300763 | 99.7 % | 4.2 |

**Leitura.** As séries federadas são `2N + 5`: os **5** agregados de site (`site:*`, constantes com N) mais o
`up` de cada alvo (2 por elemento: node + serviço), que se manteve de propósito porque a análise de causa raiz
no global precisa de saber **qual** elemento caiu. Sem hierarquia, o central puxaria ~820 séries por elemento
(o node_exporter inteiro + os histogramas do serviço). A poupança fica acima de 99 % em todos os N e
**aumenta** com N, porque o lado agregado cresce 2 séries por elemento e o lado "tudo" cresce ~820.
