# Registry de site (R2) — registo dinâmico + HTTP SD

> **Requisito R2:** *identificação e registo escaláveis* dos elementos. Na aula 2 o registry era um dicionário
> em memória com *health-check* ativo e *round-robin*. Aqui é o **`reg-01` de cada site**, que acrescenta o que
> falta para larga escala e para segurança. A identidade é a mesma em todo o lado:
> `ssle:<region>:<site>:<host>:<name>`.

## Como encaixa

```
 elemento novo (fora do inventário)                 reg-01 do site (registry/app.py :5050)
  services/app.py  ── POST /register (token) ──►   valida nome/papel/site/sub-rede/identidade
  (heartbeat 10 s)                                   lease com TTL 30 s  ──►  GET /sd/node, /sd/services
                                                                                     │ HTTP SD (15 s)
 elementos do INVENTÁRIO ── file_sd (estático) ──►  prom-01 do site  ◄──────────────┘
                                                     (relabel → job="node"/"services": as MESMAS regras)
```

| Aula 2 | Aqui | Porquê |
|---|---|---|
| registo sem autenticação | escrita só com **token do site** (`hmac.compare_digest`), gerado no deploy (`build/secrets/`, fora do Git; `0600` no contentor) | toda a escrita exige autenticação; sem token configurado o registry é **só de leitura** (falha fechada) |
| qualquer nome/URL | nome `^[a-z]{3}-\d{2}$`, papel numa lista, **site = o do registry**, IP **na sub-rede do site** | delegação (R4): um site não regista elementos de outro; entrada inválida → recusa |
| — | reclamar a identidade de um elemento do inventário com **outro IP** → `409` | um contentor comprometido não se faz passar pelo `sen-01` |
| *health-check* ativo a cada 5 s | **lease com TTL** renovado pelo próprio elemento | escala: o registry não faz N pedidos por ciclo; um elemento que morre desaparece sozinho |
| round-robin para clientes | mantém-se (`/services/<papel>`) **+ HTTP SD** para o Prometheus | o mesmo registo serve a descoberta de serviços **e** a monitorização |
| — | `/metrics`: `site_info{city,lat,lon}`, instâncias estáticas/dinâmicas, rejeições por motivo | Geomap no Grafana; rejeições `auth` são um sinal de segurança |

🧠 **Falha segura:** os elementos do inventário são lidos por `file_sd` e o HTTP SD devolve **só** os
registados dinamicamente. Se o `reg-01` cair, a frota de base continua monitorizada e o Prometheus mantém os
últimos alvos do SD — perde-se, no máximo, a descoberta de elementos **novos**.

## Prova (teste de integração, sem lab) — `bash registry/it-local.sh`

Registry real + `services/app.py` real (sensor dinâmico `sen-07`) + **Prometheus 2.53.5** real com o
`prometheus.yml` do site `opo` renderizado pelo inventário (`infra/inventory.py siteprom`), tudo em
`127.0.0.1`. Output real (08/11/2026):

```text
[it] registry do site opo em 127.0.0.1:15050 (TTL 10 s)
[it] (1) escrita sem token:
      HTTP 403
[it] Prometheus 2.53.5 em 127.0.0.1:19090 com o prometheus.yml do site opo (SD a cada 3 s)
[it] (2) arranca o sen-07 (services/app.py) — NÃO está no inventário
      node sen-07 opo sensor http://10.10.2.57:9100/metrics
      services sen-07 opo sensor http://10.10.2.57:8000/metrics
      site_info{region="pt",site="opo",city="Porto",lat="41.15",lon="-8.61"} 1
      ssle_registry_instances{region="pt",site="opo",kind="static"} 4
      ssle_registry_instances{region="pt",site="opo",kind="dynamic"} 1
      ssle_registry_rejections_total{region="pt",site="opo",reason="auth"} 1
[it] (3) o sen-07 morre → o lease expira (10 s) e sai dos alvos
      saiu dos alvos 9 s depois de morrer
RESULTADO: R2 — registo dinâmico → descoberta pelo Prometheus → expiração ✅
```

(Os alvos aparecem `down` neste teste porque `10.10.2.57` só existe no lab; o que se prova aqui é a
**descoberta** e as labels. No T490 o `sen-07` é um contentor e o scrape funciona.)

Testes unitários (12): `python3 -m unittest -v registry/test_core.py` — token, validação, delegação,
identidade, IP em uso, TTL, heartbeat, round-robin, HTTP SD só com dinâmicos.

## Limites (de propósito)

- O token é **partilhado por site**, não por elemento: quem o tiver regista qualquer nome livre do site.
  Próximo passo seria um token por elemento (ou mTLS com o certificado do Incus).
- O registry confia no IP **declarado** (valida a sub-rede, não a origem do pedido): atrás do NAT do Incus a
  origem seria o gateway. Com o NAT desligado nas PoCs pode passar a exigir `IP declarado == IP de origem`.
- Estado só em memória (como na aula 2): reiniciar o `reg-01` esquece os dinâmicos até ao próximo heartbeat
  (≤ 10 s) — aceitável porque os elementos se voltam a registar sozinhos.

## O que levar contigo

- **Registo dinâmico ≠ inventário:** o inventário é a fonte da verdade da frota de base; o registry é o que
  deixa a frota **crescer** sem editar ficheiros (escala) — e por isso tem de **autenticar e validar**.
- **Lease + heartbeat** escala melhor que *health-check* ativo e dá limpeza automática.
- **HTTP SD + relabel do `job`**: os elementos novos herdam as mesmas regras de liveness/anomalia.
