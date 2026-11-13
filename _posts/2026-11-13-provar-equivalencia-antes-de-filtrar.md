---
title: "Migrando uma regra do Splunk pro Sentinel: provar a equivalência antes de filtrar"
description: "Como migrar uma regra de firewall do Splunk pro Sentinel e deixar uma rede de fora sem criar furo: reproduzir, comparar com o original e só então filtrar."
date: 2026-11-13 11:50:00 -0300
categories: [Na prática, Sentinel]
tags: [sentinel, kql, siem, splunk, palo alto]
media_subpath: /assets/img/posts/provar-equivalencia-antes-de-filtrar
image:
  path: capa.webp
  alt: "Uma lupa animada sorrindo e fazendo joinha entre dois monitores com os mesmos pontos, um check verde no meio e uma mão descartando uma placa de wi-fi de visitante."
---

O chamado tem uma linha: "a regra X não pode alertar pra rede de visitantes". Parece coisa de dez minutos. Um `where not(...)` no fim da query e pronto.

Aí você descobre que a regra ainda mora no Splunk, que no Sentinel não existe nada parecido, e que "rede de visitantes" não é uma coisa só. Dez minutos viram uma tarde. Mas uma tarde bem gasta.

## O cenário

Imagine um ambiente comum, com firewall de próxima geração mandando log pro SIEM. A empresa está trocando de SIEM e uma detecção (spyware, no exemplo) precisa ir do Splunk pro Sentinel. No caminho, alguém pede: essa regra não deve alertar pra uma rede específica, a de visitantes.

Dois riscos nesse pedido. Filtrar demais e calar uma detecção de verdade. Filtrar de menos e continuar acordando o SOC por causa de um café de visitante.

## O ambiente típico

![Firewall com três zonas mandando log em CEF pro Splunk e pro Sentinel](arquitetura.svg){: width="900" height="380" }
_Diagrama de referência. Não representa nenhum ambiente real._

Durante a migração, os dois SIEMs recebem o mesmo log. Isso é uma vantagem: o Splunk vira a régua e o Sentinel é o que você está provando. Se as zonas e as regras do firewall aparecem no log, dá pra filtrar por elas. Se não aparecem, o filtro por zona nem existe, e o por faixa de IP vira o único.

## O método em cinco passos

![Cinco passos: ler, reescrever, comparar, filtrar, observar](metodo.svg){: width="900" height="300" }
_Diagrama de referência. Não representa nenhum ambiente real._

> Filtro novo só entra depois que a regra nova provou que enxerga o mesmo que a antiga.
{: .prompt-tip }

### 1. Ler a regra como ela roda hoje

Antes de escrever qualquer KQL, pegue a busca salva do Splunk e anote o que não está na query: a frequência (a cada 5 minutos?), a janela, a severidade, o throttle por campo e o que acontece quando dispara (webhook, ticket). No Sentinel isso vira agendamento, agrupamento de incidentes e playbook. A query é só um terço da regra.

### 2. Reescrever sem filtro nenhum

Reproduza a lógica fiel, sem a exceção que o chamado pede. Num log de firewall em CEF, a tabela é `CommonSecurityLog`. Os campos específicos do fabricante costumam cair em `DeviceCustomString*` e `FlexString*` (confira o mapeamento no seu ambiente, ele varia com o conector).

```kql
let Janela = 7d;
CommonSecurityLog
| where TimeGenerated > ago(Janela)
| where DeviceVendor == "Palo Alto Networks"
| extend ZonaOrigem = DeviceCustomString1
| extend RegraFirewall = DeviceCustomString3
| extend Ameaca = DeviceCustomString6
| extend Categoria = FlexString1
| where Categoria =~ "spyware"
| project TimeGenerated, SourceIP, DestinationIP, ZonaOrigem, RegraFirewall, Ameaca, DeviceAction, LogSeverity
```

### 3. Comparar com o original

Rode a mesma janela nos dois produtos e compare a contagem de eventos. Se o Splunk disse 8 e o Sentinel disse 21, a regra nova não é equivalente e qualquer filtro em cima dela está no escuro.

Duas diferenças que aparecem muito:

| O que difere | No Splunk | No Sentinel |
|---|---|---|
| Valor de ação (descarte, bloqueio) | texto normalizado pelo add-on | texto bruto do firewall, com outro nome |
| Nome da ameaça | um separador (`generic:x`) | dois (`generic::x`) |
| Campo vazio | linha continua | `where` com null derruba a linha |

> Os dois produtos normalizam o mesmo log de jeitos diferentes. Comparar a lógica não basta, compare o **resultado**.
{: .prompt-danger }

Ache as diferenças olhando os valores distintos dos campos que a regra usa:

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| summarize Eventos = count() by Acao = DeviceAction, Ameaca = DeviceCustomString6
| order by Eventos desc
```

Ajuste a regra nova até a contagem bater. Exemplo (números inventados): Splunk 8, Sentinel 8. Aí sim, passo 4.

### 4. Agora o filtro, e sem furo

"Rede de visitantes" tem várias pontas, e um filtro por uma só deixa passar. Combine as três, com `coalesce` pra uma coluna nula não derrubar a linha:

```kql
let FaixasVisitante = dynamic(["198.51.100.0/24", "203.0.113.0/24"]);
let Base =
CommonSecurityLog
| where TimeGenerated > ago(7d)
| extend ZonaOrigem = DeviceCustomString1
| extend RegraFirewall = DeviceCustomString3;
Base
| where not(
    ZonaOrigem =~ "Z_VISITANTE"
    or coalesce(ipv4_is_in_any_range(SourceIP, FaixasVisitante), false)
    or (RegraFirewall has "VISITANTE" and coalesce(ipv4_is_in_range(SourceIP, "10.20.0.0/16"), false)))
```

Por que as três:

- **A zona** pega o caso normal.
- **O nome da regra do firewall** pega tráfego da mesma rede que entra por outra zona.
- **As faixas de IP** pegam o que sobrou. E aqui vale conferir a lista contra o log: a lista que chega no chamado costuma ter menos faixas do que o log mostra.

> Se o chamado diz "IPs internos", pergunte o que isso inclui. Todo IP privado é "interno", e um usuário corporativo com spyware detectado não deveria ser calado.
{: .prompt-warning }

Depois de filtrar, compare de novo: o que sumiu tem que ser só a rede de visitantes. Liste o que sobrou por zona e regra e confira se ainda aparece algo que parece visitante:

```kql
Base
| where SourceIP startswith "10.20."
| summarize Eventos = count() by ZonaOrigem, RegraFirewall
| order by Eventos desc
```

## Falsos positivos comuns (e o outro lado)

Rede de visitante gera muito evento de spyware e adware: notebooks pessoais, celulares, tudo sem gerência. Por isso o pedido é razoável. O que não é razoável é o filtro escorregar pra fora da rede de visitante.

Depois de ligar a regra, olhe as primeiras 24 horas. Um único host pode responder por quase todos os alertas (um servidor, um scanner, algo que fala com o mesmo destino o dia todo). Nesse caso, uma exceção estreita funciona melhor que uma exceção larga.

```kql
| where not(SourceIP == "192.0.2.10"
    and ZonaOrigem =~ "Z_SERVIDORES"
    and Ameaca matches regex @"^generic::exemplo\.[a-z]+\(\d+\)$")
```

> Exceção nunca só por IP. IP com zona e com o padrão da ameaça. Se o IP um dia virar outra coisa, a exceção não vira um buraco.
{: .prompt-info }

## Agrupar no lugar do throttle

O Splunk segurava alerta repetido com throttle por campo (por exemplo, 10 minutos por IP de origem). No Sentinel, o equivalente mais próximo é o agrupamento de alertas em incidente: agrupe por entidade IP, numa janela, e o mesmo IP repetido vira um incidente só. A Microsoft documenta isso em regras agendadas, junto com a supressão ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)).

Diferença que importa: o throttle esconde alerta, o agrupamento guarda todos dentro de um incidente. Você perde menos informação.

## Antes de dizer que está pronto

- A contagem do Sentinel bate com a do original, sem filtro, na mesma janela?
- Os campos que a regra usa têm o mesmo formato nos dois produtos?
- O filtro cobre zona, regra de firewall e faixa de IP, não só uma?
- Sobrou algo com cara de visitante depois do filtro?
- Frequência, severidade e agrupamento foram migrados, não só a query?
- Alguém olha o resultado nas primeiras 24 horas?

E ao escrever a conclusão, diga o limite dela: "equivalente ao original na janela de 7 dias" é uma afirmação verificada. "Funciona" não é.

## O que eu levo disso

- Em migração, reproduzir vem antes de melhorar.
- O mesmo campo muda de formato entre produtos.
- Filtro por um critério só deixa furo. Três critérios fecham.
- As primeiras 24 horas mostram o ruído real.

## Referências

- [ipv4_is_in_any_range(), Microsoft Learn (Kusto)](https://learn.microsoft.com/en-us/kusto/query/ipv4-is-in-any-range-function?view=microsoft-fabric)
- [Create scheduled analytics rules in Microsoft Sentinel, Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- [CommonSecurityLog, Azure Monitor Logs reference, Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
