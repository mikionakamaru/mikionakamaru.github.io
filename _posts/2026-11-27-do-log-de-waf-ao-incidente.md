---
title: "Do log de WAF ao incidente: levando a Cloudflare pro Sentinel sem afogar o SOC"
description: "Medir o que chega, validar duas semanas de alertas, provar falso positivo com um teste de minutos e só então ligar o incidente."
date: 2026-11-27 14:00:00 -0300
categories: [Na prática, Microsoft Sentinel]
tags: [sentinel, kql, cloudflare, waf, soar]
media_subpath: /assets/img/posts/do-log-de-waf-ao-incidente
image:
  path: capa.webp
  alt: "Funil luminoso que recebe centenas de pontos cinza e deixa sair poucos pontos coral para uma fila de cartões, com uma lupa comparando duas páginas web iguais (imagem ilustrativa gerada por IA)"
---

"Liga o log do WAF no SIEM e cria umas regras." Parece tarefa de uma tarde. Aí você liga, cria dez regras bonitas e, na primeira semana, uma delas sozinha gera mais alerta que o SOC inteiro dá conta de olhar. E ninguém sabe se aquilo é ataque ou se é o site respondendo do jeito dele.

## O cenário

O pedido costuma vir assim: a empresa já tem um WAF na frente dos sites, quer o log dele no SIEM e quer que o SOC receba incidente quando algo passar. A expectativa é ver ataque. O risco é ver ruído.

Neste post eu uso a Cloudflare e o Microsoft Sentinel como exemplo, mas o método serve pra qualquer WAF e qualquer SIEM. **A regra não vai pra fila do SOC no dia em que é criada. Ela vai depois de provar que sabe a diferença entre ataque e barulho.**

## O ambiente típico

- Um WAF ou CDN na frente dos sites públicos, mandando os eventos de firewall pro SIEM por um job de exportação.
- O SIEM recebendo isso numa tabela própria.
- Regras agendadas que viram alerta e, depois, incidente.
- Uma plataforma de orquestração onde o SOC trata o incidente, com playbook por regra.

![Do log de WAF ao incidente, em oito passos](fluxo.svg){: width="900" height="420" }

## Como fazer

### 1. Meça o que chega antes de propor qualquer coisa

O job de exportação do WAF deixa escolher os campos. Muita gente marca o mínimo e esquece. Antes de escrever o primeiro caso de uso, descubra quais colunas vêm de fato preenchidas.

```kql
CloudflareV2_CL
| where TimeGenerated > ago(1h)
| take 5000
| evaluate narrow()
| summarize Linhas = count(), Preenchidas = countif(isnotempty(Value)) by Column
| extend PctPreenchida = round(100.0 * Preenchidas / Linhas, 1)
| sort by PctPreenchida asc
```

Coluna com 0% não existe pra você, mesmo que esteja na documentação. Sem país de origem, sem user agent e sem score de bot, metade das ideias de caso de uso morre aqui. É melhor morrer aqui do que em produção.

> Coluna vazia vira resultado vazio, e resultado vazio vira "não encontrado". Confira o campo antes de confiar no zero.
{: .prompt-danger }

Junto com os campos, meça volume por dia e atraso entre o evento e a chegada. O atraso decide a janela das regras.

### 2. Proponha só o que o dado aguenta, e compense a lacuna

Com os campos na mão, os casos de uso que costumam valer pra log de firewall do WAF são:

| Caso de uso | O que pega | Campo que precisa |
|---|---|---|
| Varredura de caminhos com acesso permitido | scanner que achou algo | IP, caminho, ação, status |
| Arquivo sensível servido com sucesso | `.env`, `.git`, backup exposto | caminho, status |
| Payload de ataque que chegou na aplicação | injeção que passou pelo WAF | query string, status |
| Força bruta em login | tentativa em massa | caminho, status |
| Inundação de um IP | volume anormal num host | IP, host |
| Host novo publicado | ambiente de teste exposto sem querer | host |
| Ausência de log | o envio parou | qualquer um |
| Queda brusca de mitigação | regra do WAF desligada | ação |

O último merece destaque. Se o log de auditoria do WAF não vem pro SIEM, ninguém vê quando alguém desliga uma regra ou coloca um site em exceção. **Dá pra compensar com o próprio log de firewall: tráfego normal e bloqueios despencando na mesma hora é sinal de mudança no WAF.**

### 3. Suba em homologação: ativa, sem incidente

Toda regra nova entra gerando alerta e sem abrir incidente. Os alertas ficam no SIEM pra você estudar, e o SOC não recebe nada. Um prefixo no nome (tipo `[HMG]`) deixa claro o que ainda está em teste.

### 4. Valide duas semanas de alertas, regra por regra

Depois de uns 14 dias, olhe o que cada regra teria mandado pro SOC.

```kql
SecurityAlert
| where TimeGenerated > ago(14d)
| where AlertName has "Cloudflare"
| summarize arg_min(TimeGenerated, *) by SystemAlertId
| summarize N = count() by AlertName, Dia = startofday(TimeGenerated)
| summarize Alertas = sum(N), MediaDia = round(sum(N) / 14.0, 1), MaxDia = max(N), DiasComAlerta = count() by AlertName
| sort by Alertas desc
```

Leia três coisas:

- **Média e pico por dia.** Regra com centenas de alertas por dia não vai pra fila de ninguém.
- **Número redondo demais.** Uma regra que gera exatamente o mesmo número todo dia está batendo num teto, não no ataque. Na prática, vi regra configurada pra um alerta por resultado parar sempre em 150 por execução. O volume real era maior e estava sendo cortado.
- **Quem domina.** Agrupe por entidade (IP, host). Quando duas ou três entidades respondem pela maior parte, a resposta está nelas.

### 5. Zero alerta só vale depois de ver a regra rodando

Regra que não alertou nada em 14 dias pode estar perfeita ou pode estar quebrada. A tabela de saúde do Sentinel diz qual dos dois.

```kql
SentinelHealth
| where TimeGenerated > ago(14d)
| where SentinelResourceType == "Analytics Rule"
| where SentinelResourceName has "Cloudflare"
| summarize Execucoes = count(), Falhas = countif(Status != "Success"), UltimaExecucao = max(TimeGenerated)
    by SentinelResourceName
| sort by Falhas desc
```

> A tabela de saúde precisa estar ligada nas configurações do Sentinel. Se a consulta vier vazia, o que falta é isso, não a regra.
{: .prompt-info }

### 6. Prove o falso positivo com um teste de minutos

O caso clássico: a regra de arquivo sensível diz que `/.env` respondeu 200. Parece vazamento. Muitas vezes é o site respondendo a página padrão pra qualquer caminho (aplicação de página única, página de "não encontrado" que devolve 200). O log do WAF não traz o tamanho da resposta, então ele não sabe a diferença.

O teste é comparar o caminho suspeito com uma página que com certeza não existe, no mesmo site. No PowerShell do Windows:

```powershell
$alvos = @(
  "https://www.exemplo.com.br/.env",
  "https://www.exemplo.com.br/pagina-que-nao-existe-123"
)
foreach ($u in $alvos) {
  $r = (curl.exe -s -o NUL --max-time 15 -w "%{http_code}|%{size_download}|%{content_type}" $u) -split "\|"
  [pscustomobject]@{ Status = $r[0]; Bytes = $r[1]; Tipo = $r[2]; URL = $u }
}
```

Exemplo de resultado (inventado):

| Status | Bytes | Tipo | URL |
|---|---|---|---|
| 200 | 5218 | text/html | /.env |
| 200 | 5218 | text/html | /pagina-que-nao-existe-123 |

Mesmo tamanho e mesmo tipo: é a página padrão, não o arquivo. Tamanho diferente ou tipo `text/plain` no `.env`: aí é exposição de verdade, e vira prioridade.

> Use `curl.exe`, com o `.exe`. No PowerShell, `curl` sozinho é apelido de outro comando e os parâmetros mudam.
{: .prompt-tip }

Com o teste feito, a exceção da regra pode ser por comportamento: o site que responde 200 pra muitos caminhos sensíveis diferentes no mesmo dia é página padrão. Site que responde 200 pra um ou dois continua alertando, porque esse é o cenário de vazamento real.

```kql
let Padrao = @"(?i)(/\.env[^/]*$|/\.git(/|$)|/\.aws/|/actuator(/[a-z]+)?$|/server-status$|\.(sql|pem|bak|key)$)";
let Acessos = CloudflareV2_CL
| where TimeGenerated > ago(1d)
| where EdgeResponseStatus in (200, 201, 206)
| where ClientRequestPath matches regex Padrao;
let RespondeTudo = Acessos
| summarize Caminhos = dcount(ClientRequestPath) by ClientRequestHost
| where Caminhos >= 5
| project ClientRequestHost;
Acessos
| where TimeGenerated > ago(15m)
| where ClientRequestHost !in (RespondeTudo)
| summarize Requisicoes = count(), Caminhos = make_set(ClientRequestPath, 10), IPs = dcount(ClientIP) by ClientRequestHost
```

Repare no padrão ancorado no fim do caminho (`$`). Procurar por palavra pega coisa demais: `/backup` casa com `/ajuda/backup-de-dados/`, que é só uma página do site.

### 7. Exceção por comportamento, nunca só por IP

A regra de inundação vai pegar integrações legítimas: aquela rotina que consulta a API milhares de vezes em poucos minutos. A tentação é jogar o IP numa lista de exceção. Só que rotina em nuvem pública costuma sair por IP diferente a cada execução, e a faixa da nuvem é compartilhada com qualquer outro cliente dela.

Exceção boa junta o que identifica a rotina: o host de destino, os caminhos que ela chama e o horário em que roda. Quem confirma que a rotina é legítima é o dono da aplicação, não o SOC.

> Faixa de nuvem pública na lista de exceção libera qualquer cliente daquela nuvem. É o atacante agradecendo.
{: .prompt-warning }

### 8. Regra de linha de base: mediana, não média

A regra de queda de mitigação compara a hora atual com a mesma hora dos dias anteriores. Com média, um único dia de ataque grande (milhares de bloqueios) infla a base. Na semana seguinte, um dia normal parece "queda" e a regra dispara à toa.

Com mediana, um ou dois dias fora da curva não mexem na base:

```kql
let Base = CloudflareV2_CL
| where TimeGenerated between (ago(8d) .. ago(1h))
| summarize Total = count(), Mitigadas = countif(Action != "skip") by Dia = bin(TimeGenerated, 1d), HoraDoDia = hourofday(TimeGenerated)
| summarize TotalBase = percentile(Total, 50), MitigadasBase = percentile(Mitigadas, 50) by HoraDoDia;
CloudflareV2_CL
| where TimeGenerated > ago(1h)
| summarize Total = count(), Mitigadas = countif(Action != "skip") by HoraDoDia = hourofday(now(-1h))
| join kind=inner Base on HoraDoDia
| extend PctTrafego = round(100.0 * Total / TotalBase, 1), PctMitigacao = round(100.0 * Mitigadas / MitigadasBase, 1)
| where PctTrafego >= 50 and PctMitigacao < 20
```

Um WAF desligado de verdade derruba a mitigação pra perto de zero, e a regra continua pegando.

### 9. Só então: orquestração primeiro, incidente depois

A ordem importa:

1. Tira o prefixo de homologação e importa a regra ainda sem incidente.
2. Cadastra a regra e o playbook na plataforma de orquestração, com o nome exato da regra.
3. Só então liga a criação de incidente, com agrupamento por entidade (o mesmo IP numa janela de uma hora vira um incidente, não dez).

Se a integração com a orquestração só envia o incidente no momento em que ele é criado, inverter os passos 2 e 3 é perder o incidente.

### 10. Confira a primeira noite

Na manhã seguinte, compare o volume real com o que a validação prometeu.

```kql
SecurityIncident
| where TimeGenerated > ago(12h)
| where Title has "Cloudflare"
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize Incidentes = count(), Alertas = sum(array_length(AlertIds)), Status = make_set(Status) by Title
| sort by Incidentes desc
```

E avise o time que trata os incidentes antes de ligar as regras. Um aviso curto basta: quais regras entraram e um ponto de atenção. Por exemplo: o mesmo IP de scanner costuma abrir incidente em regras diferentes ao mesmo tempo, então vale analisar junto.

## Falsos positivos comuns

| Parece | Costuma ser |
|---|---|
| Arquivo sensível servido com 200 | página padrão do site respondendo qualquer caminho |
| Inundação contra a API | integração ou rotina agendada de parceiro |
| Varredura de caminhos | buscador indexando o site, ou scanner de vulnerabilidade da própria empresa |
| Queda de mitigação do WAF | base inflada por um dia de ataque grande |
| Host novo publicado | ambiente de desenvolvimento ou homologação que alguém abriu (às vezes é exatamente o que você quer pegar) |
| Payload de ataque que passou | scanner de mercado testando tudo; vale ver se a resposta foi a página padrão |

## A pergunta que muda tudo

Antes de mexer em limiar, pergunte: **esse alerta é sobre o que o atacante fez ou sobre como o site respondeu?** No log de WAF, metade dos falsos positivos vem do segundo caso. O atacante pediu `/.env`, o site devolveu a home, e o log anotou "200". O teste de tamanho resolve em minutos o que discutir limiar não resolve em uma semana.

## Perguntas que costumam aparecer

**Não seria melhor bloquear o IP que faz a inundação?**
Se for ataque, sim, e isso é configuração do WAF (rate limit), não da regra do SIEM. Se for integração, bloquear derruba o negócio. A regra existe pra separar os dois.

**Por que não ligar o incidente logo e ir ajustando?**
Porque o SOC aprende a ignorar regra barulhenta na primeira semana. Depois, quando ela acertar, ninguém olha.

**Dá pra juntar num incidente só os alertas do mesmo IP em regras diferentes?**
O agrupamento de incidente no Sentinel é dentro da mesma regra. Pra juntar regras diferentes, o caminho é uma regra de correlação a mais (mesmo IP em duas ou mais detecções numa hora), que soma um incidente de prioridade alta. Ela não reduz volume. Ela dá contexto.

## Antes de ligar o incidente

- [ ] Campos do envio medidos: os casos de uso só usam colunas preenchidas.
- [ ] 14 dias de alertas lidos por regra: média, pico, teto e entidade dominante.
- [ ] Regras com zero alerta conferidas na tabela de saúde.
- [ ] Falso positivo de página padrão provado com o teste de tamanho, não suposto.
- [ ] Exceções por comportamento, com o dono da aplicação confirmando as rotinas legítimas.
- [ ] Regra de linha de base usando mediana.
- [ ] Regra e playbook cadastrados na orquestração antes de ligar o incidente.
- [ ] Time do SOC avisado, consulta da primeira noite pronta.

## O que eu levo disso

- Primeiro medir o que chega, depois propor caso de uso.
- Número redondo demais é teto, não ataque.
- Zero alerta só é bom depois de ver a regra rodando.
- Falso positivo se prova com teste, não com opinião.
- Exceção por comportamento, nunca só por IP, ainda mais em nuvem.
- Linha de base com mediana aguenta o dia de ataque.

## Referências

- [Cloudflare: campos do dataset firewall_events (Logpush)](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/firewall_events/)
- [Microsoft Learn: criar regra agendada no Sentinel (agrupamento de eventos e de incidentes)](https://learn.microsoft.com/azure/sentinel/create-analytics-rules)
- [Microsoft Learn: monitorar a saúde das regras de análise (SentinelHealth)](https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity)
- [Microsoft Learn: função percentile() do KQL](https://learn.microsoft.com/kusto/query/percentiles-aggregation-function)
