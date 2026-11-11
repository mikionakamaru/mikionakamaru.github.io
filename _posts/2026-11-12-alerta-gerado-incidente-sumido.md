---
title: "Alerta gerado, incidente sumido: onde o alerta do Sentinel morre no portal unificado"
description: "Método pra seguir um alerta do Sentinel etapa por etapa no portal do Defender e achar onde ele se perde antes de virar incidente."
date: 2026-11-12 09:00:00 -0300
categories: [Na prática, Sentinel]
tags: [sentinel, defender xdr, kql, portal unificado, detection engineering]
media_subpath: /assets/img/posts/alerta-gerado-incidente-sumido
---

Você roda o teste, a consulta da regra devolve o evento bonitinho, e a fila de incidentes continua vazia. Alguém fala "deve ser a query". Não é a query. Quase nunca é a query, mas é sempre por ela que a gente começa, porque é a única parte que dá pra abrir e ler.

## O cenário

Teste de TTP de uma analytic rule. Uma regra simples, dessas que alertam quando cai executável numa pasta onde não devia. O time cria o arquivo, espera, e nada de incidente.

O primeiro reflexo é mexer na consulta. Trocar `contains` por `has`, aumentar a lista de extensões, rodar de novo. Só que **a consulta rodada à mão devolve o evento**. Então o problema não está nela.

> Se a consulta da regra, rodada à mão, devolve o evento, pare de editar a consulta. O alerta está morrendo em outro lugar.
{: .prompt-tip }

## O ambiente típico

Sentinel ligado ao portal do Defender (o tal portal unificado). Nesse modelo a regra continua sendo do Sentinel, mas quem cria e correlaciona o incidente é o Defender XDR ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal)).

Isso significa que entre "o evento aconteceu" e "o SOC viu" existem cinco etapas, cada uma com a sua tabela:

![Cinco etapas do alerta, do dado ao incidente, com a tabela de cada uma](pipeline.svg){: width="900" height="360" }
_Diagrama de referência._

| Etapa | Pergunta | Onde olhar |
|---|---|---|
| 1. Dado | O evento chegou no workspace? | tabela de origem (ex.: `DeviceFileEvents`) |
| 2. Execução | A regra rodou? Gerou alerta? | `SentinelHealth` |
| 3. Alerta | O Sentinel gravou o alerta? | `SecurityAlert` |
| 4. Ingestão | O Defender recebeu o alerta? | `AlertInfo` |
| 5. Incidente | Virou item na fila? | `SecurityIncident` |

O método é só isso: **descer etapa por etapa até achar a primeira que está vazia.**

## Como fazer

### 1. O dado chegou, e a tempo?

Antes de qualquer outra coisa, confira se o evento do teste está lá e quanto demorou pra chegar.

```kql
DeviceFileEvents
| where TimeGenerated > ago(3h)
| where DeviceName startswith "<HOST-DO-TESTE>"
| where FolderPath contains "<PASTA-MONITORADA>"
| project TimeGenerated, ActionType, FileName, FolderPath, Atraso = ingestion_time() - TimeGenerated
| order by TimeGenerated desc
```

Atraso de poucos minutos é normal. Atraso maior que a tolerância da regra faz o evento cair entre uma execução e outra. Se o evento nem aparece, o problema é de coleta (máquina fora do EDR, conector sem a tabela marcada) e o resto do método nem começa.

> Executar um binário que já estava na pasta gera evento de processo, não de arquivo. Se a regra olha arquivo, o teste tem que criar, copiar ou renomear o arquivo.
{: .prompt-info }

### 2. A regra rodou?

O `SentinelHealth` registra cada execução de regra agendada, com sucesso, falha e se passou do threshold ([Microsoft Learn](https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity)). Ele precisa estar ligado em Settings > Microsoft Sentinel > Auditing and health monitoring ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring)).

```kql
SentinelHealth
| where TimeGenerated > ago(2d)
| where SentinelResourceType == "Analytics Rule"
| where SentinelResourceName has "<NOME-DA-REGRA>"
| project TimeGenerated, Status, Description
| order by TimeGenerated desc
```

Procure a linha "Rule executed successfully, generating 1 alert(s)". Se ela existe, a regra está viva e alertando. O problema está depois.

### 3. O alerta foi gravado no Sentinel?

```kql
SecurityAlert
| where TimeGenerated > ago(2d)
| where AlertName has "<NOME-DA-REGRA>"
| project TimeGenerated, SystemAlertId, StartTime, EndTime, Entities
| order by TimeGenerated desc
```

Anote os `SystemAlertId`. Eles são a prova de que o Sentinel fez a parte dele.

> Não confie no campo `IsIncident` do `SecurityAlert` no portal unificado. Ele pode vir `false` até em alerta que virou incidente.
{: .prompt-warning }

### 4. O Defender recebeu?

Essa é a consulta que separa os dois mundos. O `AlertInfo` é a tabela de alertas do lado do Defender ([Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)).

```kql
AlertInfo
| where Timestamp > ago(7d)
| where Title has "<NOME-DA-REGRA>"
| project Timestamp, AlertId, Title, ServiceSource, DetectionSource
```

Use janela larga. O `Timestamp` aqui costuma refletir o horário do evento, não o da execução da regra, e um `ago(3h)` apertado esconde o alerta que você procura.

Se o alerta está no `SecurityAlert` e não está no `AlertInfo`, achou: **o Sentinel gerou, o Defender não ingeriu.**

### 5. É só essa regra ou são todas?

Antes de abrir chamado, compare com o resto do workspace. Esta consulta mostra, por regra, quantos alertas viraram incidente.

```kql
SecurityAlert
| where TimeGenerated > ago(1d)
| where ProviderName == "ASI Scheduled Alerts"
| join kind=leftouter (
    SecurityIncident
    | where TimeGenerated > ago(2d)
    | mv-expand AlertIds
    | extend SystemAlertId = tostring(AlertIds)
    | summarize arg_max(TimeGenerated, IncidentNumber) by SystemAlertId
  ) on SystemAlertId
| summarize Alertas = count(), ComIncidente = countif(isnotempty(IncidentNumber)) by AlertName
| order by Alertas desc
```

Exemplo de leitura (dados inventados):

| AlertName | Alertas | ComIncidente | Leitura |
|---|---|---|---|
| Regra A | 9 | 9 | normal |
| Regra B (homologação) | 1.240 | 0 | criação de incidente desligada de propósito |
| **Regra do teste** | **6** | **0** | **aqui está o problema** |

Regra que deveria abrir incidente e aparece zerada, com as vizinhas funcionando, aponta pra algo específico dela.

### 6. Descarte o que mora no Defender

Com a perda isolada na ingestão, sobram poucos suspeitos:

1. **Incident settings da regra.** "Create incidents from alerts" precisa estar Enabled. Confira na regra ao vivo, não no export de ontem.
2. **Alert tuning.** Em Settings > Microsoft Defender XDR > Alert tuning, abra cada regra custom e leia as condições e os Service sources. Regra de tuning que só olha Defender for Endpoint não toca em alerta do Sentinel.
3. **Mudança recente na regra.** O `SentinelAudit` (ou o `AzureActivity`) mostra quem gravou a regra e quando.

```kql
AzureActivity
| where TimeGenerated > ago(10d)
| where OperationNameValue has "Microsoft.SecurityInsights/alertRules"
| where _ResourceId has "<GUID-DA-REGRA>"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller
| order by TimeGenerated desc
```

> Uma regra de alert tuning com ação "Hide alert" e escopo na organização inteira esconde o teste e esconde o ataque real do mesmo jeito. Se achar uma dessas pegando seu alerta, a conversa é com o dono do ambiente, não só um ajuste técnico.
{: .prompt-danger }

### 7. Republique e teste com regra nova

Se nada acima explica, republicar a regra costuma destravar. Dois detalhes que custam tempo:

- **Salvar uma regra existente não faz ela rodar na hora.** Ela volta no próximo horário agendado.
- **Pra testar já, crie uma cópia com outro nome e outro GUID.** Regra nova roda na criação. Se a cópia chega no Defender e a original não, o problema está na regra antiga, não na lógica.

Aproveite o republish pra revisar o mapeamento de entidades. Host com `HostName`, arquivo com nome e diretório na mesma entidade, linha de comando como entidade `Process`. Entidade bem mapeada é o que o motor de correlação do Defender usa pra montar o incidente.

## Falsas pistas comuns

| Parece a causa | Por que não é (ou não sozinha) |
|---|---|
| "A consulta está errada" | Rodada à mão, ela devolve o evento. |
| "A regra está desativada" | O `SentinelHealth` mostra execução com alerta. |
| "O incidente foi agrupado com outro" | Agrupado ainda aparece no `AlertInfo`. Se não está lá, não chegou. |
| "Buscar o incidente pelo título" | O Defender pode renomear o incidente ao correlacionar. Busque pelo ID do alerta. |
| "Rodei agora e não veio nada" | Janela curta demais ou regra que ainda não executou depois do save. |

## A pergunta que muda tudo

"A consulta acha o evento?" é a pergunta errada. A certa é: **em qual tabela o alerta existe pela última vez?** Ela troca uma tarde de chute por cinco consultas com resposta sim ou não.

## Antes de dizer que está resolvido

- [ ] Teste novo, com arquivo criado depois da correção.
- [ ] Alerta aparece no `SecurityAlert` **e** no `AlertInfo`.
- [ ] Incidente aparece na fila com as entidades certas.
- [ ] Regra de teste apagada, senão o SOC recebe incidente duplicado.
- [ ] Incidente do teste classificado como teste, não como falso positivo.

E na conclusão, escreva o limite. Se o republish e o ajuste de entidades aconteceram juntos, **você não sabe qual dos dois resolveu**. Diga isso. Ninguém confia num relatório que nunca admite um "não sei".

> Classificar o incidente de um teste como falso positivo contamina a métrica da regra. Daqui a três meses alguém usa esse número pra justificar desligar uma detecção que funciona.
{: .prompt-warning }

## O que eu levo disso

- No portal unificado, "alerta gerado" e "incidente criado" acontecem em sistemas diferentes. Conferir os dois.
- `SecurityAlert` contra `AlertInfo` é a consulta que mostra onde o alerta morreu.
- Comparar a regra com as vizinhas separa problema da regra de problema do ambiente.
- Regra de teste precisa de GUID novo pra rodar na hora.
- Fechar o teste com a classificação certa faz parte do teste.

## Referências

- [Microsoft Sentinel in the Microsoft Defender portal](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal) (Microsoft Learn)
- [Monitor the health and audit the integrity of your analytics rules](https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity) (Microsoft Learn)
- [Turn on auditing and health monitoring in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring) (Microsoft Learn)
- [AlertInfo table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table) (Microsoft Learn)
