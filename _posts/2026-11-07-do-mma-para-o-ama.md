---
title: "Do MMA para o AMA: como mapear o que ainda depende do agente antigo antes de desligá-lo"
description: "Método para descobrir onde o MMA ainda é necessário, validar o AMA e só então remover o agente antigo, com consultas KQL prontas."
date: 2026-11-07 14:40:00 -0300
categories: [Na prática, Sentinel]
tags: [mma, ama, sentinel, kql, defender for endpoint, dcr]
media_subpath: /assets/img/posts/do-mma-para-o-ama
image:
  path: capa.webp
  alt: "Dois servidores em desenho animado numa pista de corrida passando um bastão: um antigo e desgastado, outro moderno e azul, com uma lupa conferindo a passagem."
---

Chega o chamado: "o MMA ainda precisa existir?". Uma linha. A resposta não cabe em uma.

Se você responder "não, a Microsoft aposentou", está certo e provavelmente vai derrubar a coleta de algum servidor que ninguém lembrava que dependia dele. Se responder "sim, deixa", também está certo e vai pagar ingestão em dobro até a próxima auditoria. O trabalho de verdade é saber **onde** ele ainda é necessário. Aqui vai o método que eu uso.

## O cenário

Um ambiente típico de médio ou grande porte, com Sentinel e um parque misto: servidores novos, servidores velhos, máquinas que foram instaladas por três equipes diferentes. Alguém pergunta se dá pra desinstalar o Microsoft Monitoring Agent (MMA, também chamado de Log Analytics agent) e trocar tudo pelo Azure Monitor Agent (AMA).

O contexto oficial ajuda a dar urgência. Segundo a Microsoft, o agente foi aposentado em 31 de agosto de 2024, e depois de 2 de março de 2026 o envio de dados por ele pode parar a qualquer momento, sem aviso ([Microsoft Learn](https://learn.microsoft.com/en-au/azure/azure-monitor/agents/azure-monitor-agent-migration)). > Não é uma decisão de "se", é de "como, sem quebrar nada". Depois de 2 de março de 2026 o MMA pode parar de mandar dados sem aviso.
{: .prompt-warning }

## O que muda quando os dois agentes convivem

![Servidor com MMA e AMA enviando ao workspace do Sentinel](arquitetura.svg){: width="900" height="360" }
_Diagrama de referência. Não representa nenhum ambiente real._

O MMA manda o que a configuração do **workspace** mandar. O AMA manda o que a **regra de coleta (DCR)** associada à máquina mandar. São mecanismos separados. Por isso um servidor pode ter os dois agentes saudáveis e ainda assim o AMA não coletar nada de segurança: sem DCR associada, ele fica ali, vivo e inútil.

E se os dois coletam o mesmo log, o evento chega duas vezes.

## Como fazer

A própria Microsoft recomenda quatro passos: avaliar, configurar o AMA com DCRs, validar e só então remover o agente antigo. Na prática eu transformo isso em cinco perguntas.

### 1. Quem tem qual agente?

```kql
Heartbeat
| where TimeGenerated > ago(7d)
| extend Agente = case(
    Category == "Direct Agent", "MMA",
    Category == "Azure Monitor Agent", "AMA",
    Category)
| summarize Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated), Batimentos = count()
    by Computer, Agente, Version
| order by Computer asc
```

Cada máquina vira uma ou duas linhas. Uma linha só com MMA: ainda não migrou. Duas linhas: está em transição. Uma linha só com AMA: terminou.

Exemplo do resultado (dados inventados):

| Computer | Agente | Ultimo |
|---|---|---|
| srv-app-01 | MMA | há 2 min |
| srv-app-01 | AMA | há 1 min |
| srv-db-02 | MMA | há 3 min |
| srv-web-03 | AMA | há 1 min |

Aqui o `srv-db-02` nem começou.

> Heartbeat dos dois agentes só prova que ambos estão vivos. **Não prova que o AMA está coletando o que o MMA coletava.** Isso vem a seguir.
{: .prompt-tip }

### 2. De onde vem o log de segurança?

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Eventos = count(), Ultimo = max(TimeGenerated) by Computer, EventID
| order by Computer asc, Eventos desc
```

Rode antes e depois de associar a DCR. Se o conjunto de EventIDs de uma máquina antes da troca for o mesmo depois, o AMA está cobrindo. Se faltarem eventos, a DCR está filtrando demais (conjunto Minimal ou XPath apertado, por exemplo).

### 3. Que DCR está associada?

Pelo Azure Resource Graph, não pelo Log Analytics:

```kql
insightsresources
| where type =~ 'microsoft.insights/datacollectionruleassociations'
| where id contains '<nome-da-maquina>'
| extend DCR = tostring(properties.dataCollectionRuleId)
| extend Partes = split(DCR, '/')
| extend NomeDCR = tostring(Partes[array_length(Partes) - 1])
| project id, NomeDCR, DCR
```

Resultado vazio quer dizer que a máquina não tem DCR nenhuma. Dois cuidados: o Resource Graph não aceita índice negativo (`[-1]`), por isso o `array_length`, e a tabela `insightsresources` costuma trazer essas associações, mas confirme no seu ambiente. Se vier vazio com DCR associada, confira pelo portal, em Monitor, Data Collection Rules, aba Resources.

### 4. Tem evento duplicado?

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Copias = count() by Computer, EventID, Activity, Account, bin(TimeGenerated, 1m)
| where Copias > 1
| summarize EventosDuplicados = sum(Copias) by Computer, EventID, Activity
| order by EventosDuplicados desc
```

Isso é uma estimativa, não prova: dois eventos legítimos parecidos no mesmo minuto também aparecem. Mas se um EventID só tem pares exatos, está duplicado. Para evitar a dupla ingestão durante o teste, a Microsoft sugere remover a configuração de workspace do MMA nos servidores-piloto, sem desinstalar o agente.

### 5. Para onde cada MMA manda os dados?

Um MMA pode estar configurado para mais de um workspace. No inventário, confira o destino de cada agente, e não só se ele existe. Vale conferir se todos os destinos são workspaces que alguém ainda acompanha.

Se o Defender estiver no ambiente, o tráfego de rede dos próprios dispositivos também ajuda a ver para onde o processo do MMA conversa.

## Falsos positivos comuns

- **"Os dois agentes aparecem no Heartbeat, então migrou."** Não. Falta a DCR.
- **"Tem DCR, então está coletando segurança."** Depende de quais fontes ela tem. Uma DCR só de performance ou só de Forwarded Events não cobre o log Security da máquina.
- **"Os eventos caíram depois de associar a DCR, deu problema."** Pode ser só o fim da duplicidade.

## A pergunta que muda tudo

Aqui está a confusão mais cara que eu vejo. Existem dois conectores do Sentinel que usam o AMA e parecem a mesma coisa:

| | Windows Security Events via AMA | Windows Forwarded Events |
|---|---|---|
| Lê | Logs de segurança da própria máquina | Eventos que outras máquinas encaminharam para um coletor (WEC) |
| Tabela | `SecurityEvent` | `WindowsEvent` |
| Onde instala o agente | Em cada servidor | Só no coletor |
| Filtro | All, Common, Minimal ou XPath | Todos ou XPath |

Pela descrição da própria Microsoft, o Security Events via AMA é a opção quando dá pra instalar o agente em cada servidor, e o Forwarded Events serve quando isso não é prático ([Microsoft Tech Community](https://techcommunity.microsoft.com/t5/fasttrack-for-azure/windows-events-how-to-collect-them-in-sentinel-and-which-way-is/ba-p/3997342)). Os dados dos dois caem em tabelas diferentes, e as regras de detecção consultam uma ou outra.

Então a pergunta antes de remover o MMA de um servidor é: **o que ele coletava, e qual DCR cobre isso hoje?**

> Se o MMA alimentava `SecurityEvent` e a DCR da máquina só tem Forwarded Events, desligar o MMA apaga o log Security daquele servidor. Em silêncio. Até alguma regra parar de disparar e ninguém perceber.
{: .prompt-danger }

## Perguntas que costumam aparecer

**"Então eu removo o AMA?"** Não. O AMA é o novo. O que sai é o MMA.

**"Dá pra ter os dois?"** Dá, durante a transição. Só acompanhe a duplicidade e o custo.

**"Tem ferramenta pra ajudar?"** Tem. A Microsoft mantém a AMA Migration Helper workbook, que inventaria os agentes e acompanha o progresso, e uma ferramenta de descoberta e remoção do MMA em escala ([Microsoft Learn](https://learn.microsoft.com/en-au/azure/azure-monitor/agents/azure-monitor-agent-migration)).

**"E se o servidor também for gerenciado pelo SCOM?"** Aí o MMA fica nele.

> A aposentadoria não vale para o agente conectado exclusivamente ao SCOM local.
{: .prompt-info }

## Antes de dizer que pode remover

1. Todo servidor do escopo tem DCR associada e o AMA com batimento recente.
2. O conjunto de EventIDs por máquina é o mesmo antes e depois da troca.
3. As regras de detecção que dependem da tabela afetada seguem disparando num teste.
4. Você sabe para quais workspaces cada MMA estava mandando dados, e todos têm substituto ou destino aprovado.
5. Máquinas antigas que usam o MMA para falar com outro produto (o Defender, por exemplo) têm outro caminho definido, porque aí a regra de coleta não resolve.
6. A duplicidade foi tratada: configuração de workspace removida dos pilotos antes da desinstalação.

Na conclusão, escreva o limite: "o AMA cobre os EventIDs X, Y e Z em N servidores do piloto, e a validação cobriu tantos dias". Dizer "migrado" sem esse recorte é dizer que está limpo sem ter olhado.

## O que eu levo disso

- Resposta binária a "ainda precisa?" quase sempre está errada. A resposta útil é uma lista de onde, por quê e o que substitui.
- Heartbeat mostra que o agente vive, não o que ele coleta.
- Conector com o mesmo agente não quer dizer mesma tabela, nem mesma cobertura.
- Remover por último, e só depois de comparar antes e depois.

## Referências

- [Migrate to Azure Monitor Agent from Log Analytics agent (Microsoft Learn)](https://learn.microsoft.com/en-au/azure/azure-monitor/agents/azure-monitor-agent-migration)
- [Windows Events: how to collect them in Sentinel, and which way is best (Microsoft Tech Community)](https://techcommunity.microsoft.com/t5/fasttrack-for-azure/windows-events-how-to-collect-them-in-sentinel-and-which-way-is/ba-p/3997342)
