---
title: "Saiu um alerta do FBI e perguntaram se fomos afetados: como responder sem chutar"
description: "Do alerta público à resposta com evidência: extrair indicadores, checar se o log enxerga cada um, separar ruído de internet e declarar o limite da busca."
date: 2026-11-24 09:00:00 -0300
categories: [Na prática, Threat Hunting]
tags: [threat hunting, threat intelligence, kql, sentinel, entra id]
media_subpath: /assets/img/posts/o-alerta-saiu-e-perguntaram-se-fomos-afetados
image:
  path: capa.webp
  alt: "Documento de alerta apontando para uma lupa sobre linhas de log, com um trecho tracejado que o log não registra (imagem ilustrativa gerada por IA)"
---

Sexta à tarde sai um alerta de agência do governo americano. Segunda de manhã ele já deu a volta ao mundo, virou boletim de fornecedor, e chega na sua caixa com seis pessoas em cópia: "o que estamos fazendo sobre isso?". Ninguém leu o PDF. Todo mundo leu a manchete.

## O cenário

O alerta da vez pode ser qualquer um. Enquanto escrevo, o assunto é o ARTEX, um framework de pentest com agentes de IA que virou ferramenta de ataque, com alerta do FBI e relatório da Microsoft. Mês que vem vai ser outro nome.

A pergunta que chega tem sempre três partes: o que está sendo feito, se há exposição e o que antecipa o risco. A resposta média é "estamos monitorando". **A resposta que presta diz o que foi procurado, onde, por quanto tempo e o que a busca não conseguia ver.**

## O ambiente típico

Imagine um ambiente comum, com as fontes que a maioria tem no SIEM:

- firewall de borda e WAF mandando log em CEF;
- uma CDN ou proxy reverso na frente dos sites;
- Microsoft Entra ID com os logs de login;
- um EDR nos servidores e estações.

Cada fonte enxerga um pedaço. Nenhuma enxerga tudo. O trabalho é saber qual indicador cada uma consegue mostrar.

![Do alerta público à resposta: cinco passos, com a checagem de campo antes da busca](fluxo.svg){: width="900" height="400" }

## Como fazer

### 1. Leia a fonte primária inteira, antes da primeira consulta

Boletim de fornecedor resume. Notícia resume o resumo. O documento original costuma ter mais indicadores do que qualquer versão de segunda mão, e traz as ressalvas que ninguém copia.

> Já me aconteceu de varrer uma lista de IPs tirada de um boletim, dar o trabalho por encerrado e descobrir no fim que o documento original tinha o dobro. Leia o PDF primeiro. Depois confira de novo.
{: .prompt-danger }

Junte também a segunda fonte oficial, quando existir. Fabricante e agência publicam listas diferentes, e às vezes uma tem erro de digitação que a outra não tem.

### 2. Transforme o alerta numa tabela de indicadores

Antes de escrever KQL, monte a lista por tipo. Cada tipo vai pra uma fonte diferente.

| Tipo de indicador | Exemplo | Onde procurar |
|---|---|---|
| Endereço IP | infraestrutura de ataque e C2 | Firewall, WAF, CDN, login |
| Rota ou caminho em URL | painel da ferramenta | WAF, CDN, proxy |
| Marcador em URL | texto fixo que a ferramenta deixa | WAF, CDN, proxy |
| User-Agent | identificação da ferramenta | Só onde o campo é logado |
| Nome de alerta | detecção do fabricante | Alertas e incidentes |
| Hash e processo | malware instalado depois | EDR |

### 3. Confira se o log tem o campo, antes de procurar nele

Esse é o passo que quase todo mundo pula. A consulta por User-Agent volta vazia, e "vazio" vira "não encontrado". Só que em muito ambiente o firewall e a CDN não mandam esse campo pro SIEM.

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize Eventos = count(), ComUserAgent = countif(isnotempty(RequestClientApplication)), ComUrl = countif(isnotempty(RequestURL)) by DeviceVendor, DeviceProduct
| extend PctUserAgent = round(100.0 * ComUserAgent / Eventos, 1), PctUrl = round(100.0 * ComUrl / Eventos, 1)
| order by Eventos desc
```

Resultado de exemplo (inventado):

| DeviceVendor | Eventos | PctUserAgent | PctUrl |
|---|---|---|---|
| Fabricante A | 48.200.000 | 0,0 | 3,1 |
| Fabricante B | 912.000 | 0,0 | 100,0 |

> Zero por cento de User-Agent quer dizer que a busca por User-Agent nessa fonte é cega. O resultado vazio não prova nada. Troque de indicador ou diga isso na resposta.
{: .prompt-warning }

### 4. Varra os IPs nos dois sentidos

IP de alerta serve pra duas perguntas. Alguém de lá bateu aqui? Alguma máquina daqui falou com lá? A segunda é a que indica comprometimento, e é a que mais se esquece.

```kql
let iocs = dynamic(["192.0.2.10","192.0.2.11","198.51.100.25","203.0.113.77"]);
union
(CommonSecurityLog
| where TimeGenerated > ago(90d)
| where SourceIP in (iocs) or DestinationIP in (iocs)
| project TimeGenerated, Fonte = "Borda", Origem = SourceIP, Destino = DestinationIP, Acao = DeviceAction),
(SigninLogs
| where TimeGenerated > ago(90d)
| where IPAddress in (iocs)
| project TimeGenerated, Fonte = "Login", Origem = IPAddress, Destino = UserPrincipalName, Acao = ResultType)
| summarize Eventos = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by Fonte, Origem, Destino, Acao
| order by Eventos desc
```

Use 90 dias, ou o máximo que a retenção der. Campanha desse tipo começa meses antes de virar alerta.

> Quando o alerta trouxer uma faixa inteira, use `ipv4_is_in_range(SourceIP, "192.0.2.0/24")` junto com a lista. E inclua as duas grafias quando as fontes divergirem num dígito.
{: .prompt-tip }

### 5. Procure o que a ferramenta deixa na URL

Ferramenta automatizada testa caminho que não existe pra medir a resposta do servidor, e algumas deixam um texto fixo no pedido. Isso aparece em qualquer log que guarde caminho e query, mesmo sem User-Agent.

```kql
let marcadores = @"(?i)caminho-inexistente-xyz|MARCADOR_DE_ESCRITA|ferramenta-probe";
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where RequestURL matches regex marcadores
| summarize Eventos = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by SourceIP, DestinationIP, RequestURL, DeviceAction
| order by Eventos desc
```

Troque o padrão pelos marcadores do alerta. Use `matches regex` com `(?i)`: o operador `has` não casa com variação colada, do tipo `FerramentaVerify`.

### 6. No login, o User-Agent existe

O Entra ID guarda o User-Agent de cada login. Aqui a busca enxerga.

```kql
SigninLogs
| where TimeGenerated > ago(90d)
| where UserAgent matches regex @"(?i)ferramenta|variante|biblioteca/0\."
| summarize Tentativas = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by UserPrincipalName, IPAddress, UserAgent, AppDisplayName, ResultType
```

Olhe também as detecções de risco do Entra ID Protection. A do tipo "Verified threat actor IP" marca login vindo de infraestrutura que a Microsoft atribui a grupo de ataque, e sai sempre como risco alto.

### 7. Feche pelo nome dos alertas

O fabricante costuma publicar o nome dos alertas ligados à campanha. A busca na tela de incidentes olha o título do incidente, não o do alerta. Vá na tabela.

```kql
SecurityAlert
| where TimeGenerated > ago(90d)
| where AlertName has "NomeDaFerramenta" or AlertName has "NomeDoGrupo" or Description has "NomeDaFerramenta"
| summarize Alertas = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by AlertName, AlertSeverity, ProviderName
```

## Falsos positivos comuns

- **Scanner de vulnerabilidade comercial.** É o IP mais barulhento da borda e nunca é a ferramenta do alerta. A assinatura do IPS costuma dizer o nome dele, e o próprio pedido entrega (extensão de plugin no caminho, nome do produto no parâmetro).
- **Scanner de template.** Muitos exploits diferentes em minutos, com domínio de callback no payload. Parece ataque dirigido. É varredura de internet inteira.
- **Robô de exploit único.** O mesmo comando injetado no mesmo login, em ritmo fixo, dia e noite, por semanas. Merece bloqueio, mas não tem nada da ferramenta nova.
- **Busca global que casa pedaço de palavra.** Procurar o nome da ferramenta no portal devolve arquivo, imagem de container e vulnerabilidade que só têm as mesmas letras no meio do nome.
- **"Credencial suspeita" que é celular novo.** Login de dispositivo desconhecido seguido de método de autenticação novo em minutos parece conta tomada. O log de auditoria mostra o registro do aparelho e do autenticador, tudo no mesmo minuto.
- **Mesmo bloco de rede de um IP do alerta.** Vizinho de /24 em provedor de hospedagem não é indicador. Olhe o que o IP pede antes de concluir qualquer coisa.

## A pergunta que muda tudo

Antes de escrever "não encontrei", pergunte: **o ambiente tinha como ver?**

Pra cada indicador, a resposta honesta tem três estados, não dois. Encontrei. Não encontrei, e o log enxergaria. Não encontrei, e o log não enxerga. Quem lê a resposta precisa saber qual é qual.

> O ruído que você separou do tema não vai pro lixo. Scanner batendo em tudo mostra o que está publicado e por onde passa sem inspeção. Entra no relatório como achado à parte, com a etiqueta certa.
{: .prompt-info }

## Perguntas que costumam aparecer

**"Então estamos seguros?"** A busca responde sobre os indicadores publicados até a data, nas fontes e no período analisados. Indicador de IP envelhece rápido, e o próprio FBI avisa que endereço em nuvem é reatribuído.

**"Por que não bloquear a lista de IPs e pronto?"** Pode bloquear, com conferência antes. Mas quem usa esse tipo de ferramenta troca de proxy e de VPN, então a lista sozinha protege pouco.

**"Esse IP estranho que apareceu é a ferramenta?"** Só se bater com algum indicador. IP barulhento sem marcador é internet sendo internet.

## Antes de dizer que está limpo

- [ ] Fonte primária lida inteira, e lista de indicadores conferida contra ela no fim.
- [ ] Segunda fonte oficial cruzada com a primeira.
- [ ] Cobertura de campo medida em cada fonte de log.
- [ ] IPs varridos como origem e como destino, na maior janela que a retenção permite.
- [ ] Rotas e marcadores procurados em tudo que guarda URL.
- [ ] User-Agent procurado onde o campo existe.
- [ ] Alertas procurados pelo nome, na tabela.
- [ ] Ruído identificado pelo que é, e não descartado.
- [ ] Conclusão com o limite escrito: "não identifiquei os indicadores publicados até a data X, nas fontes A, B e C, em N dias. A fonte D não registra o campo Y."

E mande a resposta sem pergunta em aberto. Se precisa de uma confirmação pra agir, declare a premissa e a ação padrão. Pergunta solta num e-mail com seis pessoas em cópia vira uma semana de "fala com fulano".

## O que eu levo disso

- "Não encontrei" só vale se o log tinha como mostrar.
- O documento original primeiro. Boletim e notícia depois.
- IP de alerta se procura na entrada e na saída.
- O IP mais barulhento quase nunca é o assunto do alerta.
- A resposta boa cabe no topo do e-mail. A evidência vai no anexo.

## Referências

- [FBI FLASH-20261113-001: Threat Overview of ARTEX Autonomous Penetration Testing Framework](https://www.ic3.gov/csa/2026/261113.pdf)
- [Microsoft Threat Intelligence: ARTEX abuse expands as cybercriminals target financial sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)
- [Microsoft Entra ID Protection: risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
