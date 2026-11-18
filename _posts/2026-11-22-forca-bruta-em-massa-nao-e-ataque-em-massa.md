---
title: "Força bruta em massa não é ataque em massa: como triar uma lista de contas com alerta"
description: "Uma lista grande de contas com alerta de força bruta quase sempre esconde poucas contas em risco. Como separar ruído, higiene e password spray com KQL."
date: 2026-11-22 09:00:00 -0300
categories: [Na prática, Threat Hunting]
tags: [threat hunting, kql, sentinel, defender xdr, entra id, password spray]
media_subpath: /assets/img/posts/forca-bruta-em-massa-nao-e-ataque-em-massa
image:
  path: capa.webp
  alt: "Analista de SOC separando cartões de alerta em três caixas: notebook e servidor transbordando, globo com só dois cartões acesos (imagem ilustrativa gerada por IA)"
---

Chega a planilha. Uma coluna, dezenas de nomes, e o pedido: "todas essas contas tiveram alerta de força bruta, vê quais estão comprometidas". O primeiro impulso é abrir conta por conta. O segundo é pedir demissão. Tem um terceiro caminho, e ele começa por uma pergunta que não é sobre a conta.

## O cenário

O pedido é de threat hunting, mas com cara de triagem. Alguém olhou o painel de incidentes, viu a mesma regra de força bruta disparando pra muita gente e quer saber onde focar. Não tem um incidente específico. Tem uma lista.

O erro clássico é tratar a lista como um ataque só. **Uma lista grande de contas com alerta quase nunca é um ataque grande.** Normalmente é uma mistura de três coisas que geram o mesmo alerta e não têm nada a ver uma com a outra.

## O ambiente típico

Um ambiente comum de médio ou grande porte, híbrido:

- Active Directory local, com Defender for Identity nos controladores de domínio;
- Microsoft Entra ID sincronizado, com MFA e Acesso Condicional;
- Defender for Endpoint nas estações e servidores;
- Microsoft Sentinel recebendo tudo isso, mais os logs do Exchange Online.

A regra de força bruta costuma olhar falha de logon no endpoint ou no AD. Ela não sabe de onde a falha veio. É você quem precisa descobrir.

![Triagem das falhas por origem: local, interna e externa](triagem.svg){: width="900" height="430" }

## Como fazer

Antes de tudo, coloque a lista numa variável. Vai repetir em todas as consultas, e assim a primeira rodada sai inteira de uma vez, mesmo antes de a lista chegar.

```kql
let users = dynamic(["usuario.a","usuario.b","usuario.c"]);
```

> Use o sAMAccountName em minúsculas e compare sempre com `tolower()`. Cada tabela guarda a conta de um jeito: uma traz `AccountName`, outra traz UPN completo.
{: .prompt-tip }

### 1. Separe o desbloqueio de tela do resto

A pergunta que mais assusta é "teve sucesso depois das falhas?". Ela também é a que mais engana. Rode e olhe a coluna `RemoteIP` e o tipo de logon.

```kql
let users = dynamic(["usuario.a","usuario.b","usuario.c"]);
let falhas = DeviceLogonEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "LogonFailed"
    | extend Conta = tolower(AccountName)
    | where Conta in (users)
    | summarize QtdFalhas = count(), UltimaFalha = max(TimeGenerated) by Conta, DeviceName, RemoteIP, Janela = bin(TimeGenerated, 1h)
    | where QtdFalhas >= 5;
let sucessos = DeviceLogonEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "LogonSuccess"
    | extend Conta = tolower(AccountName)
    | where Conta in (users)
    | project Conta, DeviceName, RemoteIP, HoraSucesso = TimeGenerated, LogonType;
falhas
| join kind=inner sucessos on Conta, DeviceName, RemoteIP
| where HoraSucesso between (UltimaFalha .. (UltimaFalha + 1h))
| summarize QtdFalhas = max(QtdFalhas), PrimeiroSucesso = min(HoraSucesso), TiposLogon = make_set(LogonType) by Conta, DeviceName, RemoteIP
| order by QtdFalhas desc
```

Resultado de exemplo (inventado):

| Conta | DeviceName | RemoteIP | QtdFalhas | TiposLogon |
|---|---|---|---|---|
| usuario.a | NB-0142 | 127.0.0.1 | 17 | Unlock, Interactive |
| usuario.b | NB-0388 | 127.0.0.1 | 9 | CachedInteractive |
| adm.usuario.c | SRV-FS-01 | | 9 | Network |

Origem `127.0.0.1` com tipo `Unlock` é a pessoa na frente do próprio notebook, errando a senha e acertando na décima tentativa. Segunda-feira de manhã, depois de trocar a senha na sexta. Dá pra riscar da lista.

> Sucesso depois de rajada de falhas parece o fim da história. Com origem local e tipo Unlock, é só o começo da semana de alguém.
{: .prompt-info }

### 2. Ache a credencial antiga presa em algum lugar

Conta administrativa com milhares de falhas, todas com o mesmo motivo e das mesmas máquinas, não é ataque. É senha velha esquecida num serviço, numa tarefa agendada, num drive mapeado ou numa sessão RDP que ninguém fechou.

```kql
IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where ActionType == "LogonFailed"
| where FailureReason == "OldPassword"
| summarize Falhas = count(), Protocolos = make_set(Protocol), Destinos = make_set(DestinationDeviceName, 5) by Conta = tolower(AccountName), Origem = coalesce(DeviceName, IPAddress)
| order by Falhas desc
```

Se a origem for sempre a mesma lista de servidores, você achou o problema. Ele é de higiene, e não de resposta a incidente. Impressora com scan-to-folder costuma aparecer aqui também, com hostname de fábrica no lugar do nome.

### 3. Agora sim: IPs externos, com país e provedor

Aqui mora o ataque, quando ele existe. A tabela `IdentityLogonEvents` traz autenticações do AD e dos serviços online da Microsoft, com `Location` e `ISP` de cada IP. Tire os IPs privados e as saídas de internet da empresa.

```kql
let users = dynamic(["usuario.a","usuario.b","usuario.c"]);
let saidasCorporativas = dynamic(["198.51.100.0/24","203.0.113.10/32"]);
IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where Application != "Active Directory"
| extend Conta = tolower(AccountName)
| where Conta in (users)
| where isnotempty(IPAddress)
| extend IPv6 = IPAddress has ":"
| where IPv6 or (not(ipv4_is_private(IPAddress)) and not(ipv4_is_in_any_range(IPAddress, saidasCorporativas)))
| summarize Sucessos = countif(ActionType == "LogonSuccess"), Falhas = countif(ActionType == "LogonFailed"), Motivos = make_set(FailureReason, 10) by Conta, IPAddress, Location, ISP
| order by Conta asc, Sucessos desc
```

Olhe três coisas. Quantos IPs diferentes por conta. Quantas tentativas por IP. E se algum deles tem sucesso.

### 4. Reconheça o desenho do spray

Força bruta clássica é um IP martelando uma conta. Password spray lento é o contrário: dezenas de IPs, uma ou duas tentativas cada, espalhadas por semanas. Cada IP sozinho parece inocente.

![Força bruta clássica concentrada num IP contra password spray distribuído em dezenas de IPs](spray.svg){: width="900" height="360" }

```kql
let users = dynamic(["usuario.a","usuario.b","usuario.c"]);
IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where Application != "Active Directory"
| where ActionType == "LogonFailed"
| extend Conta = tolower(AccountName)
| where Conta in (users)
| where IPAddress has ":" or not(ipv4_is_private(IPAddress))
| summarize Tentativas = count(), IPs = dcount(IPAddress), Paises = make_set(Location), Provedores = make_set(ISP, 10), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by Conta
| extend TentativasPorIP = round(todouble(Tentativas) / IPs, 1)
| where IPs >= 10 and TentativasPorIP <= 2
| order by IPs desc
```

> Regra que conta falhas por IP nunca vê o spray lento. Ele só aparece quando você agrupa por conta e conta os IPs.
{: .prompt-danger }

Outro sinal forte: duas contas diferentes recebendo tentativas dos mesmos blocos de rede. É a mesma campanha. Vale cruzar os prefixos.

### 5. Leia o código de resultado antes de concluir

Ter tentativa externa não quer dizer que a senha caiu. Quem responde isso é o código do Entra ID na `SigninLogs`.

```kql
let contasSuspeitas = dynamic(["usuario.a","usuario.b"]);
SigninLogs
| where TimeGenerated > ago(30d)
| extend Conta = tolower(tostring(split(UserPrincipalName, "@")[0]))
| where Conta in (contasSuspeitas)
| summarize Tentativas = count(), Codigos = make_set(ResultType), StatusCA = make_set(ConditionalAccessStatus), Exigencia = make_set(AuthenticationRequirement), ClientApps = make_set(ClientAppUsed) by Conta, IPAddress, Location
| order by Conta asc
```

| Código | O que quer dizer | Leitura no hunting |
|---|---|---|
| 50126 | Usuário ou senha inválidos | A senha estava errada |
| 50053 | Conta travada pelo Smart Lockout | O Entra parou de aceitar tentativas daquela origem |
| 50074 / 50076 | MFA exigido | **A senha estava certa** e o MFA segurou |
| 53003 | Bloqueado pelo Acesso Condicional | A política barrou antes de qualquer coisa |
| 0 | Sucesso | Entrou. Investigue o que fez depois |

> Spray com só 50126 e 50053 ainda não acertou a senha. Apareceu 50074 ou 50076 de IP estranho? A senha vazou, e só o MFA está entre o atacante e a conta.
{: .prompt-warning }

## Falsos positivos comuns

- **Desbloqueio de tela.** Origem `127.0.0.1`, tipo `Unlock`, sucesso logo depois. Depois de troca de senha obrigatória, a lista explode.
- **Conta administrativa em serviço.** Milhares de `OldPassword` vindos de servidores fixos. O alerta é real, mas o problema é outro.
- **Impressora com credencial antiga.** Hostname de fábrica, falha de usuário inexistente ou senha antiga.
- **VPN do próprio colaborador.** Sucesso com MFA de um provedor de hospedagem no exterior, acessando aplicativos internos que só quem trabalha ali conhece. Confirme com a pessoa antes de tratar como invasão.
- **Varredura administrativa.** Logon de rede em dezenas de servidores em um minuto, saindo de um jump server, com PowerShell remoto. Antes de chamar de movimento lateral, veja o que rodou na máquina de origem naquele minuto.
- **Relay de privacidade no celular.** IPv6 de CDN conhecida, uma ou duas autenticações com sucesso. É o celular da pessoa, não um atacante.

## A pergunta que muda tudo

A pergunta não é "essa conta foi atacada?". É **"de onde veio cada falha?"**. Local, interna ou externa. Com isso, uma lista de dezenas de contas vira duas ou três que pedem ação, um punhado que pede conversa com o time de servidores e o resto que só pede paciência.

E quando a tabela não responde, troque de tabela. A pergunta continua valendo.

> Se a sua tabela de sign-ins não interativos estiver no plano Basic, ela aceita consulta de uma tabela só, e o intervalo de tempo vem do seletor do Log Analytics. `union` com ela costuma quebrar. A `IdentityLogonEvents` cobre boa parte do mesmo terreno e ainda traz país e provedor.
{: .prompt-info }

## Antes de dizer que está limpo

- [ ] Cada falha classificada por origem: local, interna ou externa.
- [ ] IPs externos com país, provedor, sucesso e falha separados.
- [ ] Códigos de resultado conferidos: nenhum 50074/50076 nem sucesso de origem estranha.
- [ ] MFA, senha, funções e métodos de autenticação sem alteração suspeita no período.
- [ ] Caixa postal sem regra de encaminhamento externo nem permissão nova.
- [ ] Nenhuma ferramenta de reconhecimento ou de credencial executada pelas contas.
- [ ] Conclusão escrita com o limite dela: "não identifiquei comprometimento na janela de 30 dias com as fontes X, Y e Z", e não "a conta está segura".

Para as contas sob spray, o plano costuma ser curto. Troca preventiva de senha, conferir se o MFA está registrado, bloquear autenticação legada por Acesso Condicional e deixar uma consulta agendada pra avisar se algum IP externo conseguir sucesso.

## O que eu levo disso

- Alerta de força bruta em massa quase nunca é ataque em massa. O trabalho é separar a origem.
- O spray que importa é o lento. Ele não dispara regra por IP.
- O código de resultado diz mais que a quantidade de tentativas.
- Conta .adm usada como credencial de serviço gera mais alerta do que qualquer atacante.
- Monte as consultas antes de a lista chegar. Quando ela vier, é só trocar a variável.

## Referências

- [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Protect user accounts from attacks with Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [IdentityLogonEvents table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table)
- [Query data in a Basic and Auxiliary table in Azure Monitor Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/basic-logs-query)
