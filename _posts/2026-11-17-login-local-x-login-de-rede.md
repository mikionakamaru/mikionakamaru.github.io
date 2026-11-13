---
title: "Login local x login de rede: refinando a regra de criação de contas em banco"
description: "Como separar login local de login de rede no SQL Server e no Oracle, testar antes de mexer e não perder o evento que chega atrasado no Sentinel."
date: 2026-11-17 09:00:00 -0300
categories: [Na prática, Sentinel]
tags: [sentinel, kql, siem, sql server, oracle, detection engineering]
media_subpath: /assets/img/posts/login-local-x-login-de-rede
---

O pedido chega numa linha: "a regra de criação de login no banco só deve alertar conta local, não de rede". Parece um `where` a mais. Aí você abre os eventos e descobre que metade nem é criação de login, que o Oracle tem quatro jeitos de autenticar e que tem evento que chega no workspace depois que a regra já passou por ali. O que podia dar errado?

## O cenário

Uma analytic rule olha a auditoria de dois bancos, SQL Server e Oracle, e alerta todo `CREATE LOGIN` e todo `CREATE USER`. O SOC recebe incidente a cada usuário do AD que ganha acesso a um banco, que é rotina de DBA. A conta que importa, a local com senha própria, some no meio do barulho.

O pedido é razoável: **alertar a conta que nasce dentro do banco**, porque ela não passa pelo AD, não tem MFA e não some quando a pessoa sai da empresa.

> Conta local de banco é persistência clássica (MITRE T1136, Create Account). Ela sobrevive ao desligamento do usuário no AD.
{: .prompt-info }

## O ambiente típico

![Fluxo dos bancos até o alerta, com a volta da regra na SecurityAlert](fluxo.svg){: width="900" height="400" }

Dois detalhes desse desenho mudam a regra. A coleta tem **atraso variável**: o evento pode chegar em segundos ou em horas. E muita gente lê a auditoria por uma **função** do workspace, não pela tabela crua, o que esconde colunas como `TimeGenerated` e às vezes a hora de ingestão.

## Como fazer

### 1. Separe local de rede pela sintaxe

A diferença está no próprio comando. Não precisa consultar o AD.

| Banco | Comando | Tipo | Alerta? |
|---|---|---|---|
| SQL Server | `CREATE LOGIN nome WITH PASSWORD = ...` | Local, senha no banco | Sim |
| SQL Server | `CREATE LOGIN nome FROM CERTIFICATE` / `ASYMMETRIC KEY` | Local, assinatura de código | Sim (raro, vale ver) |
| SQL Server | `CREATE LOGIN [DOMINIO\usuario] FROM WINDOWS` | Rede (AD) | Não |
| SQL Server | `CREATE LOGIN [user@dominio] FROM EXTERNAL PROVIDER` | Rede (Entra ID) | Não |
| Oracle | `CREATE USER nome IDENTIFIED BY ...` | Local, senha no banco | Sim |
| Oracle | `CREATE USER nome IDENTIFIED GLOBALLY` | Diretório corporativo | Não |
| Oracle | `CREATE USER nome IDENTIFIED EXTERNALLY` | Sistema operacional ou serviço externo | Decisão do dono da regra |
| Oracle | `CREATE USER nome NO AUTHENTICATION` | Schema sem login | Decisão do dono da regra |

As duas últimas linhas não têm resposta técnica certa. `EXTERNALLY` costuma ser conta de SO ou Kerberos, o que muita empresa trata como rede. `NO AUTHENTICATION` não loga, mas é criação de conta do mesmo jeito.

> Não decida `EXTERNALLY` e `NO AUTHENTICATION` sozinho. Leve o exemplo real pro dono da regra e registre a resposta. É isso que segura a regra quando alguém perguntar por que um alerta não veio.
{: .prompt-warning }

### 2. Reconheça o que você quer, não exclua o que não quer

O caminho óbvio é `where Comando !has "FROM WINDOWS"`. Funciona até chegar um lote com dois comandos:

```sql
CREATE LOGIN [DOMINIO\joao] FROM WINDOWS;
CREATE LOGIN app_backdoor WITH PASSWORD = 'Senha@123';
```

O filtro de exclusão vê `FROM WINDOWS` e joga o lote inteiro fora, junto com a conta local. **Reconhecimento positivo** é mais difícil de driblar: procure o padrão do login local e extraia o nome dele.

```kql
let LoginLocalSql = @"(?i)create\s+login\s+(?:\[([^\]]+)\]\s*|([A-Za-z_#@][^\s\[\]';]*)\s+)(?:with\b|from\s+(?:certificate|asymmetric\s+key)\b)";
SqlAudit_CL
| where Statement contains "CREATE LOGIN"
| extend Conta = trim(" ", coalesce(extract(LoginLocalSql, 1, Statement), extract(LoginLocalSql, 2, Statement)))
| where isnotempty(Conta)
| project EventTime, Servidor = ServerName, Executor = PrincipalName, Conta, Statement
```

Troque `SqlAudit_CL` e as colunas pelas da sua tabela ou função. A regex aceita nome com e sem colchete, nome com espaço (`[app login]`) e ignora o que vem depois de `FROM WINDOWS`.

### 3. Meça o antes e depois antes de mexer na regra

Antes de importar qualquer JSON, rode a lógica nova sobre o histórico e classifique cada evento. É isso que vai pro dono da regra aprovar.

```kql
let LoginLocalSql = @"(?i)create\s+login\s+(?:\[([^\]]+)\]\s*|([A-Za-z_#@][^\s\[\]';]*)\s+)(?:with\b|from\s+(?:certificate|asymmetric\s+key)\b)";
SqlAudit_CL
| where Statement contains "CREATE LOGIN"
| extend Conta = coalesce(extract(LoginLocalSql, 1, Statement), extract(LoginLocalSql, 2, Statement))
| extend Motivo = case(
    isnotempty(Conta), "Local",
    Statement matches regex @"(?i)create\s+login\s+\[[^\]]+\]\s*from\s+(windows|external\s+provider)", "Rede",
    "Ruido (cita CREATE LOGIN sem criar)")
| summarize Eventos = count() by Motivo
```

Resultado de exemplo, inventado pra mostrar o formato:

| Motivo | Eventos | Alerta hoje | Alerta depois |
|---|---|---|---|
| Rede | 140 | sim | não |
| Ruido | 12 | sim | não |
| Local | 7 | sim | sim |

Confira duas coisas linha a linha: nenhum "Local" pode sair, e nenhum "Rede" ou "Ruido" pode ficar. Cruze também com os incidentes que a regra gerou. Se a maioria só tinha login de rede, o refinamento se paga no primeiro mês.

### 4. Meça o atraso de ingestão

Esse é o passo que quase ninguém faz e que explica dia sem alerta.

```kql
SqlAudit_CL
| where Statement contains "CREATE LOGIN"
| extend Ingestao = ingestion_time()
| extend AtrasoMin = datetime_diff('minute', Ingestao, EventTime)
| summarize Eventos = count(), P50 = percentile(AtrasoMin, 50), P95 = percentile(AtrasoMin, 95), Maximo = max(AtrasoMin) by Dia = bin(EventTime, 1d)
| order by Dia asc
```

Se o `P95` ou o `Maximo` passar da janela da regra, a regra está perdendo evento. E ela não avisa.

![Linha do tempo de um evento atrasado que nenhuma execução da regra enxerga](janela.svg){: width="900" height="380" }

> A regra roda, o `SentinelHealth` diz "executed successfully", e o evento atrasado nunca cai dentro de nenhuma janela. Sem erro, sem falha, sem alerta.
{: .prompt-danger }

Pra descartar a outra hipótese (regra que não rodou), olhe a saúde dela, se o monitoramento estiver ligado:

```kql
SentinelHealth
| where SentinelResourceName == "Nome da sua regra"
| summarize Execucoes = count(), Falhas = countif(Status != "Success") by Dia = bin(TimeGenerated, 1d)
| order by Dia asc
```

Vinte e quatro execuções por dia, zero falha e mesmo assim dia sem alerta? É atraso.

### 5. Janela longa e uma regra que lembra o que já alertou

A Microsoft documenta o padrão: aumentar a janela e filtrar por `ingestion_time() > ago(1h)`, pra cada evento ser pego uma vez, na hora em que chega. Funciona quando a hora de ingestão está disponível. Quando a função de auditoria não repassa essa hora, o filtro descarta tudo.

A saída é a regra consultar os próprios alertas. Cada evento ganha uma chave (banco, servidor, conta e hora), que vai num custom detail. Antes de alertar, a regra procura essa chave na `SecurityAlert` das últimas 48 horas.

```kql
let JaAlertados = SecurityAlert
    | where TimeGenerated > ago(2d)
    | where AlertName == "Nome da sua regra"
    | extend EventKey = tostring(parse_json(tostring(parse_json(ExtendedProperties)["Custom Details"])).EventKey[0])
    | where isnotempty(EventKey)
    | distinct EventKey;
let LoginLocalSql = @"(?i)create\s+login\s+(?:\[([^\]]+)\]\s*|([A-Za-z_#@][^\s\[\]';]*)\s+)(?:with\b|from\s+(?:certificate|asymmetric\s+key)\b)";
SqlAudit_CL
| where Statement contains "CREATE LOGIN"
| extend Conta = trim(" ", coalesce(extract(LoginLocalSql, 1, Statement), extract(LoginLocalSql, 2, Statement)))
| where isnotempty(Conta)
| extend EventKey = strcat("SQLServer|", ServerName, "|", Conta, "|", format_datetime(EventTime, "yyyy-MM-dd HH:mm:ss.fffffff"))
| where EventKey !in (JaAlertados)
| project TimeGenerated = EventTime, Servidor = ServerName, Conta, Executor = PrincipalName, SQLCommand = substring(Statement, 0, 1500), EventKey
```

> **Atenção ao limite dos custom details: 2 KB somados por alerta.** O que passar disso é descartado, sem aviso. Se o comando SQL vier num script longo, ele ocupa o espaço e a `EventKey` some do alerta. Sem a chave, a deduplicação para de funcionar e o mesmo evento alerta de novo a cada hora, por 24 horas. **Corte o comando** (`substring(..., 0, 1500)`) e deixe a chave pequena. O limite também vale pra quantidade: até 20 custom details por regra.
{: .prompt-danger }

Na configuração da regra:

- Frequência de 1 hora, janela de 1 dia (cobre atraso de até 23 horas).
- Um alerta por resultado, pra cada alerta carregar uma chave só.
- `EventKey` mapeado como custom detail.
- Agrupamento de incidentes por host numa janela de algumas horas, pra uma migração com dez logins não virar dez incidentes.

> Sem `ingestion_time()`, a própria `SecurityAlert` vira a memória da regra. A chave precisa ser estável: mesmo evento, mesma chave, em qualquer execução.
{: .prompt-tip }

Outra alternativa é a regra NRT, que trabalha pela hora de ingestão e dispensa tudo isso. O custo é que ela não converte a regra agendada: vira regra nova, com ID novo. A Microsoft também avisa que ela só funciona bem com fontes de atraso abaixo de 12 horas.

### 6. Depois de importar, vigie a duplicidade

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertName == "Nome da sua regra"
| extend EventKey = tostring(parse_json(tostring(parse_json(ExtendedProperties)["Custom Details"])).EventKey[0])
| summarize Alertas = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated) by EventKey
| where Alertas > 1 or isempty(EventKey)
```

Tem que voltar vazia. Chave repetida é deduplicação furada. Chave vazia é custom detail descartado.

## Falsos positivos comuns

- **O script `sp_help_revlogin`.** É o procedimento da própria Microsoft pra migrar logins entre instâncias. O texto dele monta `CREATE LOGIN ... WITH PASSWORD = ... HASHED`, e quem filtra só por `contains "CREATE LOGIN"` alerta a criação da procedure. O reconhecimento positivo descarta, porque depois de `CREATE LOGIN` vem uma aspa, não um nome.
- **Comentário de DBA.** Um `GRANT` com `-- depois do CREATE LOGIN` no final cai em qualquer filtro de texto.
- **Migração legítima.** O mesmo login criado em vários servidores na mesma tarde vira um evento por servidor. O agrupamento por host e a chave por servidor deixam isso legível.
- **Upgrade do Oracle.** Patch e upgrade podem criar contas internas `NO AUTHENTICATION`, executadas pelo `SYS`. Se a decisão for alertar, o SOC precisa saber que isso aparece em janela de manutenção.

## A pergunta que muda tudo

Não é "a regra está certa?". É **"a regra consegue ver o evento que chega atrasado?"**. Lógica perfeita com janela errada só fica perfeita no papel.

## Antes de dizer que está pronto

- [ ] Decisões de `EXTERNALLY`, `NO AUTHENTICATION` e contas de serviço registradas com o dono da regra.
- [ ] Antes e depois rodado no histórico: nenhum local saindo, nenhum rede ou ruído ficando.
- [ ] Atraso de ingestão medido, com o máximo menor que a janela.
- [ ] Custom details abaixo de 2 KB, com o comando cortado.
- [ ] Mesmo ID da regra, pra automações continuarem vinculadas.
- [ ] Consulta de duplicidade agendada pra rodar alguns dias depois.

## O que eu levo disso

- Filtro de exclusão é fácil de driblar. Reconhecer o que você quer é mais seguro.
- Regra agendada com janela curta perde evento atrasado em silêncio. Medir atraso faz parte de validar regra.
- Quando não dá pra usar `ingestion_time()`, a `SecurityAlert` serve de memória.
- Custom detail tem teto. Campo grande derruba campo pequeno.
- Antes e depois em tabela convence mais que qualquer explicação de regex.

## Referências

- [Handle ingestion delay in scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/ingestion-delay) (Microsoft Learn)
- [Near-real-time (NRT) analytics rules in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules) (Microsoft Learn)
- [Surface custom event details in alerts](https://learn.microsoft.com/en-us/azure/sentinel/surface-custom-details-in-alerts) (Microsoft Learn)
- [Monitor the health and audit the integrity of your analytics rules](https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity) (Microsoft Learn)
- [CREATE LOGIN (Transact-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/statements/create-login-transact-sql) (Microsoft Learn)
- [Transfer logins and passwords between instances of SQL Server](https://learn.microsoft.com/en-US/troubleshoot/sql/security/transfer-logins-passwords-between-instances) (Microsoft Learn)
- [CREATE USER](https://docs.oracle.com/en/database/oracle/oracle-database/21/sqlrf/CREATE-USER.html) (Oracle Database SQL Language Reference)
