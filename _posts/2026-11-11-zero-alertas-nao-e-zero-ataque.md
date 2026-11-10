---
title: "Zero alertas não é zero ataque: como checar se uma CVE crítica te pegou"
description: "Método pra caçar exploração de uma CVE crítica com firewall, SIEM e EDR, e a pergunta que vem antes de dizer que está limpo."
date: 2026-11-11 09:00:00 -0300
categories: [Na prática, Threat Hunting]
tags: [threat-hunting, vulnerabilidade, kql, sentinel, defender xdr, firewall, palo alto]
media_subpath: /assets/img/posts/zero-alertas-nao-e-zero-ataque
---

Sai uma CVE crítica, o fabricante soltou o patch ontem e a pergunta chega antes do café: "a gente foi afetado?". Você roda a consulta das assinaturas, volta vazia, e dá aquele alívio. Pois é. **Zero resultado é a resposta mais perigosa que um hunting pode devolver**, porque ela parece boa notícia e quase nunca vem com a letra miúda.

## O cenário

O pedido é sempre parecido. Apareceu uma vulnerabilidade de execução remota sem autenticação, tem exploit público circulando, e alguém quer saber se houve exploração no ambiente. Às vezes vem com um tempero extra: um alerta externo, vago, dizendo que "alguém do setor" pode ter sido comprometido.

Vou usar como exemplo o **PHP2Shell** (CVE-2026-109618 e CVE-2026-109619), duas falhas no PHP que permitem execução remota de código sem login. Ele é bom de exemplo porque tem tudo: exploração antes da divulgação, exploits públicos em poucas horas e assinatura de IPS liberada pelos fabricantes de firewall. O método serve pra qualquer CVE do mesmo tipo.

## O ambiente típico

![Ambiente típico: internet, firewall de borda, DMZ, portal de VPN, rede interna, SIEM e EDR](ambiente.svg){: width="900" height="520" }
_Diagrama de referência. Os números marcam as três perguntas que mudam o peso da conclusão._

Firewall de próxima geração na borda, publicando servidores web na DMZ e um portal de VPN. Os logs do firewall vão pro SIEM (no exemplo, Microsoft Sentinel). Os servidores com agente mandam telemetria pro EDR (no exemplo, Defender XDR). Nada de exótico. É o desenho de muita empresa.

## Como fazer

### 1. Comece a janela na primeira exploração, não no patch

A Amazon Threat Intelligence viu a primeira tentativa de exploração do PHP2Shell no honeypot dela **quatro dias antes** da divulgação. Quem corrigiu no dia do patch ainda pode ter sido alvo antes.

![Linha do tempo de uma CVE crítica, da primeira exploração até a análise](linha-do-tempo.svg){: width="900" height="340" }
_O trecho em vermelho é o que quase ninguém confere: quanto tempo a assinatura levou pra chegar no seu firewall._

> A janela de busca começa na primeira exploração conhecida. Procure no post do provedor que viu o ataque, não só no aviso do fabricante.
{: .prompt-tip }

### 2. Procure as assinaturas no firewall

O fabricante publica a lista de Threat IDs que cobrem a CVE. No `CommonSecurityLog` do Palo Alto, o nome e o ID da ameaça às vezes só aparecem dentro do `AdditionalExtensions`, então a consulta tira dos dois lugares.

```kql
let Inicio = datetime(2026-01-01);          // primeira exploração conhecida
let IDs = dynamic(["543004", "97622", "97623", "97624", "97625"]);   // use a lista completa do aviso
CommonSecurityLog
| where TimeGenerated >= Inicio
| where DeviceVendor has "Palo Alto" and DeviceProduct == "PAN-OS"
| where Activity =~ "THREAT" or DeviceEventClassID =~ "THREAT"
| extend Ameaca = coalesce(
    iff(DeviceCustomString6Label =~ "Threat Name", DeviceCustomString6, ""),
    extract(@"ThreatName=([^;]+)", 1, AdditionalExtensions),
    DeviceEventCategory)
| extend IdAmeaca = coalesce(extract(@"\((\d{4,7})\)", 1, Ameaca), extract(@"ThreatID=(\d+)", 1, AdditionalExtensions))
| extend Acao = coalesce(DeviceAction, extract(@"Action=([^;]+)", 1, AdditionalExtensions))
| where IdAmeaca in (IDs) or Ameaca has_any ("PHP2Shell", "CVE-2026-109618", "CVE-2026-109619")
| summarize Eventos = count(), Primeiro = min(TimeGenerated), Ultimo = max(TimeGenerated), Acoes = make_set(Acao)
    by SourceIP, DestinationIP, Ameaca, IdAmeaca
```

Se voltar alguma linha, olhe a coluna `Acoes`. `alert` quer dizer que o firewall viu e **deixou passar**.

### 3. Cruze com os IOCs da fonte primária

Os provedores que viram o ataque publicam IPs. Use os deles primeiro, e depois os de terceiros. Procure no firewall e nos dispositivos com EDR.

```kql
let IOCs = dynamic(["203.0.113.10", "203.0.113.25", "198.51.100.7"]);   // troque pelos IPs publicados
DeviceNetworkEvents
| where Timestamp >= datetime(2026-01-01)
| where RemoteIP in (IOCs)
| summarize Eventos = count(), Primeiro = min(Timestamp), Ultimo = max(Timestamp),
    Processos = make_set(InitiatingProcessFileName)
    by DeviceName, RemoteIP, RemotePort
```

> Muitos desses IPs são infraestrutura de anonimização compartilhada. Um hit não prova ataque, mas obriga a investigar o que aconteceu naquela sessão.
{: .prompt-warning }

### 4. Lembre que o próprio equipamento pode ser alvo

Firewall e console de gerência também rodam serviço web. No caso do PHP2Shell, o fabricante do firewall confirmou que a interface de gerência era afetada. Confira se ela aceita conexão da internet, se houve login administrativo de IP externo e se algum processo de gerência travou ou reiniciou no período. O PHP2Shell explora justamente o tratamento de erro por falta de memória do PHP.

### 5. Procure execução nos servidores

Exploração bem-sucedida deixa rastro de execução. O servidor web passa a iniciar shell, ferramenta de download ou comando de reconhecimento.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2026-01-01)
| where InitiatingProcessFileName startswith "php"
    or InitiatingProcessFileName in~ ("httpd", "apache2", "nginx", "lsphp", "httpd.exe", "w3wp.exe")
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "python3", "perl", "nc",
    "whoami", "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe")
| summarize Execucoes = count(), Primeiro = min(Timestamp), Comandos = make_set(ProcessCommandLine, 20)
    by DeviceName, InitiatingProcessFileName, FileName
| sort by Primeiro asc
```

E os arquivos que um webshell deixa pra trás:

```kql
DeviceFileEvents
| where Timestamp >= datetime(2026-01-01)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName endswith ".php" or FileName endswith ".phtml" or FileName =~ ".htaccess"
| where InitiatingProcessFileName startswith "php"
    or InitiatingProcessFileName in~ ("httpd", "apache2", "nginx", "lsphp", "httpd.exe", "w3wp.exe")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, SHA256
```

Resultado de exemplo da consulta de execução (inventado, pra mostrar a leitura):

| Dispositivo | Processo pai | Filho | O que era |
|---|---|---|---|
| SRV-WEB-*** | w3wp.exe | cmd.exe | aplicação legada chamando comando do sistema |
| SRV-APP-*** | httpd.exe | cmd.exe | rotação de log do Apache |
| SRV-K8S-*** | nginx | sh | container subindo depois de deploy |

Nenhuma das três é ataque. Mas você só sabe disso depois de ler a linha de comando de cada uma.

## Falsos positivos comuns

| O que parece ataque | O que costuma ser | Como provar |
|---|---|---|
| Servidor web abrindo `cmd.exe` ou `sh` | Aplicação legada chamando comando do sistema (impressão, log, integração) | A linha de comando e a recorrência: rotina roda igual todo dia |
| Container web executando shell logo depois de um ataque | Deploy subindo container novo com scripts de inicialização | O que aconteceu nos segundos antes: sincronização do pipeline de deploy |
| Estação com alerta de "código PHP em imagem" | Usuário navegando e baixando arquivo de um site qualquer | Processo de origem (navegador) e ausência de arquivo gravado |
| Conexão de IP interno para o IP do atacante | O próprio portal ou balanceador respondendo à varredura | Sessão sem handshake completo, sem aplicação identificada |
| Consulta DNS ao domínio da CVE | Alguém da equipe lendo sobre o assunto | Sem tráfego depois, só a resolução de nome |
| Servidor "mais atacado" é o mesmo que fez algo estranho | IP público de saída compartilhado por NAT | O IP de entrada e o de saída são serviços diferentes |

> Leia o aviso do fabricante antes de correr atrás do portal de VPN. No PHP2Shell, o fabricante do firewall confirmou que o portal e o gateway de VPN não eram afetados, só a interface de gerência.
{: .prompt-info }

## A pergunta que muda tudo

Tudo limpo até aqui? Então vem a pergunta que separa um hunting de verdade de um "rodei a query e não deu nada": **o ambiente tinha como ver o ataque?**

São três checagens. Cada uma pode zerar o valor das consultas anteriores.

**1. A assinatura estava instalada em cada firewall?** O fabricante libera, a console de gerência baixa e distribui. Só que o job de distribuição pode falhar, e um equipamento pode ficar de fora. Confira a versão de assinatura em cada firewall, não só na console. No PAN-OS:

```bash
show system info | match app-version
```

> Já vi job de atualização de assinatura falhando todo dia, em silêncio, e firewall de borda passando dias sem a assinatura nova. Ninguém olha log de sistema de firewall até precisar dele.
{: .prompt-danger }

**2. O firewall enxerga o corpo da requisição?** O PHP2Shell vai dentro de um POST. Se o HTTPS de entrada não é decriptado, a assinatura não tem o que ler. No log do Palo Alto o destino aparece com o IP público, então use o endereço traduzido pra chegar ao servidor:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor has "Palo Alto" and DeviceProduct == "PAN-OS"
| where Activity =~ "TRAFFIC" and DeviceEventClassID =~ "end"
| where DestinationPort == 443 and not(ipv4_is_private(SourceIP)) and not(ipv4_is_private(DestinationIP))
| extend DestinoInterno = coalesce(DestinationTranslatedAddress, extract(@"NATDestinationIP=([^;]+)", 1, AdditionalExtensions))
| where isnotempty(DestinoInterno) and ipv4_is_private(DestinoInterno)
| extend App = coalesce(ApplicationProtocol, extract(@"Application=([^;]+)", 1, AdditionalExtensions))
| summarize Sessoes = count() by DeviceName, DestinoInterno, App
| sort by Sessoes desc
```

Se os servidores publicados aparecem quase só como `ssl`, o firewall não está abrindo o HTTPS. Se aparecem como `web-browsing` ou com o nome da aplicação, tem inspeção.

**3. Os servidores publicados têm EDR?** Pegue a lista de `DestinoInterno` da consulta anterior e procure no EDR:

```kql
let Publicados = dynamic(["10.0.10.21", "10.0.10.22", "10.0.10.23"]);   // destinos internos da consulta anterior
DeviceNetworkInfo
| where Timestamp > ago(7d)
| mv-expand Ip = parse_json(IPAddresses)
| extend IP = tostring(Ip.IPAddress)
| where IP in (Publicados)
| summarize Ultimo = max(Timestamp) by IP, DeviceName
```

O IP que não aparecer não tem agente. Nesses servidores, as consultas do passo 5 nunca chegaram.

## Antes de dizer que está limpo

- [ ] Janela começando na primeira exploração conhecida
- [ ] Lista completa de Threat IDs do aviso do fabricante
- [ ] IOCs da fonte primária e de terceiros, no firewall e no EDR
- [ ] Interface de gerência dos equipamentos: exposição, login, falha de processo
- [ ] Execução e criação de arquivo por processo web
- [ ] Versão de assinatura conferida **em cada** firewall
- [ ] Inspeção de HTTPS nos serviços publicados
- [ ] EDR nos servidores publicados
- [ ] Inventário de PHP (ou do software da CVE), incluindo versões fora de suporte

E escreva a conclusão com o limite dela. Em vez de "não houve exploração", algo assim:

> Não identifiquei indício de exploração bem-sucedida nos ativos com visibilidade. Nos servidores publicados sem EDR e sem inspeção de HTTPS, a análise não permite afirmar nem descartar exploração.

Essa segunda frase é a que mais ajuda o cliente, porque vira plano de ação.

## O que eu levo disso

- Zero em assinatura só vale depois de conferir três coisas: assinatura instalada, decriptação e EDR no alvo.
- Janela de busca começa na primeira exploração, não no patch.
- IOC da fonte primária entra na primeira rodada.
- No `CommonSecurityLog` do Palo Alto, o servidor de verdade está no `DestinationTranslatedAddress`.
- Toda pista suspeita precisa ser derrubada com dado. Às vezes a explicação está nos 30 segundos antes do evento.
- Conclusão boa tem limite escrito. "Está tudo bem" não ajuda ninguém a corrigir nada.

## Referências

- [Amazon Threat Intelligence identifies PHP2Shell exploitation prior to public disclosure in MadPot](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) (AWS Security Blog)
- [CVE-2026-109618: Impact of Critical Vulnerabilities in PHP on Palo Alto Networks Products](https://security.paloaltonetworks.com/CVE-2026-109618) (Palo Alto Networks Security Advisories)
- [Threat Brief: Critical Vulnerabilities in PHP: CVE-2026-109618, CVE-2026-109619](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/) (Unit 42)
