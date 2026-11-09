---
title: "Quando o alerta vem do próprio EDR: revisão de uma regra do Sentinel que casava texto aleatório"
description: "Método pra descobrir o que uma regra de linha de comando realmente casou, provar que foi o próprio Defender e refazer a regra sem perder detecção."
date: 2026-11-10 09:00:00 -0300
categories: [Na prática, Sentinel]
tags: [sentinel, kql, defender for endpoint, defender xdr, mitre att&ck, detection engineering]
media_subpath: /assets/img/posts/quando-o-alerta-vem-do-proprio-edr
---

Severidade alta. PowerShell com `-ExecutionPolicy Bypass`, rodando como SYSTEM, numa estação comum. E a regra jurando que achou um cmdlet do Nishang. Todo mundo já viu esse filme, e quase sempre o vilão é alguém da própria TI. Às vezes é pior: o vilão é o EDR.

## O cenário

Uma regra analítica no Sentinel procura nomes de cmdlets de um framework ofensivo de PowerShell na linha de comando dos processos. Ela dispara, o incidente nasce com severidade alta e a primeira pergunta é a de sempre: **é ataque ou não é?**

O Nishang é real e perigoso. É um conjunto de scripts ofensivos em PowerShell, com reverse shell, dump de credenciais, keylogger e bypass de AMSI ([GitHub do projeto](https://github.com/samratashok/nishang)). Faz sentido ter detecção pra ele. A questão é o que a detecção está olhando.

> Antes de discutir se foi ataque, descubra exatamente o que a regra casou. Metade dos falsos positivos morre nessa pergunta.
{: .prompt-tip }

## Como um cmdlet que nunca rodou aparece na linha de comando

![Cadeia de processos do sensor do Defender até o script, com o parâmetro em base64 e a diferença entre contains e has](cadeia.svg){: width="900" height="400" }
_Diagrama de referência. O trecho em base64 é ilustrativo._

O Defender for Endpoint roda scripts próprios em PowerShell. A descoberta de dispositivos, por exemplo, usa as máquinas já integradas pra observar o tráfego e **sondar ativamente** a rede atrás de equipamentos não gerenciados ([Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/device-discovery)). Quem dispara isso é o `SenseIR.exe`, filho do `MsSense.exe`, e os parâmetros vão em base64, muitas vezes comprimidos.

Base64 é uma sopa de letras. Se a regra procura texto com `contains`, que ignora maiúscula e minúscula e não exige limite de palavra, mais cedo ou mais tarde seis letras em sequência vão formar `FAKEdc`. E pronto, nasceu um "FakeDC".

## Como fazer

### 1. Qual termo casou, e onde?

A primeira consulta não investiga o ataque. Ela pega a lista da regra e mostra o trecho exato onde cada termo apareceu.

```kql
let dev = "<DISPOSITIVO>";
let t0 = datetime(2026-01-01 12:00:00);   // horário do alerta, em UTC
let kw = dynamic(["FakeDC","exfill","Nishang","Invoke-PortScan","Get-PassHashes"]); // use a lista completa da regra
union withsource=Tabela DeviceEvents, DeviceProcessEvents
| where Timestamp between (t0 - 30m .. t0 + 30m)
| where DeviceName startswith dev
| extend Cmd = strcat(InitiatingProcessCommandLine, " <<>> ", ProcessCommandLine)
| mv-apply k = kw to typeof(string) on (
    where Cmd contains k
    | extend Pos = indexof(tolower(Cmd), tolower(k))
    | extend Contexto = substring(Cmd, max_of(Pos - 80, 0), 200)
    | summarize Termos = make_set(k), Contextos = make_set(Contexto, 5)
  )
| where array_length(Termos) > 0
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, Termos, Contextos
```

Se o `Contexto` mostrar o termo cercado de letras aleatórias, você já sabe pra onde a investigação vai.

### 2. Quem é o pai?

```kql
let dev = "<DISPOSITIVO>";
let t0 = datetime(2026-01-01 12:00:00);
DeviceProcessEvents
| where Timestamp between (t0 - 1h .. t0 + 1h)
| where DeviceName startswith dev
| where InitiatingProcessFileName in~ ("SenseIR.exe","powershell.exe","pwsh.exe")
     or FileName in~ ("SenseIR.exe","powershell.exe","pwsh.exe")
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName,
          AccountName, ProcessCommandLine, SHA1
| order by Timestamp asc
```

Exemplo do resultado (dados inventados):

| Pai do pai | Pai | Processo | Conta |
|---|---|---|---|
| services.exe | MsSense.exe | SenseIR.exe | SYSTEM |
| MsSense.exe | SenseIR.exe | powershell.exe | SYSTEM |
| SenseIR.exe | powershell.exe | powershell.exe | LOCAL SERVICE |

`services.exe → MsSense.exe → SenseIR.exe` é o caminho do próprio sensor.

> SenseIR na cadeia não é passe livre. Live Response também passa por ele, e uma conta de admin comprometida pode usar o portal pra rodar script. Prove o conteúdo, não só o pai.
{: .prompt-danger }

### 3. O que tem dentro do parâmetro?

O `SenseIR.exe` costuma receber um JSON em base64 (começa com `eyJ`). Dá pra abrir direto no KQL:

```kql
let dev = "<DISPOSITIVO>";
let t0 = datetime(2026-01-01 12:00:00);
DeviceProcessEvents
| where Timestamp between (t0 - 30m .. t0 + 30m)
| where DeviceName startswith dev
| where FileName =~ "SenseIR.exe" or InitiatingProcessFileName =~ "SenseIR.exe"
| extend Cmd = iff(FileName =~ "SenseIR.exe", ProcessCommandLine, InitiatingProcessCommandLine)
| extend B64 = extract(@"(eyJ[A-Za-z0-9+/=_-]+)", 1, Cmd)
| where isnotempty(B64)
| distinct Timestamp, Json = base64_decode_tostring(B64)
```

O parâmetro do script (`-ParamsAsBase64 ... -IsCompressed True`) é outro bicho: quatro bytes de tamanho e depois um gzip. Esse eu abro fora do portal, em PowerShell:

```powershell
$b64 = '<COLE AQUI O VALOR DE -ParamsAsBase64>'
$bytes = [Convert]::FromBase64String($b64)
$ms = [IO.MemoryStream]::new($bytes, 4, $bytes.Length - 4)   # pula os 4 bytes de tamanho
$gz = [IO.Compression.GZipStream]::new($ms, [IO.Compression.CompressionMode]::Decompress)
[IO.StreamReader]::new($gz).ReadToEnd()
```

Se sair um JSON com lista de IPs, MACs e identificadores de dispositivo, é a varredura de rede do Defender. E o termo que a regra "achou" não vai estar no texto decodificado. Ele só existia na forma codificada.

> O JSON decodificado traz IP interno, MAC e identificador de máquina. Não cole isso em decodificador online.
{: .prompt-warning }

### 4. O que o PowerShell executou de verdade?

Linha de comando mostra o que foi pedido. O AMSI mostra o que rodou.

```kql
let dev = "<DISPOSITIVO>";
let t0 = datetime(2026-01-01 12:00:00);
DeviceEvents
| where Timestamp between (t0 - 2h .. t0 + 2h)
| where DeviceName startswith dev
| where ActionType == "PowerShellCommand"
| extend Comando = tostring(parse_json(AdditionalFields).Command)
| summarize Vezes = count(), Primeiro = min(Timestamp) by Comando, InitiatingProcessFileName
| order by Primeiro asc
```

Funções como `Scan-Device`, `Scan-Smb`, `Discover-mDnsDevices` e `Scan-Ldap` são o scanner do Defender. Cmdlet do Nishang não aparece. Fecha com a rede: conexões só pra infraestrutura da Microsoft e pras máquinas que estavam na lista do JSON.

### 5. Quantas vezes essa regra já acertou?

Essa é a consulta que muda a conversa. Ela compara a lógica atual com a proposta, em toda a organização:

```kql
let kw = dynamic(["FakeDC","exfill","Nishang","Invoke-PortScan","Get-PassHashes"]); // lista completa da regra
union DeviceEvents, DeviceProcessEvents
| where Timestamp > ago(30d)
| extend Cmd = strcat(InitiatingProcessCommandLine, " <<>> ", ProcessCommandLine)
| mv-apply k = kw to typeof(string) on (where Cmd contains k | summarize Termos = make_set(k))
| where array_length(Termos) > 0
| extend Proposta = InitiatingProcessCommandLine has_any (kw) or ProcessCommandLine has_any (kw)
| summarize Eventos = count(), Maquinas = dcount(DeviceName),
            Exemplos = make_set(strcat(DeviceName, " | ", InitiatingProcessFileName, " > ", FileName), 5)
    by Proposta, TermosTxt = tostring(Termos)
```

`Proposta = false` é o que deixa de disparar com o ajuste. Se tudo que some for colisão, o ajuste é seguro.

> O Advanced Hunting guarda 30 dias. Pra olhar mais pra trás, rode a mesma lógica no Logs do Sentinel, com `TimeGenerated`.
{: .prompt-info }

## Falsos positivos comuns

| Onde o termo apareceu | Por que casa | Como reconhecer |
|---|---|---|
| Parâmetro em base64 de script do EDR | Letras aleatórias formam o nome | Pai `SenseIR.exe`, termo cercado de base64 |
| Pasta temporária do `Add-Type` | O .NET gera nomes aleatórios de 8 letras, e às vezes eles formam um termo da lista | `csc.exe` compilando em `SystemTemp` ou `Temp` |
| Link aberto pelo Teams ou Outlook | Token ou cookie do Safe Links na URL | `ms-teams.exe > msedge.exe`, URL do safelinks |
| Nome de arquivo | Alguém abriu um PDF ou doc com o nome da ferramenta no título | Navegador ou leitor de PDF, termo como palavra inteira |

O último é o mais irônico: **a documentação do próprio SOC sobre a ferramenta, aberta no navegador, já basta pra regra disparar.**

## A pergunta que muda tudo

Depois de provar que foi o Defender, a pergunta deixa de ser "foi ataque?" e vira **"essa regra já pegou alguma coisa de verdade?"**.

A lista de cmdlets geralmente vem de uma regra Sigma escrita pra script block logging, ou seja, pra texto de script ([regra Sigma original](https://detection.fyi/sigmahq/sigma/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets/)). Portada pra linha de comando, ela erra dos dois lados. Casa texto aleatório. E não vê o uso real, porque o Nishang quase sempre é carregado em memória com um `IEX (New-Object Net.WebClient).DownloadString(...)`, e o nome do cmdlet nunca passa pela linha de comando.

> Uma regra que só gera falso positivo e não cobre o uso real não é detecção. É barulho com severidade alta.
{: .prompt-danger }

## Como refazer a regra

Quatro mudanças:

1. **`has_any` no lugar de `contains`.** O `has` compara termos inteiros, e termo é uma sequência de letras e números ([Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators)). O próprio exemplo da documentação: `"KustoExplorerQueryRun" has "Explorer"` é falso. `FAKEdc` dentro do base64 vira um termo só, e ele não é `FakeDC`.
2. **Exigir PowerShell na cadeia.** O Nishang é PowerShell, e a técnica é T1059.001 ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/001/)). Isso derruba navegador, Teams e leitor de PDF.
3. **Ler os comandos do AMSI.** É ali que o carregamento em memória aparece.
4. **Revisar a lista.** Confira se as ferramentas mais usadas do framework estão nela, como a reverse shell `Invoke-PowerShellTcp`.

```kql
let kw = dynamic(["Invoke-PowerShellTcp","Invoke-PortScan","Get-PassHashes","Invoke-AmsiBypass","Nishang"]); // lista completa
let ps = dynamic(["powershell.exe","pwsh.exe","powershell_ise.exe"]);
let PorLinhaDeComando =
    union DeviceEvents, DeviceProcessEvents
    | where FileName in~ (ps) or InitiatingProcessFileName in~ (ps)
    | where InitiatingProcessCommandLine has_any (kw) or ProcessCommandLine has_any (kw)
    | extend Origem = "CommandLine", ComandoAmsi = "";
let PorAmsi =
    DeviceEvents
    | where ActionType == "PowerShellCommand"
    | extend ComandoAmsi = tostring(parse_json(AdditionalFields).Command)
    | where ComandoAmsi has_any (kw)
    | extend Origem = "AMSI";
union PorLinhaDeComando, PorAmsi
| project TimeGenerated, Origem, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, FileName, InitiatingProcessCommandLine, ProcessCommandLine, ComandoAmsi
```

O que se perde: cmdlet colado em outro texto sem separador (isso já é ofuscação, que nenhuma das versões pegava) e Nishang rodando dentro de outro executável .NET (que ainda passa pelo AMSI).

## Antes de dizer que está resolvido

- [ ] Sei o termo exato que casou e o trecho onde ele estava.
- [ ] A cadeia de processos sai de `services.exe → MsSense.exe → SenseIR.exe`.
- [ ] O conteúdo decodificado é do Defender, não um script qualquer de Live Response.
- [ ] O AMSI não mostra cmdlet ofensivo e a rede não mostra destino estranho.
- [ ] A regra nova foi comparada com a antiga no histórico.
- [ ] **A regra nova passou num teste positivo.**

Esse último é o que mais se esquece. Zero resultados numa regra nova pode ser regra boa ou consulta quebrada. Um teste inofensivo resolve:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Invoke-PowerShellTcp teste do SOC'"
```

Não executa nada, só imprime o texto. Combine antes com o cliente, porque vai abrir um incidente de severidade alta. O esperado são duas linhas: uma com `Origem = CommandLine` e outra com `Origem = AMSI`. Se vier uma só, o ramo que faltou está quebrado.

## O que eu levo disso

- Primeiro descubra o que a regra casou. Depois investigue o ataque.
- O EDR também roda PowerShell com Bypass como SYSTEM. Conhecer o que ele faz evita falso alarme.
- Regra Sigma de script block não funciona igual em linha de comando.
- `contains` em texto aleatório é questão de tempo. `has` é o padrão pra nome de comando.
- Zero resultados não prova nada. Teste positivo prova.

## Referências

- [Device discovery overview, Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/device-discovery)
- [has operator, Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/has-operator)
- [String operators e o que é um termo, Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators)
- [T1059.001 Command and Scripting Interpreter: PowerShell, MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/001/)
- [Nishang, GitHub](https://github.com/samratashok/nishang)
- [Malicious Nishang PowerShell Commandlets, regra Sigma (detection.fyi)](https://detection.fyi/sigmahq/sigma/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets/)
