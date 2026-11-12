---
title: "O Defender disse zero: medindo e corrigindo um 0-day do Outlook com KQL e Intune"
description: "Como medir a exposição real a uma CVE do Office por build, sem esperar o painel do Defender, e corrigir o parque com Intune Remediations em ondas."
date: 2026-11-13 09:00:00 -0300
categories: [Na prática, Intune]
tags: [intune, remediations, kql, defender vulnerability management, microsoft 365 apps, vulnerabilidade]
media_subpath: /assets/img/posts/o-defender-disse-zero
---

Sai um 0-day do Outlook com exploração confirmada. Você abre o Defender, procura a CVE, e lá está ela: "No action required", zero dispositivos expostos. Dá aquela vontade de fechar a aba e ir tomar café. Não vá. Zero, nas primeiras horas de uma CVE, quase sempre quer dizer "ainda não olhei".

## O cenário

O pedido é sempre o mesmo: "saiu essa CVE, a gente está vulnerável?". Normalmente chega com o link de uma notícia e um prazo de "pra ontem".

Nesse caso a vulnerabilidade era no Outlook. Um arquivo de mensagem malicioso faz o cliente se conectar num servidor do atacante sem o aviso de conteúdo externo, e o hash NTLMv2 do usuário vai junto. A Microsoft corrigiu no Patch Tuesday de novembro de 2026 e marcou como explorada.

A pergunta parece simples. A resposta do portal é que engana.

## O ambiente típico

Parque Windows com Microsoft 365 Apps (Click-to-Run), Defender for Endpoint com Vulnerability Management e Intune gerenciando os dispositivos. Nada exótico.

O que pouca gente lembra é que entre o patch sair e o Defender te mostrar quem está exposto existem relógios diferentes:

![Linha do tempo do patch até o Exposed devices](linha-do-tempo.svg){: width="900" height="340" }
_Prazos típicos, não oficiais. Variam de CVE pra CVE._

| O que | Tabela | Responde |
|---|---|---|
| Catálogo de vulnerabilidades | `DeviceTvmSoftwareVulnerabilitiesKB` | "Essa CVE existe e afeta qual produto?" |
| Avaliação por dispositivo | `DeviceTvmSoftwareVulnerabilities` | "Quais máquinas minhas estão expostas?" |
| Inventário de software | `DeviceTvmSoftwareInventory` | "Que versão está instalada em cada máquina?" |

**O painel "Exposed devices" depende da segunda linha.** Se ela ainda não rodou pra essa CVE, ele mostra zero. O inventário, a terceira linha, já está lá desde antes da CVE existir.

> "No action required" com 0 exposed devices, nos primeiros dias de uma CVE, não é evidência de nada. Não use esse print pra dizer ao cliente que ele está seguro.
{: .prompt-danger }

## Como fazer

### 1. Confirmar que a CVE está no catálogo

Primeiro, saber se o problema é "a CVE não existe aqui" ou "a CVE existe e ninguém foi avaliado".

```kql
DeviceTvmSoftwareVulnerabilitiesKB
| where CveId =~ "CVE-2026-124194"
| mv-expand AffectedSoftware
| project CveId, PublishedDate, IsExploitAvailable, VulnerabilitySeverityLevel, AffectedSoftware
```

Se voltar linha com `AffectedSoftware` apontando pro Office e a tela de Exposed devices estiver vazia, você está na zona do falso negativo. `IsExploitAvailable = 1` também é um dado bom pra levar pro relatório: é o próprio Defender confirmando exploit em circulação.

### 2. Ver como o Office aparece no inventário

O nome do produto muda de ambiente pra ambiente. Antes de filtrar, olhe.

```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "microsoft"
| where SoftwareName has "office" or SoftwareName has "outlook"
| summarize Devices = dcount(DeviceId) by SoftwareName
| sort by Devices desc
```

O Click-to-Run costuma aparecer só como `office`, seja Microsoft 365 Apps ou Office LTSC. Quem diferencia os dois é o número do build.

> `DeviceTvmSoftwareInventory` é uma foto, não um log. Ela não tem coluna `Timestamp`. Se você copiar um `arg_max(Timestamp, *)` de outra consulta, vai tomar erro de semântica.
{: .prompt-info }

### 3. Montar a tabela de builds corrigidos

A Microsoft publica os builds de cada canal na página de notas de segurança do Office. Pro patch de 10/11/2026 a tabela ficou assim:

| Produto e canal | Versão | Build corrigido |
|---|---|---|
| Current Channel | 2610 | 20527.20196 |
| Monthly Enterprise | 2610 / 2609 / 2608 | 20527.20194 / 20430.20264 / 20326.20320 |
| Semi-Annual Enterprise | 2610 / 2609 / 2608 | 20527.20192 / 20430.20262 / 20326.20318 |
| Office LTSC 2024 | 2408 | 17932.21140 |
| Office LTSC 2021 | 2108 | 14334.21048 |

O terceiro número da versão (`16.0.XXXXX.YYYYY`) diz a família. O quarto diz se ela já tem o patch.

### 4. Classificar cada máquina

```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "microsoft" and SoftwareName == "office"
| where SoftwareVersion startswith "16.0."
| distinct DeviceId, DeviceName, SoftwareVersion
| extend Build = toint(split(SoftwareVersion, ".")[2]), Rev = toint(split(SoftwareVersion, ".")[3])
| extend Status = case(
    Build == 17932 and Rev >= 21140, "Corrigido",
    Build == 14334 and Rev >= 21048, "Corrigido",
    Build == 20527 and Rev >= 20192, "Corrigido",
    Build == 20430 and Rev >= 20262, "Corrigido",
    Build == 20326 and Rev >= 20318, "Corrigido",
    Build > 20527, "Corrigido",
    "Vulneravel")
| project DeviceName, SoftwareVersion, Status
| sort by Status asc, DeviceName asc
```

Usei o menor build de cada família (o do Semi-Annual) como corte. Assim uma máquina Semi-Annual já corrigida não aparece como vulnerável por engano.

Pro relatório executivo, o resumo:

```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "microsoft" and SoftwareName == "office"
| where SoftwareVersion startswith "16.0."
| distinct DeviceId, SoftwareVersion
| summarize Devices = dcount(DeviceId) by SoftwareVersion
| sort by Devices desc
```

### 5. Ler o resultado

Resultado de exemplo, inventado pra ilustrar:

| SoftwareVersion | Devices | Leitura |
|---|---|---|
| 16.0.20430.20180 | 180 | Todo mundo no mesmo build antigo |
| 16.0.20527.20150 | 12 | Current Channel, um update atrás |
| 16.0.20527.20194 | 2 | Já corrigido |
| 16.0.19127.20936 | 1 | Mais de um ano sem atualizar |

**Muita máquina parada no mesmo build exato não é atraso de rollout.** Rollout gradual espalha versões. Um bloco grande e uniforme cheira a versão fixada por política (`TargetVersion` no Intune ou no ODT). Se for isso, o patch não chega sozinho nunca.

### 6. Corrigir com Intune Remediations

Por que Remediations e não só esperar o update automático:

- o detect mede a versão local e sai em silêncio se já está corrigido;
- o remediate dispara o update na hora, sem esperar o rollout gradual;
- o output de cada máquina aparece no portal, e dá pra exportar.

O coração do detect é ler a versão, o canal e as políticas que travam o update:

```powershell
$cfg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
$pol = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" -ErrorAction SilentlyContinue

$ver = [version]$cfg.VersionToReport
$targetVersion = if ($pol.updatetargetversion) { $pol.updatetargetversion } else { "nenhum" }

Write-Output "Versao=$($cfg.VersionToReport);TargetVersion=$targetVersion;AutoUpdate=$($pol.enableautomaticupdates)"
```

O remediate é uma linha que importa:

```powershell
& "$env:ProgramFiles\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" /update user displaylevel=false forceappshutdown=false
```

Os dois scripts completos estão prontos pra baixar:

| Script | Download |
|---|---|
| Detect | [Detect-OfficeOutlookCVE-2026-124194.ps1](/intune-remediations/office-outlook-cve-2026-124194/Detect-OfficeOutlookCVE-2026-124194.ps1){: download="Detect-OfficeOutlookCVE-2026-124194.ps1" } |
| Remediate | [Remediate-OfficeOutlookCVE-2026-124194.ps1](/intune-remediations/office-outlook-cve-2026-124194/Remediate-OfficeOutlookCVE-2026-124194.ps1){: download="Remediate-OfficeOutlookCVE-2026-124194.ps1" } |

A tabela de builds e o passo a passo de configuração estão no [README da pasta no GitHub](https://github.com/mikionakamaru/mikionakamaru.github.io/tree/main/intune-remediations/office-outlook-cve-2026-124194).

Sem `updatetoversion`. O Click-to-Run baixa o build mais novo **do canal da própria máquina**. Forçar um build específico do Current Channel numa máquina Monthly Enterprise ou falha, ou troca o canal sem ninguém pedir.

Configuração no Intune:

| Campo | Valor |
|---|---|
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | Yes |
| Schedule | Hourly, intervalo 1 |

> Não use agendamento "Once". O download pode não terminar na primeira execução e o Outlook aberto segura a aplicação do update. Com Hourly, a máquina já corrigida sai no detect e não roda nada de novo.
{: .prompt-tip }

Se o output mostrar `TargetVersion` preenchido, o script vai rodar e não vai mudar nada. A correção é na política: Settings Catalog, Microsoft 365 Apps, Updates. Tire o Target Version e ligue um Update Deadline de alguns dias pra fechar o Outlook de quem nunca fecha.

### 7. Rollout em ondas

![Três ondas de rollout com grupos de dispositivos](ondas.svg){: width="900" height="330" }
_Diagrama de referência._

Piloto com as máquinas da TI, depois o parque sem a diretoria, depois a diretoria. **Todos os grupos de dispositivos, nenhum de usuários.** O Intune não garante uma exclusão quando o include é de um tipo e o exclude é de outro. Grupo de usuário na exclusão é o jeito mais fácil de a diretoria receber o script na onda 2 sem ninguém perceber.

> Diretoria é o alvo preferido de quem quer um hash NTLM. Deixar esse grupo pra depois faz sentido por alguns dias, não por semanas.
{: .prompt-warning }

## Falsos positivos comuns

- **"Vulnerável" no dia seguinte ao patch.** Rollout gradual mais o atraso do inventário. Rode de novo em 48 horas antes de abrir chamado.
- **A mesma máquina duas vezes.** O inventário às vezes traz o hostname com e sem o sufixo de domínio. Conte por `DeviceId`, não por nome.
- **Office antigo que não aparece.** Office 2013 e anteriores não são `16.0` e não entram na consulta. Eles não estão "fora do risco", estão fora da contagem.

## A pergunta que muda tudo

Depois de saber quem está vulnerável, a pergunta certa é: **isso vai chegar sozinho?**

Se o parque atualiza pela CDN sem trava, a resposta é sim, e o trabalho é acompanhar. Se tem versão fixada, a resposta é nunca, e o trabalho é mexer na política. O detect existe pra responder essa pergunta máquina por máquina.

## Perguntas que costumam aparecer

**O Defender diz "No action required". Por que vocês dizem que estamos vulneráveis?**
Porque a avaliação por dispositivo ainda não rodou pra essa CVE. A comparação de build com a tabela oficial da Microsoft é a fonte de verdade até o painel encher.

**Por que não forçar a versão exata no script?**
Porque cada canal tem o seu build corrigido. Forçar um build de outro canal quebra a atualização ou troca o canal.

**O script vai fechar o Outlook do usuário?**
Não. O update baixa em segundo plano e aplica quando os aplicativos são fechados. Quem fecha à força é o Update Deadline da política, e só depois do prazo.

**Bloquear SMB de saída resolve?**
Ajuda. A Microsoft recomenda bloquear a porta TCP 445 de saída pra internet como camada extra. Não substitui o update.

## Antes de dizer que está corrigido

- [ ] A consulta de status foi rodada de novo pelo menos 48 horas depois do patch.
- [ ] As máquinas com `TargetVersion` foram tratadas na política, não só no script.
- [ ] O grupo excluído (diretoria) voltou pro escopo.
- [ ] O Exposed devices do Defender, quando encheu, bate com a sua contagem. Se der menos, é máquina sem rescan. Se der mais, revise a tabela de builds.
- [ ] O Office fora de suporte foi listado à parte, com a mitigação de rede.

E na conclusão, escreva o limite: "análise por comparação de build com a tabela oficial da Microsoft; o Defender ainda não tinha concluído a avaliação automática desta CVE na data". Se amanhã o painel pular de zero pra duzentos, ninguém vai perguntar por que ontem você disse outra coisa.

## O que eu levo disso

- Painel de vulnerabilidade tem atraso. Inventário de versão, não.
- Build igual em massa é política, não azar.
- Remediation agendada uma vez esconde quem não terminou o download.
- Include e exclude no Intune, sempre do mesmo tipo de grupo.

## Referências

- [Release notes for Microsoft Office security updates](https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates) (Microsoft Learn)
- [Update history for Microsoft 365 Apps (listed by date)](https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date) (Microsoft Learn)
