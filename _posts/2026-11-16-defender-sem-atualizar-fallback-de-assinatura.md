---
title: "Defender sem atualizar: o fallback de assinatura que existe na política e não acontece na máquina"
description: "Como testar cada fonte de atualização do Defender, uma por uma, e montar no Intune uma remediação que diz por onde atualizou ou onde falhou."
date: 2026-11-16 09:00:00 -0300
categories: [Na prática, Defender]
tags: [defender for endpoint, intune, remediations, configuration manager, powershell]
media_subpath: /assets/img/posts/defender-sem-atualizar-fallback-de-assinatura
---

Todo mundo tem um plano B pra atualização do antivírus. Tá lá na política, marcadinho, quatro fontes em ordem. O problema é que plano B que nunca foi testado é só uma caixa de seleção. E a gente só descobre isso no dia em que o plano A para e ninguém avisa.

## O cenário

O pedido chega mais ou menos assim: "se o nosso gerenciador falhar, quero que as máquinas busquem a assinatura direto na Microsoft". Parece configuração de cinco minutos.

Aí você abre a política e a configuração já está lá. Fonte externa marcada, carência curta, atualização forçada ligada. **O pedido já estava atendido no console.** A pergunta certa passa a ser outra: se já está configurado, por que máquina fica dias com assinatura velha?

## O ambiente típico

Parque Windows com Microsoft Defender Antivirus, definições entregues por Configuration Manager (com um ponto de atualização em cima de WSUS) e Intune em cogerenciamento. É um desenho bem comum.

O Defender tem uma lista de fontes e tenta uma depois da outra. Cada fonte depende de uma coisa diferente pra funcionar:

![Ordem de fontes de atualização do Defender e o que trava cada uma](fontes-fallback.svg){: width="900" height="380" }
_Ambiente de exemplo. Os bloqueios são os que mais aparecem, não uma lista completa._

| Fonte | Nome no Defender | Depende de |
|---|---|---|
| WSUS interno | `InternalDefinitionUpdateServer` | Definição aprovada no WSUS |
| Microsoft Update | `MicrosoftUpdateServer` | Agente do Windows Update poder falar com a Microsoft |
| Página de security intelligence | `MMPC` | Saída HTTPS pra internet como SYSTEM |
| Compartilhamento de rede | `FileShares` | Caminho UNC configurado e alguém atualizando a pasta |

> A política lista as fontes. Ela não testa nenhuma. Fonte marcada no console e fonte funcionando na máquina são coisas diferentes.
{: .prompt-danger }

## Como fazer

### 1. Ver a ordem que realmente chegou na máquina

O console mostra o que você configurou. A máquina mostra o que ela recebeu.

```powershell
Get-MpPreference | Format-List SignatureFallbackOrder, SignatureAuGracePeriod
```

`SignatureFallbackOrder` vem como texto separado por barra vertical, por exemplo `InternalDefinitionUpdateServer|MicrosoftUpdateServer|MMPC`. Se aparecer só `MicrosoftUpdateServer|MMPC`, a máquina está no padrão do produto e a sua política não está valendo ali.

`SignatureAuGracePeriod` é a carência em minutos. No Configuration Manager ela aparece em horas, na opção que diz que o cliente só busca fontes alternativas se a assinatura estiver mais velha que X horas.

### 2. Testar uma fonte por vez

Esse é o passo que quase ninguém faz. O `Update-MpSignature` aceita a fonte como parâmetro, então dá pra saber qual está quebrada em dois minutos.

```powershell
Update-MpSignature -UpdateSource InternalDefinitionUpdateServer
Update-MpSignature -UpdateSource MicrosoftUpdateServer
Update-MpSignature -UpdateSource MMPC

Get-MpComputerStatus | Format-List AntivirusSignatureVersion, AntivirusSignatureLastUpdated
```

Rode cada linha, olhe o erro e confira se a versão mudou. Exemplo do que costuma sair (valores inventados):

| Fonte | Resultado | Leitura |
|---|---|---|
| `InternalDefinitionUpdateServer` | Sem erro, versão igual | O WSUS respondeu e não tinha nada aprovado |
| `MicrosoftUpdateServer` | Erro `0x8024402C` | O agente do Windows Update não chega na Microsoft |
| `MMPC` | Sem erro, versão nova | A fonte externa funciona |

> Teste como SYSTEM, não com o seu usuário. A atualização de verdade roda como SYSTEM, e é comum o proxy liberar o usuário e barrar a conta da máquina.
{: .prompt-tip }

### 3. Conferir se o Windows Update está preso no WSUS

Abra `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`. Se existir `WUServer` e os valores `SetPolicyDrivenUpdateSourceFor...` estiverem em 1, todo scan vai pro WSUS. Nesse cenário a fonte Microsoft Update tende a falhar sempre, e a sua lista de quatro fontes na prática tem duas.

Isso não é erro de configuração. É o comportamento esperado de quem centraliza update. Só precisa entrar na conta quando você desenha o fallback.

### 4. Lembrar que a fonte externa tem uma espera própria

A documentação da Microsoft diz que, quando a página de security intelligence fica como fallback depois de WSUS ou Microsoft Update, o Defender só baixa dela quando a atualização atual é considerada vencida. O padrão citado é de sete dias seguidos sem conseguir atualizar pelas outras fontes. O prazo é ajustável pela política que define em quantos dias a assinatura passa a ser considerada desatualizada.

> A carência em horas do gerenciador e o prazo em dias da assinatura vencida são dois relógios. Baixar o primeiro pra 24 horas não mexe no segundo.
{: .prompt-warning }

### 5. Montar a remediação no Intune

Com o diagnóstico feito, sobra a rede de segurança: um par de scripts no Intune Remediations que roda todo dia.

A detecção conta os dias pela data da máquina:

```powershell
$LimiteDias = 2
$st   = Get-MpComputerStatus
$dias = ((Get-Date).Date - $st.AntivirusSignatureLastUpdated.Date).Days
if ($dias -gt $LimiteDias) { exit 1 } else { exit 0 }
```

A remediação lê a ordem configurada e tenta fonte por fonte, parando na primeira que resolver:

```powershell
$fila = (Get-MpPreference).SignatureFallbackOrder -split '\|'
foreach ($fonte in $fila) {
    try   { Update-MpSignature -UpdateSource $fonte -ErrorAction Stop }
    catch { $erro = $_ }
    $dias = ((Get-Date).Date - (Get-MpComputerStatus).AntivirusSignatureLastUpdated.Date).Days
    if ($dias -le $LimiteDias) { "SUCESSO,$fonte"; break }
}
```

Os trechos acima são o esqueleto. Os scripts completos tratam erro, código de falha por fonte, eventos do log do Defender e saída em uma linha pronta pra CSV. Estão na [pasta do GitHub](https://github.com/mikionakamaru/mikionakamaru.github.io/tree/main/intune-remediations/defender-assinatura-fallback), com a tabela dos 16 campos.

O resultado fica assim (exemplo inventado):

```
2026-11-12 09:15,SUCESSO,MMPC,InternalDefinitionUpdateServer=SEM_PACOTE_NOVO|MicrosoftUpdateServer=FALHA 0x8024402C|MMPC=OK,...
```

Em uma linha você sabe quem tentou, quem falhou, com qual código, e quem resolveu.

> O portal do Intune mostra a saída da detecção, antes e depois. A saída normal da remediação não aparece. O jeito é gravar o resultado num arquivo e fazer a detecção ler e imprimir junto.
{: .prompt-info }

## Falsos positivos comuns

- **Máquina desligada há dias.** Ela aparece como desatualizada e não tem nada quebrado. Cruze com o último contato antes de abrir chamado.
- **Defender em modo passivo.** Com outro antivírus como principal, o campo de modo mostra `Passive` ou `EDR Block Mode`. A assinatura continua atualizando, mas o painel de quem cuida do outro produto pode não olhar pra ela.
- **Fonte que "funciona" sem entregar.** O WSUS sem aprovação responde sem erro. Sem conferir a versão depois, parece sucesso.
- **Teste feito com usuário administrador.** Passa no proxy, dá certo, e a conta SYSTEM continua barrada.

## A pergunta que muda tudo

Em vez de "a fonte externa está configurada?", pergunte: **"quando foi a última vez que uma máquina daqui atualizou por ela?"**. Se ninguém sabe responder, o fallback nunca foi exercitado. A remediação com o campo de fonte responde isso sozinha, todo dia.

## Antes de dizer que está resolvido

- A ordem de fontes que chegou na máquina é a que você configurou.
- Cada fonte foi testada sozinha, como SYSTEM, e você sabe qual falha e por quê.
- O prazo de assinatura vencida está num valor que você escolheu, não no padrão por acaso.
- A remediação rodou num grupo piloto com pelo menos uma máquina desatualizada de verdade.
- O relatório mostra a fonte que atualizou, não só "sucesso".

Escreva a conclusão com o limite dela. "A detecção foi validada e a remediação está em piloto" é uma frase honesta. "Problema resolvido" só depois de ver uma máquina velha voltar.

## O que eu levo disso

- Política certa no console não é fallback funcionando no cliente.
- `Update-MpSignature -UpdateSource` é o teste mais barato que existe pra isso.
- Script que diz "falhou" não ajuda. Script que diz onde tentou e com qual código, ajuda.
- Pensar a saída como CSV desde o começo poupa uma tarde de planilha.

## Referências

- [Manage the sources for Microsoft Defender Antivirus protection updates](https://learn.microsoft.com/en-us/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus)
- [Manage Microsoft Defender Antivirus updates and scans for endpoints that are out of date](https://learn.microsoft.com/en-us/defender-endpoint/manage-outdated-endpoints-microsoft-defender-antivirus)
- [Endpoint Protection security intelligence updates in Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/protect/deploy-use/endpoint-definition-updates)
- [Update-MpSignature](https://learn.microsoft.com/en-us/powershell/module/defender/update-mpsignature)
