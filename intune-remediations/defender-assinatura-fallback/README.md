# Defender: assinatura parada e fallback de fontes

Detecta máquina com a assinatura do Microsoft Defender há mais de 2 dias sem atualizar e tenta atualizar fonte por fonte, seguindo o Signature Update Fallback Order. O resultado diz por qual fonte atualizou, ou onde tentou e falhou.

> **Estado:** detecção testada em máquina atualizada. A remediação ainda não foi validada em máquina desatualizada. Rode num grupo piloto antes do parque.

## Arquivos

| Arquivo | O que faz |
|---|---|
| `Detect-DefenderSignature.ps1` | Conta os dias desde a última atualização de assinatura, pela data local da máquina. Mais de 2 dias, `exit 1`. Junta na saída o resultado da última remediação. |
| `Remediate-DefenderSignature.ps1` | Tenta `Update-MpSignature -UpdateSource` em cada fonte: primeiro a ordem configurada na máquina, depois `MicrosoftUpdateServer` e `MMPC`. Para na primeira que resolver. Traz os eventos 2000 a 2004 do log do Defender. |

## Por que a detecção mostra o resultado da remediação

O portal do Intune mostra a saída da detecção (antes e depois da remediação) e o erro da remediação. A saída normal da remediação não aparece. Por isso a remediação grava a linha dela em `C:\ProgramData\DefenderUpdateCheck\ultimo_resultado.txt` e a detecção cola essa linha no fim da própria saída. O resultado completo sai na coluna *Post-remediation detection output*.

## Saída

Uma linha, campos separados por vírgula, sem acento. Abre direto como CSV no export do Intune.

```
ATUALIZADO,0,2026-11-11 06:41,1.463.243.0,MicrosoftUpdateServer|MMPC,Normal,SEM_REMEDIACAO,NA,NA,NA,NA,NA,NA,NA,NA,NA
```

| # | Campo | Significado |
|---|---|---|
| 1 | Status | `ATUALIZADO`, `DESATUALIZADO` ou `ERRO_LEITURA` |
| 2 | DiasSemAtualizar | Dias de calendário desde a última atualização |
| 3 | UltimaAtualizacao | Data e hora da última atualização |
| 4 | VersaoAssinatura | Versão instalada |
| 5 | OrdemFallback | Signature Update Fallback Order em vigor (`PADRAO` se vazio) |
| 6 | ModoAV | Modo do Defender Antivírus (`Normal`, `Passive`, `EDR Block Mode`) |
| 7 | DataRemediacao | Quando a remediação rodou |
| 8 | Status da remediação | `SUCESSO`, `JA_ATUALIZADO`, `FALHA_DOWNLOAD`, `FALHA_INSTALACAO` ou `ERRO_SCRIPT` |
| 9 | FonteQueAtualizou | Fonte que resolveu, ou `NENHUMA` |
| 10 | Tentativas | `Fonte=OK`, `Fonte=SEM_PACOTE_NOVO` ou `Fonte=FALHA 0x...`, separadas por `\|` |
| 11 | OrdemConfigurada | Fallback Order lido na máquina |
| 12 | VersaoAntes | Versão antes da tentativa |
| 13 | VersaoDepois | Versão depois da tentativa |
| 14 | UltimaAtualizacao | Data da assinatura depois da tentativa |
| 15 | DiasSemAtualizar | Dias sem atualizar depois da tentativa |
| 16 | Log | Eventos 2000 a 2004 do Defender gerados na execução |

Exemplo de remediação que só conseguiu pela última fonte (valores ilustrativos):

```
2026-11-12 09:15,SUCESSO,MMPC,InternalDefinitionUpdateServer=SEM_PACOTE_NOVO|MicrosoftUpdateServer=FALHA 0x8024402C|MMPC=OK,InternalDefinitionUpdateServer|MicrosoftUpdateServer|MMPC,1.463.100.0,1.463.300.0,2026-11-12 09:15,0,Evt2000 09:15:22 ...
```

## Configuração no Intune

| Campo | Valor |
|---|---|
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | Yes |
| Schedule | Daily |
| Assignments | Grupos de **dispositivos** |

## Limites

- `FALHA_DOWNLOAD` e `FALHA_INSTALACAO` são uma heurística. O `Update-MpSignature` não separa as duas coisas. O script marca instalação quando aparece evento 2003 ou 2004, ou erro `0x8050....`. Na dúvida, vale o campo Log.
- A fonte `MMPC` baixa direto da Microsoft por HTTPS. O script roda como SYSTEM, então depende de proxy e firewall liberarem essa conta.
- O limite de dias fica na variável `$LimiteDias`, no topo dos dois scripts. Use o mesmo valor nos dois.

Referências: [Manage the sources for Microsoft Defender Antivirus protection updates](https://learn.microsoft.com/en-us/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus) e [Update-MpSignature](https://learn.microsoft.com/en-us/powershell/module/defender/update-mpsignature).
