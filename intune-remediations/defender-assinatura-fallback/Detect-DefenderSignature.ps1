# ==============================================================================
# Detect-DefenderSignature.ps1
# Intune Remediations - script de DETECCAO
# ==============================================================================
# O QUE FAZ
#   Verifica ha quantos dias a assinatura (vacina) do Microsoft Defender nao
#   atualiza. Se passou do limite, avisa o Intune para rodar a remediacao.
#
# COMO O INTUNE USA ESTE SCRIPT
#   - Roda todo dia (agendamento da Remediation).
#   - Exit 0 = maquina conforme, nada mais acontece.
#   - Exit 1 = maquina nao conforme, o Intune roda o script de remediacao e
#     depois roda este script de novo (deteccao pos-remediacao).
#   - O texto do Write-Output vira a coluna "Pre-remediation detection output"
#     (1a rodada) e "Post-remediation detection output" (2a rodada).
#
# FORMATO DA SAIDA
#   Uma unica linha, campos separados por virgula, sem acento e sem caractere
#   especial, para abrir direto como CSV.
#
# COLUNAS (16)
#    1 Status             ATUALIZADO | DESATUALIZADO | ERRO_LEITURA
#    2 DiasSemAtualizar   diferenca em dias de calendario (data local da maquina)
#    3 UltimaAtualizacao  yyyy-MM-dd HH:mm
#    4 VersaoAssinatura   ex.: 1.421.250.0
#    5 OrdemFallback      SignatureFallbackOrder em vigor (PADRAO se vazio)
#    6 ModoAV             Normal | Passive | EDR Block Mode ...
#    7 a 16               resultado da ultima remediacao (as 10 colunas do
#                         script Remediate-DefenderSignature.ps1)
#
# CONFIGURACAO NO INTUNE
#   Run this script using the logged-on credentials = No (roda como SYSTEM)
#   Run script in 64-bit PowerShell                 = Yes
# ==============================================================================


# ------------------------------------------------------------------------------
# ETAPA 0 - Parametros
# ------------------------------------------------------------------------------

# Quantos dias a maquina pode ficar sem atualizar antes de ser nao conforme.
# Com 2: vacina do dia 9 e hoje dia 11 = 2 dias, passa. No dia 12 = 3, remedia.
# IMPORTANTE: usar o mesmo valor no script de remediacao.
$LimiteDias = 2

# Arquivo onde o script de remediacao grava o resultado dele.
# O portal do Intune nao mostra a saida da remediacao, so a da deteccao.
# Por isso a deteccao le este arquivo e junta na propria saida.
$ArqResultado = Join-Path $env:ProgramData 'DefenderUpdateCheck\ultimo_resultado.txt'

# Texto usado quando a maquina nunca passou pela remediacao.
# Tem 10 campos para manter o CSV sempre com 16 colunas.
$SemRemediacao = 'SEM_REMEDIACAO,NA,NA,NA,NA,NA,NA,NA,NA,NA'


# ------------------------------------------------------------------------------
# ETAPA 1 - Funcao que limpa texto para caber no CSV
# ------------------------------------------------------------------------------
# Recebe qualquer texto e devolve sem acento, sem virgula, sem quebra de linha
# e sem caractere especial. Se o texto vier vazio, devolve NA.
function Limpar {
    param([string]$Texto, [int]$Max = 200)

    if ([string]::IsNullOrEmpty($Texto)) { return 'NA' }

    # FormD separa a letra do acento: "a com til" vira "a" + "til".
    $norm = $Texto.Normalize([Text.NormalizationForm]::FormD)

    # Copia so as letras e joga fora as marcas de acento (NonSpacingMark).
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $norm.ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($c)
        }
    }

    # Virgula, quebra de linha e tab viram espaco (virgula quebraria o CSV).
    $r = $sb.ToString() -replace '[\r\n\t,]+', ' '

    # Remove tudo que nao for letra, numero ou pontuacao simples.
    $r = $r -replace '[^A-Za-z0-9 _.:;=|/\\()\-]', ''

    # Junta espacos repetidos e tira espaco das pontas.
    $r = ($r -replace '\s+', ' ').Trim()

    # Corta no tamanho maximo (o Intune guarda no maximo 2048 caracteres).
    if ($r.Length -gt $Max) { $r = $r.Substring(0, $Max) }

    if ($r -eq '') { return 'NA' }
    return $r
}


# ------------------------------------------------------------------------------
# ETAPA 2 - Ler o resultado da ultima remediacao (se existir)
# ------------------------------------------------------------------------------
# Comeca assumindo que nunca houve remediacao. Se o arquivo existir e tiver
# os 10 campos esperados, usa o conteudo dele.
$ultimaRemediacao = $SemRemediacao
try {
    if (Test-Path -LiteralPath $ArqResultado) {
        $linha = (Get-Content -LiteralPath $ArqResultado -TotalCount 1 -ErrorAction Stop)
        if ($linha -and ($linha -split ',').Count -eq 10) { $ultimaRemediacao = $linha }
    }
} catch {
    # Se nao conseguir ler o arquivo, segue com SEM_REMEDIACAO.
}


# ------------------------------------------------------------------------------
# ETAPA 3 - Ler o estado do Defender e decidir
# ------------------------------------------------------------------------------
try {
    # 3.1 Estado atual do antivirus. Se o Defender nao responder, cai no catch.
    $st = Get-MpComputerStatus -ErrorAction Stop

    # 3.2 Data e hora da ultima atualizacao de assinatura.
    $ultima = $st.AntivirusSignatureLastUpdated
    if (-not $ultima) { throw 'AntivirusSignatureLastUpdated vazio' }

    # 3.3 Conta os dias pela DATA local da maquina, ignorando a hora.
    #     Ex.: atualizou dia 9 as 23h, hoje e dia 11 as 08h = 2 dias.
    $dias = ((Get-Date).Date - $ultima.Date).Days

    # 3.4 Ordem de fontes configurada (so informativo, para o relatorio).
    $ordem = 'NA'
    try { $ordem = Limpar ((Get-MpPreference -ErrorAction Stop).SignatureFallbackOrder) 120 } catch { }
    if ($ordem -eq 'NA') { $ordem = 'PADRAO' }

    # 3.5 Decide: mais dias que o limite = desatualizado.
    $status = if ($dias -gt $LimiteDias) { 'DESATUALIZADO' } else { 'ATUALIZADO' }

    # 3.6 Monta os 6 campos da deteccao.
    $saida = @(
        $status
        $dias
        $ultima.ToString('yyyy-MM-dd HH:mm')
        (Limpar $st.AntivirusSignatureVersion 40)
        $ordem
        (Limpar $st.AMRunningMode 40)
    ) -join ','

    # 3.7 Imprime a linha final (6 campos da deteccao + 10 da remediacao).
    Write-Output "$saida,$ultimaRemediacao"

    # 3.8 Exit 1 chama a remediacao. Exit 0 encerra como conforme.
    if ($status -eq 'DESATUALIZADO') { exit 1 } else { exit 0 }
}
catch {
    # ETAPA 4 - Nao conseguiu ler o Defender (servico parado, outro antivirus,
    # modulo ausente). Reporta o erro no 6o campo e sai com 1 para aparecer
    # como "com problema" no relatorio.
    $msg = Limpar $_.Exception.Message 200
    Write-Output "ERRO_LEITURA,NA,NA,NA,NA,$msg,$ultimaRemediacao"
    exit 1
}
