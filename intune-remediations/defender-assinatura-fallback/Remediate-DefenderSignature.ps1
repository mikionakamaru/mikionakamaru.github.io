# ==============================================================================
# Remediate-DefenderSignature.ps1
# Intune Remediations - script de REMEDIACAO
# ==============================================================================
# O QUE FAZ
#   Tenta atualizar a assinatura (vacina) do Microsoft Defender, uma fonte por
#   vez, e para na primeira que resolver:
#     1) as fontes do Signature Update Fallback Order, na ordem configurada
#     2) depois MicrosoftUpdateServer e MMPC, se nao estiverem na ordem
#
# QUANDO RODA
#   So roda quando o script de deteccao sai com exit 1 (maquina desatualizada).
#
# FORMATO DA SAIDA
#   Uma unica linha, campos separados por virgula, sem acento e sem caractere
#   especial. A mesma linha e gravada em
#   %ProgramData%\DefenderUpdateCheck\ultimo_resultado.txt
#   porque o portal do Intune nao mostra a saida da remediacao. Quem mostra e o
#   script de deteccao, na coluna "Post-remediation detection output".
#   Em caso de falha a linha tambem vai para a coluna "Remediation error".
#
# COLUNAS (10)
#    1 DataRemediacao     yyyy-MM-dd HH:mm
#    2 Status             SUCESSO          atualizou
#                         JA_ATUALIZADO    ja estava em dia quando rodou
#                         FALHA_DOWNLOAD   nenhuma fonte entregou o pacote
#                         FALHA_INSTALACAO pacote chegou e falhou ao aplicar
#                         ERRO_SCRIPT      erro inesperado (Defender ausente etc.)
#    3 FonteQueAtualizou  fonte que resolveu, ou NENHUMA
#    4 Tentativas         Fonte=Resultado, separados por |
#                         OK | SEM_PACOTE_NOVO | FALHA 0xCODIGO
#    5 OrdemConfigurada   SignatureFallbackOrder lido da maquina (PADRAO se vazio)
#    6 VersaoAntes        versao da assinatura antes de tentar
#    7 VersaoDepois       versao da assinatura depois de tentar
#    8 UltimaAtualizacao  yyyy-MM-dd HH:mm (depois de tentar)
#    9 DiasSemAtualizar   depois de tentar
#   10 Log                eventos 2000 a 2004 do Defender gerados na execucao
#
# CODIGOS DE SAIDA
#   Exit 0 = atualizou. Exit 1 = nao atualizou.
#
# CONFIGURACAO NO INTUNE
#   Run this script using the logged-on credentials = No (roda como SYSTEM)
#   Run script in 64-bit PowerShell                 = Yes
# ==============================================================================


# ------------------------------------------------------------------------------
# ETAPA 0 - Parametros
# ------------------------------------------------------------------------------

# Mesmo limite do script de deteccao. Atualizou e ficou dentro dele = sucesso.
$LimiteDias = 2

# Nomes de fonte que o Update-MpSignature aceita. Qualquer outro e ignorado.
#   InternalDefinitionUpdateServer = WSUS interno
#   MicrosoftUpdateServer          = Microsoft Update (internet)
#   MMPC                           = pagina de security intelligence da Microsoft
#   FileShares                     = compartilhamento UNC
$Conhecidas = @('InternalDefinitionUpdateServer', 'MicrosoftUpdateServer', 'MMPC', 'FileShares')

# Fontes tentadas no fim, mesmo que nao estejam na ordem configurada.
$FontesExtras = @('MicrosoftUpdateServer', 'MMPC')

# Onde o resultado fica gravado para o script de deteccao ler.
$PastaSaida   = Join-Path $env:ProgramData 'DefenderUpdateCheck'
$ArqResultado = Join-Path $PastaSaida 'ultimo_resultado.txt'

# Log de eventos do Defender (Visualizador de Eventos).
$LogDefender = 'Microsoft-Windows-Windows Defender/Operational'


# ------------------------------------------------------------------------------
# ETAPA 1 - Funcoes de apoio
# ------------------------------------------------------------------------------

# Limpa um texto para caber no CSV: tira acento, virgula, quebra de linha e
# caractere especial. Texto vazio vira NA.
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

    if ($r.Length -gt $Max) { $r = $r.Substring(0, $Max) }
    if ($r -eq '') { return 'NA' }
    return $r
}

# Extrai o codigo de erro (0x........) de uma falha do Update-MpSignature.
# O codigo real costuma vir no texto da mensagem ou no FullyQualifiedErrorId.
# Se nao achar, usa o HResult da excecao.
function Obter-CodigoErro {
    param($Erro)
    $texto = "$($Erro.Exception.Message) $($Erro.FullyQualifiedErrorId)"
    $m = [regex]::Match($texto, '0x[0-9A-Fa-f]{8}')
    if ($m.Success) { return $m.Value.ToUpper().Replace('0X', '0x') }
    return ('0x{0:X8}' -f $Erro.Exception.HResult)
}

# Conta ha quantos dias a assinatura nao atualiza, pela DATA local da maquina
# (ignora a hora). Mesma conta do script de deteccao.
# Sem data de atualizacao devolve 9999, para ser tratado como desatualizado.
function Obter-Dias {
    param($Status)
    if (-not $Status.AntivirusSignatureLastUpdated) { return 9999 }
    return ((Get-Date).Date - $Status.AntivirusSignatureLastUpdated.Date).Days
}

# Encerra o script: grava a linha no arquivo, imprime e sai com o codigo dado.
function Finalizar {
    param([string]$Linha, [int]$Codigo)

    # O Intune guarda no maximo 2048 caracteres. Corta com folga.
    if ($Linha.Length -gt 1900) { $Linha = $Linha.Substring(0, 1900) }

    # Grava o resultado para o script de deteccao mostrar no portal.
    # Se a gravacao falhar, nao interrompe: a saida abaixo ainda e impressa.
    try {
        if (-not (Test-Path -LiteralPath $PastaSaida)) {
            New-Item -Path $PastaSaida -ItemType Directory -Force | Out-Null
        }
        Set-Content -LiteralPath $ArqResultado -Value $Linha -Encoding ASCII -Force
    } catch { }

    # Saida padrao.
    Write-Output $Linha

    # Em falha, repete na saida de erro. E ela que preenche a coluna
    # "Remediation error" do portal.
    if ($Codigo -ne 0) { [Console]::Error.WriteLine($Linha) }

    exit $Codigo
}


# ------------------------------------------------------------------------------
# ETAPA 2 - Marcar o inicio
# ------------------------------------------------------------------------------
# A hora de inicio serve para duas coisas: carimbar o resultado e filtrar no
# log do Defender so os eventos gerados por esta execucao.
$inicio  = Get-Date
$carimbo = $inicio.ToString('yyyy-MM-dd HH:mm')

try {
    # --------------------------------------------------------------------------
    # ETAPA 3 - Foto do estado ANTES de tentar
    # --------------------------------------------------------------------------
    # Se o Defender nao responder aqui, cai no catch final (ERRO_SCRIPT).
    $antes = Get-MpComputerStatus -ErrorAction Stop
    $versaoAntes = Limpar $antes.AntivirusSignatureVersion 40


    # --------------------------------------------------------------------------
    # ETAPA 4 - Ler o Signature Update Fallback Order da maquina
    # --------------------------------------------------------------------------
    # Vem de GPO, SCCM ou Intune. Ex.: "InternalDefinitionUpdateServer|MMPC".
    # Se nao houver nada configurado, o campo fica vazio e reportamos PADRAO.
    $ordemBruta = $null
    try { $ordemBruta = (Get-MpPreference -ErrorAction Stop).SignatureFallbackOrder } catch { }
    $ordemCfg = Limpar $ordemBruta 120
    if ($ordemCfg -eq 'NA') { $ordemCfg = 'PADRAO' }


    # --------------------------------------------------------------------------
    # ETAPA 5 - Montar a fila de fontes
    # --------------------------------------------------------------------------
    $fila = @()

    # 5.1 Primeiro as fontes configuradas, na ordem em que aparecem.
    #     Quebra o texto no "|", tira chaves e espacos, e so aceita nome valido.
    if ($ordemBruta) {
        foreach ($parte in ($ordemBruta -split '\|')) {
            $nome = $parte -replace '[{}\s]', ''
            $achou = $Conhecidas | Where-Object { $_ -ieq $nome } | Select-Object -First 1
            if ($achou -and ($fila -notcontains $achou)) { $fila += $achou }
        }
    }

    # 5.2 Depois as fontes extras, sem repetir as que ja estao na fila.
    #     Garante que MMPC e sempre tentado, mesmo fora da ordem configurada.
    foreach ($extra in $FontesExtras) {
        if ($fila -notcontains $extra) { $fila += $extra }
    }


    # --------------------------------------------------------------------------
    # ETAPA 6 - Conferir se ainda precisa remediar
    # --------------------------------------------------------------------------
    # Entre a deteccao e a remediacao o SCCM pode ter atualizado a maquina.
    # Se ja esta dentro do limite, registra e sai sem mexer em nada.
    if ((Obter-Dias $antes) -le $LimiteDias) {
        $linha = @(
            $carimbo, 'JA_ATUALIZADO', 'NENHUMA', 'NA', $ordemCfg, $versaoAntes, $versaoAntes
            $antes.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')
            (Obter-Dias $antes), 'NA'
        ) -join ','
        Finalizar $linha 0
    }


    # --------------------------------------------------------------------------
    # ETAPA 7 - Tentar atualizar, uma fonte por vez
    # --------------------------------------------------------------------------
    $tentativas = @()          # o que aconteceu em cada fonte (coluna 4)
    $codigos    = @()          # codigos de erro, usados na Etapa 9
    $fonteOk    = 'NENHUMA'    # fonte que resolveu (coluna 3)
    $depois     = $antes       # estado depois da ultima tentativa

    foreach ($fonte in $fila) {

        # 7.1 Pede a atualizacao so para esta fonte.
        #     -ErrorAction Stop transforma a falha em excecao para capturar.
        $erro = $null
        try {
            Update-MpSignature -UpdateSource $fonte -ErrorAction Stop | Out-Null
        } catch {
            $erro = $_
        }

        # 7.2 Espera o Defender carregar a assinatura nova.
        Start-Sleep -Seconds 5

        # 7.3 Le o estado de novo e confere se ficou dentro do limite.
        #     O criterio de sucesso e o resultado real, nao o retorno do comando.
        try { $depois = Get-MpComputerStatus -ErrorAction Stop } catch { }
        $atualizou = (Obter-Dias $depois) -le $LimiteDias

        if ($atualizou) {
            # 7.4 Resolveu. Anota a fonte e para o laco: nao tenta as demais.
            $tentativas += "$fonte=OK"
            $fonteOk = $fonte
            break
        }
        elseif ($erro) {
            # 7.5 O comando deu erro. Anota a fonte com o codigo e segue.
            $cod = Obter-CodigoErro $erro
            $codigos += $cod
            $tentativas += "$fonte=FALHA $cod"
        }
        else {
            # 7.6 O comando nao deu erro, mas a assinatura continua velha.
            #     A fonte respondeu e nao tinha pacote mais novo (comum no WSUS).
            $tentativas += "$fonte=SEM_PACOTE_NOVO"
        }
    }


    # --------------------------------------------------------------------------
    # ETAPA 8 - Buscar o log do Defender desta execucao
    # --------------------------------------------------------------------------
    # Pega os eventos gerados desde o inicio do script, com sucesso ou com falha:
    #   2000 assinatura atualizada      2001 falha na atualizacao
    #   2002 engine atualizada          2003 falha na atualizacao da engine
    #   2004 falha ao carregar a assinatura (voltou para a ultima boa)
    $eventos = @()
    try {
        $eventos = @(Get-WinEvent -FilterHashtable @{
                LogName   = $LogDefender
                Id        = 2000, 2001, 2002, 2003, 2004
                StartTime = $inicio
            } -ErrorAction Stop | Sort-Object TimeCreated | Select-Object -Last 4)
    } catch {
        # Get-WinEvent da erro quando nao acha nenhum evento. Segue sem log.
    }

    # Monta o campo Log: "Evt2000 14:02:31 mensagem | Evt2001 ..."
    # Cada mensagem passa pelo Limpar (os eventos vem em portugues, com acento).
    $log = 'SEM_EVENTO'
    if ($eventos.Count -gt 0) {
        $partes = foreach ($ev in $eventos) {
            'Evt{0} {1} {2}' -f $ev.Id, $ev.TimeCreated.ToString('HH:mm:ss'), (Limpar $ev.Message 260)
        }
        $log = Limpar ($partes -join ' | ') 1100
    }


    # --------------------------------------------------------------------------
    # ETAPA 9 - Definir o status final
    # --------------------------------------------------------------------------
    if ($fonteOk -ne 'NENHUMA') {
        # Alguma fonte resolveu.
        $status = 'SUCESSO'
        $saidaCodigo = 0
    }
    else {
        # Nenhuma fonte resolveu. Separa "nao baixou" de "baixou e nao instalou".
        # O Update-MpSignature nao informa isso direto, entao e uma heuristica:
        #   - evento 2003 ou 2004, ou erro 0x8050xxxx (codigos do proprio
        #     Defender) = o pacote chegou e falhou ao aplicar
        #   - qualquer outro caso = falha de download (rede, proxy, WSUS, politica)
        $idsFalhaInstalacao = @($eventos | Where-Object { $_.Id -in 2003, 2004 })
        $codDefender = @($codigos | Where-Object { $_ -like '0x8050*' })
        if ($idsFalhaInstalacao.Count -gt 0 -or $codDefender.Count -gt 0) {
            $status = 'FALHA_INSTALACAO'
        } else {
            $status = 'FALHA_DOWNLOAD'
        }
        $saidaCodigo = 1
    }


    # --------------------------------------------------------------------------
    # ETAPA 10 - Montar a linha e encerrar
    # --------------------------------------------------------------------------
    $ultimaTxt = 'NA'
    if ($depois.AntivirusSignatureLastUpdated) {
        $ultimaTxt = $depois.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')
    }

    # Os 10 campos, na ordem documentada no cabecalho.
    $linha = @(
        $carimbo
        $status
        $fonteOk
        ($tentativas -join '|')
        $ordemCfg
        $versaoAntes
        (Limpar $depois.AntivirusSignatureVersion 40)
        $ultimaTxt
        (Obter-Dias $depois)
        $log
    ) -join ','

    # Grava no arquivo, imprime e sai (0 = atualizou, 1 = nao atualizou).
    Finalizar $linha $saidaCodigo
}
catch {
    # --------------------------------------------------------------------------
    # ETAPA 11 - Erro inesperado
    # --------------------------------------------------------------------------
    # Qualquer falha fora do previsto (Defender nao responde, modulo ausente).
    # Mantem as 10 colunas e leva a mensagem de erro no campo Log.
    $msg = Limpar $_.Exception.Message 300
    Finalizar "$carimbo,ERRO_SCRIPT,NENHUMA,NA,NA,NA,NA,NA,NA,$msg" 1
}
