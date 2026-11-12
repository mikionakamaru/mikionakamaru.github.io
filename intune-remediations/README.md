# Intune Remediations

Pares de scripts de detecção e correção pra usar em **Intune > Devices > Scripts and remediations > Remediations**. Cada pasta é um caso, com os dois scripts e um README explicando o que fazem e como configurar.

| Pasta | O que corrige | Post |
|---|---|---|
| [office-outlook-cve-2026-124194](office-outlook-cve-2026-124194/) | Microsoft 365 Apps / Office LTSC em build vulnerável à CVE-2026-124194 (Outlook, vazamento de hash NTLMv2) | [O Defender disse zero](https://mikionakamaru.github.io/posts/o-defender-disse-zero/) |

## Padrão de todos os scripts

- ASCII puro, sem acento, pra não quebrar na execução pelo Intune.
- Detect: `exit 0` = conforme, `exit 1` = precisa corrigir. A última linha de saída vai pra coluna *Pre-remediation detection output*.
- Rodam como SYSTEM, em PowerShell 64-bit, sem checagem de assinatura.
- Teste sempre num grupo piloto de dispositivos antes do parque.

Use por sua conta e risco. Leia o script antes de subir.
