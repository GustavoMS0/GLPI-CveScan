# Changelog

Todas as alterações relevantes deste projeto são documentadas neste arquivo.

## [1.0.0] - 2026-11-16

### Adicionado
- Motor de varredura de vulnerabilidades (`PluginCvescanScanner`) integrado ao inventário de softwares do GLPI (`glpi_softwares`, `glpi_softwareversions` e `glpi_items_softwareversions` / `glpi_computers_softwareversions`).
- Normalização de nomes de pacotes e versões semânticas com remoção configurável de sufixos de arquitetura (`x64`, `64-bit`, `x86`) e revisões de pacote.
- Cliente HTTPS seguro para a API pública OSV (`https://api.osv.dev/v1/query`) com endpoint imutável anti-SSRF, validação TLS estrita, extração de aliases `CVE-*`, classificação CVSS (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), versão corrigida e sanitização de links de referência `https://`.
- Cache de verificação por versão (`glpi_plugin_cvescan_cache`) e persistência de vulnerabilidades (`glpi_plugin_cvescan_findings`) com limpeza automática no expurgo (`item_purge`) de `Software` e `SoftwareVersion`.
- Tarefa agendada (`CronTask` `CveScan`) e painel administrativo (`front/config.form.php`) com resumo por severidade, execução manual em lote e limpeza de cache.
- Aba dedicada **CVEs** em `Software` (`PluginCvescanTab`) com validação de entidade e permissão de leitura.
- Camada de compatibilidade unificada (`PluginCvescanCompat`) para GLPI `10.0.0` a `12.0.99` e PHP `7.4` a `8.3+`.
