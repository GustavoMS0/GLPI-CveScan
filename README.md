# GLPI CVE Scan (`cvescan`)

Plugin para **GLPI 10, 11 e 12** que realiza varredura de vulnerabilidades conhecidas (**CVE / OSV**) sobre o inventário de softwares (`glpi_softwares` e `glpi_softwareversions`), classifica os achados por severidade **CVSS**, contabiliza ativos impactados e adiciona uma aba dedicada **CVEs** no cadastro de cada `Software`.

---

## Funcionalidades

- **Descoberta e Normalização de Inventário:**
  - Lê softwares ativos (`glpi_softwares` com `is_deleted = 0`) e suas versões instaladas (`glpi_softwareversions`).
  - Contabiliza computadores e ativos impactados por versão a partir de `glpi_items_softwareversions` (com fallback automático para `glpi_computers_softwareversions` em bases legadas).
  - Normaliza nomes de pacotes e versões semânticas, removendo sufixos de arquitetura (`(x64)`, `(64-bit)`, `x86_64`) e revisões de distribuição quando habilitado.
- **Consulta Segura à Base OSV.dev (`https://api.osv.dev/v1/query`):**
  - Endpoint HTTPS imutável em código (`PluginCvescanScanner::OSV_API_URL`), eliminando vetores de SSRF.
  - Verificação estrita de certificado TLS (`CURLOPT_SSL_VERIFYPEER = true`, `CURLOPT_SSL_VERIFYHOST = 2`), bloqueio de redirecionamentos HTTP e timeout configurável (`3` a `30` segundos).
  - Prioriza identificadores `CVE-*` nos aliases retornados, extrai nota e severidade CVSS (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`), versão corrigida (`fixed_version`) e valida links de referência exigindo esquema `https://`.
  - Cache configurável por versão (`cache_hours`, padrão `24` horas) para evitar consultas redundantes.
- **Execução Agendada (`CronTask`) e Painel Administrativo (`front/config.form.php`):**
  - Registra a ação automática `CveScan` (`PluginCvescanScanner::cronCveScan`) com controle de lote por ciclo (`batch_size`, padrão `25` versões).
  - Painel administrativo com cartões de resumo por severidade, disparo manual de lote, limpeza de cache e listagem das vulnerabilidades detectadas recentemente.
- **Aba Dedicada em `Software` (`PluginCvescanTab`):**
  - Exibe o contador `CVEs (N)` na aba do software e tabela detalhada com badge de severidade, versão afetada, versão corrigida, total de ativos impactados e data da última verificação.
  - Respeita permissões de visualização (`canViewItem()`) e isolamento de entidade (`Session::haveAccessToEntity()`).

---

## Matriz de Compatibilidade

| Versão do GLPI | Versão do PHP | Status |
| :--- | :--- | :--- |
| **GLPI 10.0.x** (`10.0.0` – `10.0.99`) | PHP `7.4` ou superior | Suportado |
| **GLPI 11.0.x** (`11.0.0` – `11.0.99`) | PHP `8.2` ou superior | Suportado |
| **GLPI 12.0.x** (`12.0.0` – `12.0.99`) | PHP `8.3` ou superior | Suportado |

---

## Instalação

1. Baixe o pacote `cvescan-1.0.0.zip` na página de [Releases](https://github.com/GustavoMS0/GLPI-CveScan/releases) ou extraia o diretório `cvescan` em `<GLPI_ROOT>/plugins/cvescan`.
2. Acesse **Configurar > Plug-ins** no GLPI.
3. Clique em **Instalar** e em seguida em **Ativar** no plugin **CVE Scan**.
4. Acesse a configuração do plugin para ajustar o tamanho do lote, tempo de cache ou disparar uma verificação manual.

---

## Testes Automatizados

A suíte standalone em `tests/` valida a execução nos modos GLPI 10 (`10.0.5` / `10.0.18`), GLPI 11 (`11.0.0`) e GLPI 12 (`12.0.0` com `CommonGLPI::$rightname` tipado) sem necessidade de banco externo ou rede:

```bash
php tests/run.php
```

---

## Licença e Autoria

- **Autor:** G. Martins (`Gustavo Martins`)
- **Licença:** [GNU General Public License v3.0 or later (GPLv3+)](LICENSE)
- **Copyright:** `Copyright (C) 2026 by G. Martins`
