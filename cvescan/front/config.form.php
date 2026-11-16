<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Painel administrativo e configuração
 *
 * Copyright (C) 2026 by G. Martins
 * ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of CVE Scan.
 *
 * CVE Scan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CVE Scan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CVE Scan. If not, see <https://www.gnu.org/licenses/>.
 * ------------------------------------------------------------------------
 */

if (!defined('GLPI_ROOT')) {
    include_once __DIR__ . '/../../../inc/includes.php';
}

require_once __DIR__ . '/../inc/compat.class.php';
require_once __DIR__ . '/../inc/config.class.php';
require_once __DIR__ . '/../inc/scanner.class.php';
require_once __DIR__ . '/../inc/tab.class.php';

if (!Session::haveRight('config', READ)) {
    PluginCvescanCompat::denyAccess();
    return;
}
Session::checkRight('config', READ);

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if ($method === 'POST') {
    if (!PluginCvescanCompat::requireSafePost()) {
        PluginCvescanCompat::denyAccess();
        return;
    }
    if (!Session::haveRight('config', UPDATE)) {
        PluginCvescanCompat::denyAccess();
        return;
    }
    Session::checkRight('config', UPDATE);

    if (isset($_POST['update'])) {
        PluginCvescanConfig::saveConfig($_POST);
        Session::addMessageAfterRedirect(
            __('Configurações salvas com sucesso.', 'cvescan'),
            false,
            INFO
        );
        Html::back();
        return;
    }

    if (isset($_POST['run_scan'])) {
        $force = !empty($_POST['force_rescan']);
        $stats = PluginCvescanScanner::runBatchScan(0, $force);
        $msg   = sprintf(
            __('Varredura concluída: %d versão(ões) verificada(s), %d vulnerabilidade(s) encontrada(s).', 'cvescan'),
            (int) $stats['scanned'],
            (int) $stats['findings']
        );
        Session::addMessageAfterRedirect($msg, false, INFO);
        Html::back();
        return;
    }

    if (isset($_POST['clear_cache'])) {
        PluginCvescanScanner::clearCache();
        Session::addMessageAfterRedirect(
            __('Cache de verificação limpo com sucesso.', 'cvescan'),
            false,
            INFO
        );
        Html::back();
        return;
    }
}

$cfg        = PluginCvescanConfig::getConfig();
$summary    = PluginCvescanScanner::getSeveritySummary();
$recentList = PluginCvescanScanner::getRecentFindings(50);
$canUpdate  = Session::haveRight('config', UPDATE);
$formAction = PluginCvescanCompat::webPath() . '/front/config.form.php';

Html::header(
    __('CVE Scan', 'cvescan'),
    $_SERVER['PHP_SELF'] ?? $formAction,
    'config',
    'plugins'
);

echo '<div class="container-xl my-3 cvescan-admin">';

// Cartões de resumo por severidade
echo '<div class="row g-3 mb-4 cvescan-summary-cards">';
$cards = [
    ['key' => 'CRITICAL', 'label' => __('Críticas', 'cvescan'), 'class' => 'cvescan-card-critical'],
    ['key' => 'HIGH',     'label' => __('Altas', 'cvescan'),    'class' => 'cvescan-card-high'],
    ['key' => 'MEDIUM',   'label' => __('Médias', 'cvescan'),   'class' => 'cvescan-card-medium'],
    ['key' => 'LOW',      'label' => __('Baixas', 'cvescan'),   'class' => 'cvescan-card-low'],
];
foreach ($cards as $card) {
    $countVal = (int) ($summary[$card['key']] ?? 0);
    echo '<div class="col-6 col-md-3">';
    echo '<div class="card ' . htmlspecialchars($card['class'], ENT_QUOTES, 'UTF-8') . '">';
    echo '<div class="card-body py-3">';
    echo '<div class="text-muted small text-uppercase fw-semibold">'
        . htmlspecialchars($card['label'], ENT_QUOTES, 'UTF-8')
        . '</div>';
    echo '<div class="fs-2 fw-bold mt-1">'
        . htmlspecialchars((string) $countVal, ENT_QUOTES, 'UTF-8')
        . '</div>';
    echo '</div></div></div>';
}
echo '</div>';

echo '<div class="row g-4 mb-4">';

// Formulário de configuração
echo '<div class="col-12 col-lg-7">';
echo '<div class="card h-100">';
echo '<div class="card-header"><h3 class="card-title mb-0">'
    . '<i class="ti ti-settings me-2" aria-hidden="true"></i>'
    . htmlspecialchars(__('Parâmetros de varredura (OSV.dev / CVE)', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</h3></div>';
echo '<div class="card-body">';
echo '<form method="post" action="' . htmlspecialchars($formAction, ENT_QUOTES, 'UTF-8') . '">';

echo '<div class="mb-3">';
echo '<label class="form-label" for="cvescan_batch_size">'
    . htmlspecialchars(__('Tamanho do lote por execução (versões)', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</label>';
echo '<input type="number" class="form-control" id="cvescan_batch_size" name="batch_size" min="1" max="200" value="'
    . htmlspecialchars((string) $cfg['batch_size'], ENT_QUOTES, 'UTF-8') . '">';
echo '<div class="form-text">'
    . htmlspecialchars(__('Quantidade máxima de versões de software consultadas a cada ciclo (1 a 200).', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</div>';
echo '</div>';

echo '<div class="mb-3">';
echo '<label class="form-label" for="cvescan_cache_hours">'
    . htmlspecialchars(__('Validade do cache por versão (horas)', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</label>';
echo '<input type="number" class="form-control" id="cvescan_cache_hours" name="cache_hours" min="1" max="720" value="'
    . htmlspecialchars((string) $cfg['cache_hours'], ENT_QUOTES, 'UTF-8') . '">';
echo '</div>';

echo '<div class="mb-3">';
echo '<label class="form-label" for="cvescan_timeout_seconds">'
    . htmlspecialchars(__('Timeout da consulta HTTPS (segundos)', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</label>';
echo '<input type="number" class="form-control" id="cvescan_timeout_seconds" name="timeout_seconds" min="3" max="30" value="'
    . htmlspecialchars((string) $cfg['timeout_seconds'], ENT_QUOTES, 'UTF-8') . '">';
echo '</div>';

$checkedStrip = !empty($cfg['strip_arch_suffix']) ? ' checked' : '';
echo '<div class="mb-3 form-check">';
echo '<input type="hidden" name="strip_arch_suffix" value="0">';
echo '<input type="checkbox" class="form-check-input" id="cvescan_strip_arch" name="strip_arch_suffix" value="1"' . $checkedStrip . '>';
echo '<label class="form-check-label" for="cvescan_strip_arch">'
    . htmlspecialchars(__('Normalizar sufixos de arquitetura e revisão de pacotes (ex.: x64, 64-bit)', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</label>';
echo '</div>';

if ($canUpdate) {
    echo '<button type="submit" name="update" value="1" class="btn btn-primary">'
        . '<i class="ti ti-device-floppy me-1" aria-hidden="true"></i>'
        . htmlspecialchars(__('Salvar configurações', 'cvescan'), ENT_QUOTES, 'UTF-8')
        . '</button>';
}

Html::closeForm();
echo '</div></div></div>';

// Ações manuais
echo '<div class="col-12 col-lg-5">';
echo '<div class="card h-100">';
echo '<div class="card-header"><h3 class="card-title mb-0">'
    . '<i class="ti ti-radar-2 me-2" aria-hidden="true"></i>'
    . htmlspecialchars(__('Execução manual e manutenção', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</h3></div>';
echo '<div class="card-body">';
echo '<p class="text-muted small">'
    . htmlspecialchars(__('Endpoint seguro fixo: https://api.osv.dev/v1/query (TLS verificado).', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</p>';

if ($canUpdate) {
    echo '<form method="post" action="' . htmlspecialchars($formAction, ENT_QUOTES, 'UTF-8') . '">';
    echo '<div class="mb-3 form-check">';
    echo '<input type="checkbox" class="form-check-input" id="cvescan_force_rescan" name="force_rescan" value="1">';
    echo '<label class="form-check-label" for="cvescan_force_rescan">'
        . htmlspecialchars(__('Ignorar cache válido neste lote', 'cvescan'), ENT_QUOTES, 'UTF-8')
        . '</label>';
    echo '</div>';
    echo '<div class="d-flex flex-wrap gap-2">';
    echo '<button type="submit" name="run_scan" value="1" class="btn btn-success">'
        . '<i class="ti ti-player-play me-1" aria-hidden="true"></i>'
        . htmlspecialchars(__('Executar lote agora', 'cvescan'), ENT_QUOTES, 'UTF-8')
        . '</button>';
    echo '<button type="submit" name="clear_cache" value="1" class="btn btn-outline-secondary">'
        . '<i class="ti ti-trash me-1" aria-hidden="true"></i>'
        . htmlspecialchars(__('Limpar cache', 'cvescan'), ENT_QUOTES, 'UTF-8')
        . '</button>';
    echo '</div>';
    Html::closeForm();
}
echo '</div></div></div>';
echo '</div>';

// Tabela de vulnerabilidades recentes
echo '<div class="card">';
echo '<div class="card-header"><h3 class="card-title mb-0">'
    . '<i class="ti ti-list-details me-2" aria-hidden="true"></i>'
    . htmlspecialchars(__('Vulnerabilidades detectadas recentemente', 'cvescan'), ENT_QUOTES, 'UTF-8')
    . '</h3></div>';

if ($recentList === []) {
    echo '<div class="card-body"><div class="alert alert-info mb-0">'
        . htmlspecialchars(__('Nenhuma vulnerabilidade registrada até o momento.', 'cvescan'), ENT_QUOTES, 'UTF-8')
        . '</div></div>';
} else {
    echo '<div class="table-responsive">';
    echo '<table class="table table-hover table-striped card-table mb-0 cvescan-table">';
    echo '<thead><tr>';
    echo '<th>' . htmlspecialchars(__('Software', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '<th>' . htmlspecialchars(__('Versão afetada', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '<th>' . htmlspecialchars(__('Identificador', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '<th>' . htmlspecialchars(__('Severidade / CVSS', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '<th>' . htmlspecialchars(__('Versão corrigida', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '<th class="text-center">' . htmlspecialchars(__('Ativos impactados', 'cvescan'), ENT_QUOTES, 'UTF-8') . '</th>';
    echo '</tr></thead><tbody>';

    foreach ($recentList as $item) {
        $softName  = (string) ($item['software_name'] ?? '');
        $verName   = (string) ($item['version_name'] ?? '');
        $vulnId    = PluginCvescanCompat::fromCore((string) ($item['vuln_id'] ?? ''));
        $severity  = strtoupper(PluginCvescanCompat::fromCore((string) ($item['severity'] ?? 'UNKNOWN')));
        $score     = isset($item['cvss_score']) && $item['cvss_score'] !== null && $item['cvss_score'] !== ''
            ? number_format((float) $item['cvss_score'], 1, '.', '')
            : '';
        $fixedVer  = PluginCvescanCompat::fromCore((string) ($item['fixed_version'] ?? ''));
        $impacted  = (int) ($item['impacted_assets'] ?? 0);
        $safeUrl   = PluginCvescanScanner::sanitizeReferenceUrl(
            PluginCvescanCompat::fromCore((string) ($item['reference_url'] ?? ''))
        );

        $vulnCell = htmlspecialchars($vulnId, ENT_QUOTES, 'UTF-8');
        if ($safeUrl !== '') {
            $vulnCell = '<a href="' . htmlspecialchars($safeUrl, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener noreferrer">'
                . $vulnCell
                . '</a>';
        }

        $badgeClass = PluginCvescanTab::severityBadgeClass($severity);
        $sevLabel   = $severity . ($score !== '' ? ' (' . $score . ')' : '');

        echo '<tr>';
        echo '<td>' . htmlspecialchars($softName, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars($verName, ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td class="fw-bold">' . $vulnCell . '</td>';
        echo '<td><span class="' . htmlspecialchars($badgeClass, ENT_QUOTES, 'UTF-8') . '">'
            . htmlspecialchars($sevLabel, ENT_QUOTES, 'UTF-8') . '</span></td>';
        echo '<td>' . htmlspecialchars($fixedVer !== '' ? $fixedVer : '-', ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td class="text-center"><span class="badge bg-secondary-lt">'
            . htmlspecialchars((string) $impacted, ENT_QUOTES, 'UTF-8') . '</span></td>';
        echo '</tr>';
    }

    echo '</tbody></table></div>';
}

echo '</div></div>';

Html::footer();
