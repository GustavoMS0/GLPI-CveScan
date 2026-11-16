<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Aba dedicada em Software
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
    die("Sorry. You can't access this file directly");
}

require_once __DIR__ . '/compat.class.php';
require_once __DIR__ . '/config.class.php';
require_once __DIR__ . '/scanner.class.php';

interface PluginCvescanTabConstants
{
    public const TAB_NUM = 1;
}

trait PluginCvescanTabBody
{
    public static function getTypeName($nb = 0): string
    {
        return __('CVEs', 'cvescan');
    }

    public static function canView(): bool
    {
        return (bool) Session::haveRight(self::$rightname, READ);
    }

    private static function escapeHtml(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    public static function severityBadgeClass(string $severity): string
    {
        $upper = strtoupper(trim($severity));
        if ($upper === 'CRITICAL') {
            return 'cvescan-badge cvescan-badge-critical';
        }
        if ($upper === 'HIGH') {
            return 'cvescan-badge cvescan-badge-high';
        }
        if ($upper === 'MEDIUM') {
            return 'cvescan-badge cvescan-badge-medium';
        }
        if ($upper === 'LOW') {
            return 'cvescan-badge cvescan-badge-low';
        }
        return 'cvescan-badge cvescan-badge-unknown';
    }

    private static function canAccessSoftware(CommonGLPI $item, $withtemplate = 0): bool
    {
        if ($withtemplate || !($item instanceof Software)) {
            return false;
        }
        $softwaresId = (int) $item->getID();
        if ($softwaresId <= 0) {
            return false;
        }
        if ((int) Session::getLoginUserID(true) <= 0) {
            return false;
        }
        if (!$item->canViewItem()) {
            return false;
        }
        if (
            method_exists($item, 'getEntityID')
            && method_exists('Session', 'haveAccessToEntity')
            && !Session::haveAccessToEntity((int) $item->getEntityID())
        ) {
            return false;
        }
        return true;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!self::canAccessSoftware($item, $withtemplate)) {
            return '';
        }

        $count = PluginCvescanScanner::countFindingsForSoftware((int) $item->getID());
        return self::createTabEntry(__('CVEs', 'cvescan'), $count);
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
    {
        if (!self::canAccessSoftware($item, $withtemplate)) {
            return false;
        }

        $softwaresId = (int) $item->getID();
        $findings    = PluginCvescanScanner::getFindingsForSoftware($softwaresId);

        echo '<div class="cvescan-tab">';
        echo '<div class="card border-0 shadow-none">';
        echo '<div class="card-header d-flex align-items-center justify-content-between">';
        echo '<h3 class="card-title mb-0">'
            . '<i class="ti ti-shield-exclamation me-2" aria-hidden="true"></i>'
            . self::escapeHtml(__('Vulnerabilidades identificadas (CVE / OSV)', 'cvescan'))
            . '</h3>';
        echo '<span class="badge bg-blue-lt cvescan-badge-total">'
            . self::escapeHtml((string) count($findings))
            . '</span>';
        echo '</div>';

        if ($findings === []) {
            echo '<div class="card-body">';
            echo '<div class="alert alert-success mb-0 cvescan-empty">'
                . '<i class="ti ti-shield-check me-2" aria-hidden="true"></i>'
                . self::escapeHtml(__('Nenhuma vulnerabilidade conhecida registrada para as versões deste software.', 'cvescan'))
                . '</div>';
            echo '</div>';
        } else {
            echo '<div class="table-responsive">';
            echo '<table class="table table-hover table-striped card-table mb-0 cvescan-table">';
            echo '<thead><tr>';
            echo '<th scope="col">' . self::escapeHtml(__('Identificador', 'cvescan')) . '</th>';
            echo '<th scope="col">' . self::escapeHtml(__('Severidade / CVSS', 'cvescan')) . '</th>';
            echo '<th scope="col">' . self::escapeHtml(__('Versão afetada', 'cvescan')) . '</th>';
            echo '<th scope="col">' . self::escapeHtml(__('Versão corrigida', 'cvescan')) . '</th>';
            echo '<th scope="col" class="text-center">' . self::escapeHtml(__('Ativos impactados', 'cvescan')) . '</th>';
            echo '<th scope="col">' . self::escapeHtml(__('Resumo', 'cvescan')) . '</th>';
            echo '<th scope="col">' . self::escapeHtml(__('Última verificação', 'cvescan')) . '</th>';
            echo '</tr></thead>';
            echo '<tbody>';

            foreach ($findings as $row) {
                $vulnId       = PluginCvescanCompat::fromCore((string) ($row['vuln_id'] ?? ''));
                $severity     = strtoupper(PluginCvescanCompat::fromCore((string) ($row['severity'] ?? 'UNKNOWN')));
                $score        = isset($row['cvss_score']) && $row['cvss_score'] !== null && $row['cvss_score'] !== ''
                    ? number_format((float) $row['cvss_score'], 1, '.', '')
                    : '';
                $versionName  = (string) ($row['version_name'] ?? '');
                $fixedVersion = PluginCvescanCompat::fromCore((string) ($row['fixed_version'] ?? ''));
                $impacted     = (int) ($row['impacted_assets'] ?? 0);
                $summary      = PluginCvescanCompat::fromCore((string) ($row['summary'] ?? ''));
                $lastScanned  = (string) ($row['last_scanned_at'] ?? '');
                $safeRefUrl   = PluginCvescanScanner::sanitizeReferenceUrl(
                    PluginCvescanCompat::fromCore((string) ($row['reference_url'] ?? ''))
                );

                $vulnHtml = self::escapeHtml($vulnId);
                if ($safeRefUrl !== '') {
                    $vulnHtml = '<a href="' . self::escapeHtml($safeRefUrl) . '" target="_blank" rel="noopener noreferrer">'
                        . $vulnHtml
                        . '</a>';
                }

                $badgeClass = self::severityBadgeClass($severity);
                $sevLabel   = $severity . ($score !== '' ? ' (' . $score . ')' : '');
                $fixedText  = $fixedVersion !== '' ? $fixedVersion : '-';
                $scanText   = ($lastScanned !== '' && class_exists('Html') && method_exists('Html', 'convDateTime'))
                    ? (string) Html::convDateTime($lastScanned)
                    : ($lastScanned !== '' ? $lastScanned : '-');

                echo '<tr>';
                echo '<td class="fw-bold">' . $vulnHtml . '</td>';
                echo '<td><span class="' . self::escapeHtml($badgeClass) . '">' . self::escapeHtml($sevLabel) . '</span></td>';
                echo '<td>' . self::escapeHtml($versionName) . '</td>';
                echo '<td>' . self::escapeHtml($fixedText) . '</td>';
                echo '<td class="text-center"><span class="badge bg-secondary-lt">' . self::escapeHtml((string) $impacted) . '</span></td>';
                echo '<td>' . self::escapeHtml($summary) . '</td>';
                echo '<td>' . self::escapeHtml($scanText) . '</td>';
                echo '</tr>';
            }

            echo '</tbody></table></div>';
        }

        echo '</div></div>';
        return true;
    }
}

if (!class_exists('PluginCvescanTab', false)) {
    if (PluginCvescanCompat::typedRightname()) {
        class PluginCvescanTab extends CommonGLPI implements PluginCvescanTabConstants
        {
            use PluginCvescanTabBody;

            public static string $rightname = 'software';
        }
    } else {
        class PluginCvescanTab extends CommonGLPI implements PluginCvescanTabConstants
        {
            use PluginCvescanTabBody;

            public static $rightname = 'software';
        }
    }
}
