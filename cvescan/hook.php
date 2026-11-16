<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Instalação e desinstalação do plugin
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

require_once __DIR__ . '/inc/compat.class.php';
require_once __DIR__ . '/inc/config.class.php';
require_once __DIR__ . '/inc/scanner.class.php';

function plugin_cvescan_install(): bool
{
    PluginCvescanScanner::installSchema();
    PluginCvescanConfig::installDefaults();

    if (class_exists('CronTask') && method_exists('CronTask', 'register')) {
        $interval = defined('DAY_TIMESTAMP') ? (int) DAY_TIMESTAMP : 86400;
        CronTask::register(
            PluginCvescanScanner::class,
            'CveScan',
            $interval,
            [
                'comment' => __('Varredura periódica de vulnerabilidades CVE/OSV no inventário de softwares', 'cvescan'),
                'mode'    => 2,
            ]
        );
    }

    return true;
}

function plugin_cvescan_uninstall(): bool
{
    if (class_exists('CronTask') && method_exists('CronTask', 'unregister')) {
        CronTask::unregister('cvescan');
    }

    PluginCvescanScanner::uninstallSchema();
    PluginCvescanConfig::uninstallConfig();

    return true;
}
