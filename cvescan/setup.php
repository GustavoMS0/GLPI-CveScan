<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Inicialização e manifesto do plugin
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

define('PLUGIN_CVESCAN_VERSION', '1.0.0');
define('PLUGIN_CVESCAN_MIN_GLPI_VERSION', '10.0.0');
define('PLUGIN_CVESCAN_MAX_GLPI_VERSION', '12.0.99');

require_once __DIR__ . '/inc/compat.class.php';
require_once __DIR__ . '/inc/config.class.php';
require_once __DIR__ . '/inc/scanner.class.php';
require_once __DIR__ . '/inc/tab.class.php';

function plugin_init_cvescan(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['cvescan'] = true;
    $PLUGIN_HOOKS['config_page']['cvescan']    = 'front/config.form.php';
    $PLUGIN_HOOKS['add_css']['cvescan']        = [
        PluginCvescanCompat::assetPath('css/cvescan.css'),
    ];

    if (class_exists('Plugin') && method_exists('Plugin', 'registerClass')) {
        Plugin::registerClass('PluginCvescanTab', [
            'addtabon' => ['Software'],
        ]);
    }

    $PLUGIN_HOOKS['item_purge']['cvescan'] = [
        'Software'        => [PluginCvescanScanner::class, 'purgeItem'],
        'SoftwareVersion' => [PluginCvescanScanner::class, 'purgeItem'],
    ];
}

/**
 * @return array<string, mixed>
 */
function plugin_version_cvescan(): array
{
    return [
        'name'         => 'CVE Scan',
        'version'      => PLUGIN_CVESCAN_VERSION,
        'author'       => 'G. Martins',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://github.com/GustavoMS0/GLPI-CveScan',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_CVESCAN_MIN_GLPI_VERSION,
                'max' => PLUGIN_CVESCAN_MAX_GLPI_VERSION,
            ],
            'php' => [
                'min' => '7.4',
            ],
        ],
    ];
}

function plugin_cvescan_check_prerequisites(): bool
{
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        return false;
    }

    if (defined('GLPI_VERSION')) {
        if (version_compare((string) GLPI_VERSION, PLUGIN_CVESCAN_MIN_GLPI_VERSION, '<')) {
            return false;
        }
        if (version_compare((string) GLPI_VERSION, PLUGIN_CVESCAN_MAX_GLPI_VERSION, '>')) {
            return false;
        }
    }

    return true;
}

function plugin_cvescan_check_config(bool $verbose = false): bool
{
    return true;
}
