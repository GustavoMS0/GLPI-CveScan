<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Configuração do plugin
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

interface PluginCvescanConfigConstants
{
    public const CONTEXT                 = 'plugin:cvescan';
    public const DEFAULT_BATCH_SIZE      = 25;
    public const MIN_BATCH_SIZE          = 1;
    public const MAX_BATCH_SIZE          = 200;
    public const DEFAULT_CACHE_HOURS     = 24;
    public const MIN_CACHE_HOURS         = 1;
    public const MAX_CACHE_HOURS         = 720;
    public const DEFAULT_TIMEOUT_SECONDS = 10;
    public const MIN_TIMEOUT_SECONDS     = 3;
    public const MAX_TIMEOUT_SECONDS     = 30;
}

trait PluginCvescanConfigBody
{
    public static function getTypeName($nb = 0): string
    {
        return __('CVE Scan', 'cvescan');
    }

    /**
     * @return array{batch_size: int, cache_hours: int, timeout_seconds: int, strip_arch_suffix: int}
     */
    public static function getDefaults(): array
    {
        return [
            'batch_size'        => self::DEFAULT_BATCH_SIZE,
            'cache_hours'       => self::DEFAULT_CACHE_HOURS,
            'timeout_seconds'   => self::DEFAULT_TIMEOUT_SECONDS,
            'strip_arch_suffix' => 1,
        ];
    }

    /**
     * @return array{batch_size: int, cache_hours: int, timeout_seconds: int, strip_arch_suffix: int}
     */
    public static function getConfig(): array
    {
        $defaults = self::getDefaults();
        $raw      = class_exists('Config')
            ? Config::getConfigurationValues(self::CONTEXT)
            : [];

        $batchSize = isset($raw['batch_size']) && is_numeric($raw['batch_size'])
            ? (int) $raw['batch_size']
            : $defaults['batch_size'];
        $batchSize = max(self::MIN_BATCH_SIZE, min(self::MAX_BATCH_SIZE, $batchSize));

        $cacheHours = isset($raw['cache_hours']) && is_numeric($raw['cache_hours'])
            ? (int) $raw['cache_hours']
            : $defaults['cache_hours'];
        $cacheHours = max(self::MIN_CACHE_HOURS, min(self::MAX_CACHE_HOURS, $cacheHours));

        $timeoutSeconds = isset($raw['timeout_seconds']) && is_numeric($raw['timeout_seconds'])
            ? (int) $raw['timeout_seconds']
            : $defaults['timeout_seconds'];
        $timeoutSeconds = max(self::MIN_TIMEOUT_SECONDS, min(self::MAX_TIMEOUT_SECONDS, $timeoutSeconds));

        $stripArch = array_key_exists('strip_arch_suffix', $raw)
            ? ((int) $raw['strip_arch_suffix'] === 1 ? 1 : 0)
            : $defaults['strip_arch_suffix'];

        return [
            'batch_size'        => $batchSize,
            'cache_hours'       => $cacheHours,
            'timeout_seconds'   => $timeoutSeconds,
            'strip_arch_suffix' => $stripArch,
        ];
    }

    /**
     * @param array<string, mixed> $input
     * @return array{batch_size: int, cache_hours: int, timeout_seconds: int, strip_arch_suffix: int}
     */
    public static function saveConfig(array $input): array
    {
        $current = self::getConfig();

        $batchSize = isset($input['batch_size']) && is_numeric($input['batch_size'])
            ? max(self::MIN_BATCH_SIZE, min(self::MAX_BATCH_SIZE, (int) $input['batch_size']))
            : $current['batch_size'];

        $cacheHours = isset($input['cache_hours']) && is_numeric($input['cache_hours'])
            ? max(self::MIN_CACHE_HOURS, min(self::MAX_CACHE_HOURS, (int) $input['cache_hours']))
            : $current['cache_hours'];

        $timeoutSeconds = isset($input['timeout_seconds']) && is_numeric($input['timeout_seconds'])
            ? max(self::MIN_TIMEOUT_SECONDS, min(self::MAX_TIMEOUT_SECONDS, (int) $input['timeout_seconds']))
            : $current['timeout_seconds'];

        $stripArch = array_key_exists('strip_arch_suffix', $input)
            ? (!empty($input['strip_arch_suffix']) ? 1 : 0)
            : $current['strip_arch_suffix'];

        $values = [
            'batch_size'        => $batchSize,
            'cache_hours'       => $cacheHours,
            'timeout_seconds'   => $timeoutSeconds,
            'strip_arch_suffix' => $stripArch,
        ];

        if (class_exists('Config')) {
            Config::setConfigurationValues(self::CONTEXT, $values);
        }

        return $values;
    }

    public static function installDefaults(): void
    {
        if (!class_exists('Config')) {
            return;
        }
        $existing = Config::getConfigurationValues(self::CONTEXT);
        $toSave   = [];
        foreach (self::getDefaults() as $key => $val) {
            if (!array_key_exists($key, $existing)) {
                $toSave[$key] = $val;
            }
        }
        if ($toSave !== []) {
            Config::setConfigurationValues(self::CONTEXT, $toSave);
        }
    }

    public static function uninstallConfig(): void
    {
        if (!class_exists('Config')) {
            return;
        }
        Config::deleteConfigurationValues(self::CONTEXT, array_keys(self::getDefaults()));
    }
}

if (!class_exists('PluginCvescanConfig', false)) {
    if (PluginCvescanCompat::typedRightname()) {
        class PluginCvescanConfig extends CommonGLPI implements PluginCvescanConfigConstants
        {
            use PluginCvescanConfigBody;

            public static string $rightname = 'config';
        }
    } else {
        class PluginCvescanConfig extends CommonGLPI implements PluginCvescanConfigConstants
        {
            use PluginCvescanConfigBody;

            public static $rightname = 'config';
        }
    }
}
