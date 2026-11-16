<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Camada de compatibilidade GLPI 10 / 11 / 12
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

class PluginCvescanCompat
{
    public static function glpiVersion(): string
    {
        return defined('GLPI_VERSION') ? (string) GLPI_VERSION : '10.0.0';
    }

    public static function glpiMajor(): int
    {
        $parts = explode('.', self::glpiVersion());
        $major = (int) ($parts[0] ?? 10);
        return $major > 0 ? $major : 10;
    }

    public static function isGlpi11OrHigher(): bool
    {
        return version_compare(self::glpiVersion(), '11.0.0-dev', '>=');
    }

    public static function typedRightname(): bool
    {
        if (!class_exists('CommonGLPI', true) || !property_exists('CommonGLPI', 'rightname')) {
            return false;
        }
        try {
            $ref = new ReflectionProperty('CommonGLPI', 'rightname');
            return $ref->hasType();
        } catch (ReflectionException $e) {
            return false;
        }
    }

    /**
     * Executa DDL compatível com GLPI 10.0.0–10.0.10 (query) e GLPI 10.0.11+/11/12 (doQuery).
     *
     * @param object $db
     * @return mixed
     */
    public static function execDdl($db, string $sql)
    {
        if (!is_object($db)) {
            return false;
        }
        return method_exists($db, 'doQuery')
            ? $db->doQuery($sql)
            : $db->query($sql);
    }

    public static function webPath(bool $absolute = false): string
    {
        global $CFG_GLPI;

        $base = '';
        if (isset($CFG_GLPI) && is_array($CFG_GLPI)) {
            $key  = $absolute ? 'url_base' : 'root_doc';
            $base = rtrim((string) ($CFG_GLPI[$key] ?? ''), '/');
        }

        if (self::isGlpi11OrHigher()) {
            return $base . '/plugins/cvescan';
        }

        $folder = (basename(dirname(__DIR__, 2)) === 'marketplace') ? 'marketplace' : 'plugins';
        return $base . '/' . $folder . '/cvescan';
    }

    public static function assetPath(string $relative): string
    {
        $clean = ltrim($relative, '/');
        if (strpos($clean, 'public/') === 0) {
            $clean = substr($clean, 7);
        }
        $prefix = self::isGlpi11OrHigher() ? '' : 'public/';
        return $prefix . $clean;
    }

    public static function fromCore(?string $val): string
    {
        if ($val === null || $val === '') {
            return '';
        }
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('Glpi\\Toolbox\\Sanitizer')
                && method_exists('Glpi\\Toolbox\\Sanitizer', 'decodeHtmlSpecialChars')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::decodeHtmlSpecialChars($val);
            }
            return htmlspecialchars_decode($val, ENT_QUOTES);
        }
        return $val;
    }

    public static function fromSanitizedInput(?string $val): string
    {
        if ($val === null || $val === '') {
            return '';
        }
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('Glpi\\Toolbox\\Sanitizer')
                && method_exists('Glpi\\Toolbox\\Sanitizer', 'unsanitize')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::unsanitize($val);
            }
            return htmlspecialchars_decode(stripslashes($val), ENT_QUOTES);
        }
        return $val;
    }

    public static function dbValues(array $data): array
    {
        global $DB;

        if (!self::isGlpi11OrHigher() && isset($DB) && is_object($DB) && method_exists($DB, 'escape')) {
            foreach ($data as $k => $v) {
                if (is_string($v)) {
                    $data[$k] = $DB->escape($v);
                }
            }
        }
        return $data;
    }

    /**
     * @param mixed $values
     * @return mixed
     */
    public static function coreInput($values)
    {
        if (!self::isGlpi11OrHigher()) {
            if (class_exists('Glpi\\Toolbox\\Sanitizer') && method_exists('Glpi\\Toolbox\\Sanitizer', 'sanitize')) {
                return \Glpi\Toolbox\Sanitizer::sanitize($values);
            }
            if (class_exists('Toolbox') && method_exists('Toolbox', 'addslashes_deep')) {
                return Toolbox::addslashes_deep($values);
            }
        }
        return $values;
    }

    public static function denyAccess(string $message = 'Access denied'): void
    {
        if (class_exists('Html') && method_exists('Html', 'displayRightError')) {
            Html::displayRightError();
            return;
        }
        if (class_exists('Glpi\\Exception\\Http\\AccessDeniedHttpException')) {
            throw new \Glpi\Exception\Http\AccessDeniedHttpException($message);
        }
        if (!headers_sent()) {
            http_response_code(403);
        }
        exit;
    }

    public static function requireSafePost(): bool
    {
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
            return false;
        }

        $fetchSite = strtolower(trim((string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($fetchSite !== '') {
            return $fetchSite === 'same-origin';
        }

        $origin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
        if ($origin === '' && isset($_SERVER['HTTP_REFERER'])) {
            $origin = trim((string) $_SERVER['HTTP_REFERER']);
        }
        $host = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));

        if ($origin === '' || $host === '') {
            return false;
        }

        $originHost = parse_url($origin, PHP_URL_HOST);
        $originPort = parse_url($origin, PHP_URL_PORT);
        if (!is_string($originHost) || $originHost === '') {
            return false;
        }

        $expectedHost = $originHost . ($originPort !== null ? ':' . $originPort : '');
        return hash_equals(strtolower($host), strtolower($expectedHost));
    }
}
