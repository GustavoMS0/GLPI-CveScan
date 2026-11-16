<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Motor de varredura de vulnerabilidades (OSV.dev / CVE)
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

interface PluginCvescanScannerConstants
{
    public const TABLE_FINDINGS = 'glpi_plugin_cvescan_findings';
    public const TABLE_CACHE    = 'glpi_plugin_cvescan_cache';
    public const OSV_API_URL    = 'https://api.osv.dev/v1/query';
}

trait PluginCvescanScannerBody
{
    /** @var callable|null */
    private static $httpTransport = null;

    /** @var string|null */
    private static $nowOverride = null;

    public static function getTypeName($nb = 0): string
    {
        return __('Varredura de CVEs', 'cvescan');
    }

    public static function setHttpTransport(?callable $fn): void
    {
        self::$httpTransport = $fn;
    }

    public static function setNowForTest(?string $now): void
    {
        self::$nowOverride = $now;
    }

    public static function resetRuntimeState(): void
    {
        self::$httpTransport = null;
        self::$nowOverride   = null;
    }

    public static function now(): string
    {
        if (self::$nowOverride !== null && self::$nowOverride !== '') {
            return self::$nowOverride;
        }
        return date('Y-m-d H:i:s');
    }

    public static function installSchema(): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        $charset   = class_exists('DBConnection') ? DBConnection::getDefaultCharset() : 'utf8mb4';
        $collation = class_exists('DBConnection') ? DBConnection::getDefaultCollation() : 'utf8mb4_unicode_ci';

        if (!$DB->tableExists(self::TABLE_FINDINGS)) {
            $sqlFindings = 'CREATE TABLE `' . self::TABLE_FINDINGS . '` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `softwares_id` int unsigned NOT NULL DEFAULT 0,
                `softwareversions_id` int unsigned NOT NULL DEFAULT 0,
                `vuln_id` varchar(64) NOT NULL DEFAULT \'\',
                `severity` varchar(16) NOT NULL DEFAULT \'UNKNOWN\',
                `cvss_score` decimal(4,1) NULL DEFAULT NULL,
                `summary` varchar(500) NOT NULL DEFAULT \'\',
                `fixed_version` varchar(128) NOT NULL DEFAULT \'\',
                `reference_url` varchar(500) NOT NULL DEFAULT \'\',
                `detected_at` timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `uniq_version_vuln` (`softwareversions_id`, `vuln_id`),
                KEY `idx_softwares_id` (`softwares_id`),
                KEY `idx_severity` (`severity`)
            ) ENGINE=InnoDB DEFAULT CHARSET=' . $charset . ' COLLATE=' . $collation . ';';

            PluginCvescanCompat::execDdl($DB, $sqlFindings);
        }

        if (!$DB->tableExists(self::TABLE_CACHE)) {
            $sqlCache = 'CREATE TABLE `' . self::TABLE_CACHE . '` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `softwareversions_id` int unsigned NOT NULL DEFAULT 0,
                `last_scanned_at` timestamp NULL DEFAULT NULL,
                `findings_count` int unsigned NOT NULL DEFAULT 0,
                `status` varchar(32) NOT NULL DEFAULT \'ok\',
                PRIMARY KEY (`id`),
                UNIQUE KEY `uniq_softwareversions_id` (`softwareversions_id`),
                KEY `idx_last_scanned_at` (`last_scanned_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=' . $charset . ' COLLATE=' . $collation . ';';

            PluginCvescanCompat::execDdl($DB, $sqlCache);
        }
    }

    public static function uninstallSchema(): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        if ($DB->tableExists(self::TABLE_FINDINGS)) {
            PluginCvescanCompat::execDdl($DB, 'DROP TABLE IF EXISTS `' . self::TABLE_FINDINGS . '`;');
        }
        if ($DB->tableExists(self::TABLE_CACHE)) {
            PluginCvescanCompat::execDdl($DB, 'DROP TABLE IF EXISTS `' . self::TABLE_CACHE . '`;');
        }
    }

    /**
     * Normaliza o nome do software para consulta estruturada.
     */
    public static function normalizePackageName(string $rawName, bool $stripArch = true): string
    {
        $name = trim(PluginCvescanCompat::fromCore($rawName));
        if ($name === '') {
            return '';
        }

        if ($stripArch) {
            // Remove sufixos entre parênteses/colchetes de arquitetura ou idioma como (x64), (64-bit), (x86 en-US)
            $name = (string) preg_replace(
                '/\s*[\(\[](?:x64|x86|x86_64|amd64|arm64|aarch64|64-bit|32-bit|64\s*bits?|32\s*bits?)(?:\s+[^)\]]*)?[\)\]]/i',
                '',
                $name
            );
            // Remove tokens finais de arquitetura soltos
            $name = (string) preg_replace(
                '/\s+(?:x64|x86|x86_64|amd64|arm64|64-bit|32-bit)$/i',
                '',
                $name
            );
        }

        $name = (string) preg_replace('/\s+/', ' ', trim($name));
        return strtolower($name);
    }

    /**
     * Normaliza a string de versão semântica do software.
     */
    public static function normalizeVersion(string $rawVersion, bool $stripRevision = true): string
    {
        $ver = trim(PluginCvescanCompat::fromCore($rawVersion));
        if ($ver === '') {
            return '';
        }

        // Remove anotações entre parênteses como (x64) ou (64-bit)
        $ver = (string) preg_replace('/\s*\([^)]*\)/', '', $ver);
        $ver = trim($ver);

        // Remove prefixo 'v' ou 'V' seguido de dígito
        if (preg_match('/^[vV](\d.*)$/', $ver, $m)) {
            $ver = $m[1];
        }

        if ($stripRevision) {
            // Remove revisões de distribuição empacotada (ex: 1.20.1-1ubuntu2.1 -> 1.20.1, 3.0.12+deb12u1 -> 3.0.12)
            $ver = (string) preg_replace('/[+-](?:deb|ubuntu|el|fc|rhel|alpine|build|\d)[a-zA-Z0-9._+-]*$/i', '', $ver);
        }

        return trim($ver);
    }

    /**
     * Valida estritamente URLs de referência permitindo apenas https:// bem formados.
     */
    public static function sanitizeReferenceUrl(string $url): string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 500) {
            return '';
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $host   = (string) parse_url($url, PHP_URL_HOST);

        if ($scheme !== 'https' || $host === '') {
            return '';
        }

        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return '';
        }

        return $url;
    }

    /**
     * Classifica severidade CVSS a partir da nota numérica (0.0 a 10.0).
     */
    public static function classifyCvssScore(?float $score): string
    {
        if ($score === null || $score <= 0.0) {
            return 'UNKNOWN';
        }
        if ($score >= 9.0) {
            return 'CRITICAL';
        }
        if ($score >= 7.0) {
            return 'HIGH';
        }
        if ($score >= 4.0) {
            return 'MEDIUM';
        }
        return 'LOW';
    }

    /**
     * Extrai severidade e nota CVSS de um registro de vulnerabilidade OSV.
     *
     * @param array<string, mixed> $vuln
     * @return array{severity: string, score: float|null}
     */
    public static function extractSeverityAndScore(array $vuln): array
    {
        $score = null;

        if (isset($vuln['database_specific']) && is_array($vuln['database_specific'])) {
            $dbSpec = $vuln['database_specific'];
            if (isset($dbSpec['cvss_score']) && is_numeric($dbSpec['cvss_score'])) {
                $score = round((float) $dbSpec['cvss_score'], 1);
            }
        }

        if ($score === null && isset($vuln['severity']) && is_array($vuln['severity'])) {
            foreach ($vuln['severity'] as $sevEntry) {
                if (!is_array($sevEntry)) {
                    continue;
                }
                $rawScore = isset($sevEntry['score']) ? trim((string) $sevEntry['score']) : '';
                if ($rawScore !== '' && is_numeric($rawScore)) {
                    $val = (float) $rawScore;
                    if ($val >= 0.0 && $val <= 10.0) {
                        $score = round($val, 1);
                        break;
                    }
                }
            }
        }

        if ($score !== null) {
            return [
                'severity' => self::classifyCvssScore($score),
                'score'    => $score,
            ];
        }

        $textCandidates = [];
        if (isset($vuln['database_specific']['severity']) && is_string($vuln['database_specific']['severity'])) {
            $textCandidates[] = $vuln['database_specific']['severity'];
        }
        if (isset($vuln['ecosystem_specific']['severity']) && is_string($vuln['ecosystem_specific']['severity'])) {
            $textCandidates[] = $vuln['ecosystem_specific']['severity'];
        }

        foreach ($textCandidates as $candidate) {
            $upper = strtoupper(trim($candidate));
            if ($upper === 'CRITICAL') {
                return ['severity' => 'CRITICAL', 'score' => null];
            }
            if ($upper === 'HIGH') {
                return ['severity' => 'HIGH', 'score' => null];
            }
            if ($upper === 'MEDIUM' || $upper === 'MODERATE') {
                return ['severity' => 'MEDIUM', 'score' => null];
            }
            if ($upper === 'LOW') {
                return ['severity' => 'LOW', 'score' => null];
            }
        }

        return ['severity' => 'UNKNOWN', 'score' => null];
    }

    /**
     * Faz o parsing do JSON retornado pela API OSV.dev.
     * Retorna null em caso de JSON inválido/malformado ou lista de findings normalizados.
     *
     * @return array<int, array{
     *   vuln_id: string,
     *   severity: string,
     *   cvss_score: float|null,
     *   summary: string,
     *   fixed_version: string,
     *   reference_url: string
     * }>|null
     */
    public static function parseOsvResponse(string $jsonBody): ?array
    {
        if (trim($jsonBody) === '') {
            return null;
        }

        $decoded = json_decode($jsonBody, true);
        if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        if (!isset($decoded['vulns']) || !is_array($decoded['vulns'])) {
            return [];
        }

        $findings = [];
        $seenIds  = [];

        foreach ($decoded['vulns'] as $vuln) {
            if (!is_array($vuln)) {
                continue;
            }

            $vulnId = '';
            if (isset($vuln['aliases']) && is_array($vuln['aliases'])) {
                foreach ($vuln['aliases'] as $alias) {
                    if (is_string($alias) && preg_match('/^CVE-\d{4}-\d{4,}$/i', trim($alias))) {
                        $vulnId = strtoupper(trim($alias));
                        break;
                    }
                }
            }
            if ($vulnId === '' && isset($vuln['id']) && is_string($vuln['id'])) {
                $vulnId = substr(trim($vuln['id']), 0, 64);
            }
            if ($vulnId === '' || isset($seenIds[$vulnId])) {
                continue;
            }
            $seenIds[$vulnId] = true;

            $summary = '';
            if (isset($vuln['summary']) && is_string($vuln['summary']) && trim($vuln['summary']) !== '') {
                $summary = trim($vuln['summary']);
            } elseif (isset($vuln['details']) && is_string($vuln['details']) && trim($vuln['details']) !== '') {
                $details = trim((string) preg_replace('/\s+/', ' ', $vuln['details']));
                $summary = $details;
            }
            if (strlen($summary) > 500) {
                $summary = substr($summary, 0, 497) . '...';
            }

            $sevData = self::extractSeverityAndScore($vuln);

            $fixedVersion = '';
            if (isset($vuln['affected']) && is_array($vuln['affected'])) {
                foreach ($vuln['affected'] as $affected) {
                    if (!is_array($affected) || !isset($affected['ranges']) || !is_array($affected['ranges'])) {
                        continue;
                    }
                    foreach ($affected['ranges'] as $range) {
                        if (!is_array($range) || !isset($range['events']) || !is_array($range['events'])) {
                            continue;
                        }
                        foreach ($range['events'] as $event) {
                            if (is_array($event) && isset($event['fixed']) && is_string($event['fixed']) && trim($event['fixed']) !== '') {
                                $fixedVersion = substr(trim($event['fixed']), 0, 128);
                                break 3;
                            }
                        }
                    }
                }
            }

            $referenceUrl = '';
            if (isset($vuln['references']) && is_array($vuln['references'])) {
                foreach ($vuln['references'] as $ref) {
                    if (!is_array($ref) || !isset($ref['url']) || !is_string($ref['url'])) {
                        continue;
                    }
                    $safeUrl = self::sanitizeReferenceUrl($ref['url']);
                    if ($safeUrl !== '') {
                        $referenceUrl = $safeUrl;
                        break;
                    }
                }
            }

            if ($referenceUrl === '') {
                if (strpos($vulnId, 'CVE-') === 0) {
                    $referenceUrl = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($vulnId);
                } else {
                    $referenceUrl = 'https://osv.dev/vulnerability/' . rawurlencode($vulnId);
                }
            }

            $findings[] = [
                'vuln_id'       => $vulnId,
                'severity'      => $sevData['severity'],
                'cvss_score'    => $sevData['score'],
                'summary'       => $summary,
                'fixed_version' => $fixedVersion,
                'reference_url' => $referenceUrl,
            ];
        }

        return $findings;
    }

    /**
     * Consulta a API OSV.dev usando URL imutável e verificação TLS estrita.
     *
     * @return array<int, array{
     *   vuln_id: string,
     *   severity: string,
     *   cvss_score: float|null,
     *   summary: string,
     *   fixed_version: string,
     *   reference_url: string
     * }>|null
     */
    public static function queryOsv(string $packageName, string $version, int $timeoutSeconds = 10): ?array
    {
        if ($packageName === '' || $version === '') {
            return [];
        }

        $timeout = max(
            PluginCvescanConfig::MIN_TIMEOUT_SECONDS,
            min(PluginCvescanConfig::MAX_TIMEOUT_SECONDS, $timeoutSeconds)
        );

        $payload = (string) json_encode([
            'version' => $version,
            'package' => [
                'name' => $packageName,
            ],
        ]);

        if (self::$httpTransport !== null) {
            try {
                $response = call_user_func(self::$httpTransport, self::OSV_API_URL, $payload, $timeout);
            } catch (\Throwable $e) {
                return null;
            }

            if (is_string($response)) {
                return self::parseOsvResponse($response);
            }
            if (is_array($response)) {
                $status = (int) ($response['status'] ?? 200);
                $body   = isset($response['body']) && is_string($response['body']) ? $response['body'] : '';
                if ($status < 200 || $status >= 300) {
                    return null;
                }
                return self::parseOsvResponse($body);
            }
            return null;
        }

        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init(self::OSV_API_URL);
        if ($ch === false) {
            return null;
        }

        $opts = [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'User-Agent: GLPI-CveScan/1.0',
            ],
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
        ];
        if (defined('CURLPROTO_HTTPS')) {
            $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        curl_setopt_array($ch, $opts);
        $rawBody  = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!is_string($rawBody) || $httpCode < 200 || $httpCode >= 300) {
            return null;
        }

        return self::parseOsvResponse($rawBody);
    }

    /**
     * Conta quantos ativos possuem determinada versão de software instalada.
     */
    public static function countInstallationsForVersion(int $softwareversions_id): int
    {
        global $DB;

        if ($softwareversions_id <= 0 || !isset($DB) || !is_object($DB)) {
            return 0;
        }

        $table = '';
        if ($DB->tableExists('glpi_items_softwareversions')) {
            $table = 'glpi_items_softwareversions';
        } elseif ($DB->tableExists('glpi_computers_softwareversions')) {
            $table = 'glpi_computers_softwareversions';
        }

        if ($table === '') {
            return 0;
        }

        $where = ['softwareversions_id' => $softwareversions_id];
        if (method_exists($DB, 'fieldExists') && $DB->fieldExists($table, 'is_deleted')) {
            $where['is_deleted'] = 0;
        }

        $it = $DB->request([
            'COUNT' => 'cnt',
            'FROM'  => $table,
            'WHERE' => $where,
        ]);

        foreach ($it as $row) {
            return (int) ($row['cnt'] ?? 0);
        }

        return 0;
    }

    /**
     * Verifica se uma versão possui cache válido dentro do TTL configurado.
     */
    public static function isCacheFresh(int $softwareversions_id, int $cacheHours): bool
    {
        global $DB;

        if ($softwareversions_id <= 0 || $cacheHours <= 0 || !isset($DB) || !$DB->tableExists(self::TABLE_CACHE)) {
            return false;
        }

        $it = $DB->request([
            'FROM'  => self::TABLE_CACHE,
            'WHERE' => ['softwareversions_id' => $softwareversions_id],
            'LIMIT' => 1,
        ]);

        foreach ($it as $row) {
            $status      = (string) ($row['status'] ?? '');
            $lastScanned = (string) ($row['last_scanned_at'] ?? '');
            if ($status !== 'ok' || $lastScanned === '') {
                return false;
            }
            $lastTs = strtotime($lastScanned);
            $nowTs  = strtotime(self::now());
            if ($lastTs === false || $nowTs === false) {
                return false;
            }
            return ($lastTs + ($cacheHours * 3600)) > $nowTs;
        }

        return false;
    }

    /**
     * Executa a varredura de uma versão específica de software.
     *
     * @return array{status: string, findings_count: int, skipped: bool}
     */
    public static function scanSoftwareVersion(int $softwareversions_id, bool $force = false): array
    {
        global $DB;

        if (
            $softwareversions_id <= 0
            || !isset($DB)
            || !$DB->tableExists('glpi_softwareversions')
            || !$DB->tableExists('glpi_softwares')
            || !$DB->tableExists(self::TABLE_FINDINGS)
            || !$DB->tableExists(self::TABLE_CACHE)
        ) {
            return ['status' => 'error', 'findings_count' => 0, 'skipped' => false];
        }

        $cfg = PluginCvescanConfig::getConfig();

        if (!$force && self::isCacheFresh($softwareversions_id, $cfg['cache_hours'])) {
            $cachedCount = 0;
            $itCache     = $DB->request([
                'FROM'  => self::TABLE_CACHE,
                'WHERE' => ['softwareversions_id' => $softwareversions_id],
                'LIMIT' => 1,
            ]);
            foreach ($itCache as $cRow) {
                $cachedCount = (int) ($cRow['findings_count'] ?? 0);
            }
            return ['status' => 'cached', 'findings_count' => $cachedCount, 'skipped' => true];
        }

        $verRow = null;
        $itVer  = $DB->request([
            'FROM'  => 'glpi_softwareversions',
            'WHERE' => ['id' => $softwareversions_id],
            'LIMIT' => 1,
        ]);
        foreach ($itVer as $row) {
            $verRow = $row;
            break;
        }

        if ($verRow === null) {
            return ['status' => 'not_found', 'findings_count' => 0, 'skipped' => false];
        }

        $softwaresId = (int) ($verRow['softwares_id'] ?? 0);
        $softRow     = null;
        $whereSoft   = ['id' => $softwaresId];
        if (method_exists($DB, 'fieldExists') && $DB->fieldExists('glpi_softwares', 'is_deleted')) {
            $whereSoft['is_deleted'] = 0;
        }

        $itSoft = $DB->request([
            'FROM'  => 'glpi_softwares',
            'WHERE' => $whereSoft,
            'LIMIT' => 1,
        ]);
        foreach ($itSoft as $row) {
            $softRow = $row;
            break;
        }

        if ($softRow === null) {
            return ['status' => 'software_deleted', 'findings_count' => 0, 'skipped' => false];
        }

        $stripArch   = !empty($cfg['strip_arch_suffix']);
        $packageName = self::normalizePackageName((string) ($softRow['name'] ?? ''), $stripArch);
        $versionName = self::normalizeVersion((string) ($verRow['name'] ?? ''), $stripArch);

        if ($packageName === '' || $versionName === '') {
            self::upsertCache($softwareversions_id, 0, 'ok');
            return ['status' => 'ok', 'findings_count' => 0, 'skipped' => false];
        }

        $findings = self::queryOsv($packageName, $versionName, $cfg['timeout_seconds']);
        if ($findings === null) {
            self::upsertCache($softwareversions_id, 0, 'error');
            return ['status' => 'error', 'findings_count' => 0, 'skipped' => false];
        }

        $now = self::now();

        // Substitui findings anteriores dessa versão pelos atuais
        $DB->delete(self::TABLE_FINDINGS, ['softwareversions_id' => $softwareversions_id]);

        foreach ($findings as $finding) {
            $row = PluginCvescanCompat::dbValues([
                'softwares_id'        => $softwaresId,
                'softwareversions_id' => $softwareversions_id,
                'vuln_id'             => (string) $finding['vuln_id'],
                'severity'            => (string) $finding['severity'],
                'cvss_score'          => $finding['cvss_score'],
                'summary'             => (string) $finding['summary'],
                'fixed_version'       => (string) $finding['fixed_version'],
                'reference_url'       => (string) $finding['reference_url'],
                'detected_at'         => $now,
            ]);
            $DB->insert(self::TABLE_FINDINGS, $row);
        }

        $count = count($findings);
        self::upsertCache($softwareversions_id, $count, 'ok');

        return [
            'status'         => 'ok',
            'findings_count' => $count,
            'skipped'        => false,
        ];
    }

    private static function upsertCache(int $softwareversions_id, int $findingsCount, string $status): void
    {
        global $DB;

        if (!isset($DB) || !$DB->tableExists(self::TABLE_CACHE)) {
            return;
        }

        $now      = self::now();
        $existing = null;
        $it       = $DB->request([
            'FROM'  => self::TABLE_CACHE,
            'WHERE' => ['softwareversions_id' => $softwareversions_id],
            'LIMIT' => 1,
        ]);
        foreach ($it as $row) {
            $existing = $row;
            break;
        }

        $payload = PluginCvescanCompat::dbValues([
            'softwareversions_id' => $softwareversions_id,
            'last_scanned_at'     => $now,
            'findings_count'      => max(0, $findingsCount),
            'status'              => $status,
        ]);

        if ($existing !== null) {
            $DB->update(self::TABLE_CACHE, $payload, ['softwareversions_id' => $softwareversions_id]);
        } else {
            $DB->insert(self::TABLE_CACHE, $payload);
        }
    }

    /**
     * Retorna até $limit IDs de versões de softwares ativos candidatas à varredura.
     *
     * @return int[]
     */
    public static function getCandidateVersionIds(int $limit, int $cacheHours, bool $force = false): array
    {
        global $DB;

        if (
            $limit <= 0
            || !isset($DB)
            || !$DB->tableExists('glpi_softwareversions')
            || !$DB->tableExists('glpi_softwares')
        ) {
            return [];
        }

        $whereSoft = [];
        if (method_exists($DB, 'fieldExists') && $DB->fieldExists('glpi_softwares', 'is_deleted')) {
            $whereSoft['is_deleted'] = 0;
        }

        $activeSoftwares = [];
        $itSoft          = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_softwares',
            'WHERE'  => $whereSoft,
        ]);
        foreach ($itSoft as $sRow) {
            $sid = (int) ($sRow['id'] ?? 0);
            if ($sid > 0) {
                $activeSoftwares[$sid] = true;
            }
        }

        if ($activeSoftwares === []) {
            return [];
        }

        $candidates = [];
        $itVers     = $DB->request([
            'SELECT' => ['id', 'softwares_id'],
            'FROM'   => 'glpi_softwareversions',
            'ORDER'  => 'id ASC',
        ]);

        foreach ($itVers as $vRow) {
            $vid = (int) ($vRow['id'] ?? 0);
            $sid = (int) ($vRow['softwares_id'] ?? 0);
            if ($vid <= 0 || !isset($activeSoftwares[$sid])) {
                continue;
            }
            if (!$force && self::isCacheFresh($vid, $cacheHours)) {
                continue;
            }
            $candidates[] = $vid;
            if (count($candidates) >= $limit) {
                break;
            }
        }

        return $candidates;
    }

    /**
     * Executa varredura em lote respeitando batch_size.
     *
     * @return array{scanned: int, skipped: int, findings: int, errors: int}
     */
    public static function runBatchScan(int $limit = 0, bool $force = false): array
    {
        $cfg       = PluginCvescanConfig::getConfig();
        $batchSize = $limit > 0
            ? max(1, min(PluginCvescanConfig::MAX_BATCH_SIZE, $limit))
            : $cfg['batch_size'];

        $versionIds = self::getCandidateVersionIds($batchSize, $cfg['cache_hours'], $force);

        $stats = [
            'scanned'  => 0,
            'skipped'  => 0,
            'findings' => 0,
            'errors'   => 0,
        ];

        foreach ($versionIds as $vid) {
            $res = self::scanSoftwareVersion($vid, $force);
            if (!empty($res['skipped'])) {
                $stats['skipped']++;
            } elseif ($res['status'] === 'ok') {
                $stats['scanned']++;
                $stats['findings'] += (int) $res['findings_count'];
            } else {
                $stats['errors']++;
            }
        }

        return $stats;
    }

    /**
     * Descritor da CronTask do GLPI.
     *
     * @return array<string, string>
     */
    public static function cronInfo(string $name): array
    {
        if ($name === 'CveScan') {
            return [
                'description' => __('Varredura periódica de vulnerabilidades CVE/OSV no inventário de softwares', 'cvescan'),
            ];
        }
        return [];
    }

    /**
     * Callback da tarefa agendada CronTask (PluginCvescanScanner::cronCveScan).
     *
     * @param mixed $task
     */
    public static function cronCveScan($task = null): int
    {
        $stats = self::runBatchScan(0, false);
        if (is_object($task) && method_exists($task, 'addVolume')) {
            $task->addVolume((int) $stats['scanned']);
        }
        return $stats['scanned'] > 0 ? 1 : 0;
    }

    /**
     * Alias para compatibilidade com chamadas diretas a cronScan.
     *
     * @param mixed $task
     */
    public static function cronScan($task = null): int
    {
        return self::cronCveScan($task);
    }

    public static function clearCache(): void
    {
        global $DB;

        if (!isset($DB) || !$DB->tableExists(self::TABLE_CACHE)) {
            return;
        }

        $it = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::TABLE_CACHE,
        ]);
        foreach ($it as $row) {
            $id = (int) ($row['id'] ?? 0);
            if ($id > 0) {
                $DB->delete(self::TABLE_CACHE, ['id' => $id]);
            }
        }
    }

    /**
     * Limpa vulnerabilidades e cache quando um Software ou SoftwareVersion é expurgado.
     */
    public static function purgeItem(CommonDBTM $item): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        $id = (int) $item->getID();
        if ($id <= 0) {
            return;
        }

        if ($item instanceof Software) {
            if ($DB->tableExists(self::TABLE_FINDINGS)) {
                $DB->delete(self::TABLE_FINDINGS, ['softwares_id' => $id]);
            }
            if ($DB->tableExists('glpi_softwareversions') && $DB->tableExists(self::TABLE_CACHE)) {
                $itVers = $DB->request([
                    'SELECT' => ['id'],
                    'FROM'   => 'glpi_softwareversions',
                    'WHERE'  => ['softwares_id' => $id],
                ]);
                foreach ($itVers as $vRow) {
                    $vid = (int) ($vRow['id'] ?? 0);
                    if ($vid > 0) {
                        $DB->delete(self::TABLE_CACHE, ['softwareversions_id' => $vid]);
                    }
                }
            }
            return;
        }

        if ($item instanceof SoftwareVersion) {
            if ($DB->tableExists(self::TABLE_FINDINGS)) {
                $DB->delete(self::TABLE_FINDINGS, ['softwareversions_id' => $id]);
            }
            if ($DB->tableExists(self::TABLE_CACHE)) {
                $DB->delete(self::TABLE_CACHE, ['softwareversions_id' => $id]);
            }
        }
    }

    public static function countFindingsForSoftware(int $softwares_id): int
    {
        global $DB;

        if ($softwares_id <= 0 || !isset($DB) || !$DB->tableExists(self::TABLE_FINDINGS)) {
            return 0;
        }

        $it = $DB->request([
            'COUNT' => 'cnt',
            'FROM'  => self::TABLE_FINDINGS,
            'WHERE' => ['softwares_id' => $softwares_id],
        ]);
        foreach ($it as $row) {
            return (int) ($row['cnt'] ?? 0);
        }
        return 0;
    }

    /**
     * Retorna as vulnerabilidades de todas as versões de um software, enriquecidas com nome da versão,
     * data da última verificação e contagem de ativos impactados.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getFindingsForSoftware(int $softwares_id): array
    {
        global $DB;

        if ($softwares_id <= 0 || !isset($DB) || !$DB->tableExists(self::TABLE_FINDINGS)) {
            return [];
        }

        $versionNames = [];
        if ($DB->tableExists('glpi_softwareversions')) {
            $itVers = $DB->request([
                'SELECT' => ['id', 'name'],
                'FROM'   => 'glpi_softwareversions',
                'WHERE'  => ['softwares_id' => $softwares_id],
            ]);
            foreach ($itVers as $vRow) {
                $vid                = (int) ($vRow['id'] ?? 0);
                $versionNames[$vid] = PluginCvescanCompat::fromCore((string) ($vRow['name'] ?? ''));
            }
        }

        $lastScannedByVer = [];
        if ($DB->tableExists(self::TABLE_CACHE) && $versionNames !== []) {
            $itCache = $DB->request([
                'FROM'  => self::TABLE_CACHE,
                'WHERE' => ['softwareversions_id' => array_keys($versionNames)],
            ]);
            foreach ($itCache as $cRow) {
                $vid                    = (int) ($cRow['softwareversions_id'] ?? 0);
                $lastScannedByVer[$vid] = (string) ($cRow['last_scanned_at'] ?? '');
            }
        }

        $installCountCache = [];
        $rows              = [];
        $itFindings        = $DB->request([
            'FROM'  => self::TABLE_FINDINGS,
            'WHERE' => ['softwares_id' => $softwares_id],
            'ORDER' => 'id DESC',
        ]);

        foreach ($itFindings as $fRow) {
            $vid = (int) ($fRow['softwareversions_id'] ?? 0);
            if (!array_key_exists($vid, $installCountCache)) {
                $installCountCache[$vid] = self::countInstallationsForVersion($vid);
            }
            $fRow['version_name']    = $versionNames[$vid] ?? ('#' . $vid);
            $fRow['last_scanned_at'] = $lastScannedByVer[$vid] ?? (string) ($fRow['detected_at'] ?? '');
            $fRow['impacted_assets'] = $installCountCache[$vid];
            $rows[]                  = $fRow;
        }

        $severityWeights = [
            'CRITICAL' => 4,
            'HIGH'     => 3,
            'MEDIUM'   => 2,
            'LOW'      => 1,
            'UNKNOWN'  => 0,
        ];

        usort($rows, function (array $a, array $b) use ($severityWeights): int {
            $wa = $severityWeights[strtoupper((string) ($a['severity'] ?? 'UNKNOWN'))] ?? 0;
            $wb = $severityWeights[strtoupper((string) ($b['severity'] ?? 'UNKNOWN'))] ?? 0;
            if ($wa !== $wb) {
                return $wb <=> $wa;
            }
            $sa = (float) ($a['cvss_score'] ?? 0.0);
            $sb = (float) ($b['cvss_score'] ?? 0.0);
            if ($sa !== $sb) {
                return $sb <=> $sa;
            }
            return strcmp((string) ($a['vuln_id'] ?? ''), (string) ($b['vuln_id'] ?? ''));
        });

        return $rows;
    }

    /**
     * Retorna resumo global de vulnerabilidades por severidade.
     *
     * @return array{CRITICAL: int, HIGH: int, MEDIUM: int, LOW: int, UNKNOWN: int, total: int}
     */
    public static function getSeveritySummary(): array
    {
        global $DB;

        $summary = [
            'CRITICAL' => 0,
            'HIGH'     => 0,
            'MEDIUM'   => 0,
            'LOW'      => 0,
            'UNKNOWN'  => 0,
            'total'    => 0,
        ];

        if (!isset($DB) || !$DB->tableExists(self::TABLE_FINDINGS)) {
            return $summary;
        }

        $it = $DB->request([
            'SELECT' => ['severity'],
            'FROM'   => self::TABLE_FINDINGS,
        ]);

        foreach ($it as $row) {
            $sev = strtoupper((string) ($row['severity'] ?? 'UNKNOWN'));
            if (!array_key_exists($sev, $summary) || $sev === 'total') {
                $sev = 'UNKNOWN';
            }
            $summary[$sev]++;
            $summary['total']++;
        }

        return $summary;
    }

    /**
     * Retorna as vulnerabilidades mais recentes para o painel administrativo.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getRecentFindings(int $limit = 50): array
    {
        global $DB;

        if ($limit <= 0 || !isset($DB) || !$DB->tableExists(self::TABLE_FINDINGS)) {
            return [];
        }

        $findings = [];
        $it       = $DB->request([
            'FROM'  => self::TABLE_FINDINGS,
            'ORDER' => 'id DESC',
            'LIMIT' => $limit,
        ]);

        $softwareIds = [];
        $versionIds  = [];
        foreach ($it as $row) {
            $findings[] = $row;
            $sid        = (int) ($row['softwares_id'] ?? 0);
            $vid        = (int) ($row['softwareversions_id'] ?? 0);
            if ($sid > 0) {
                $softwareIds[$sid] = $sid;
            }
            if ($vid > 0) {
                $versionIds[$vid] = $vid;
            }
        }

        if ($findings === []) {
            return [];
        }

        $softNames = [];
        if ($softwareIds !== [] && $DB->tableExists('glpi_softwares')) {
            $itSoft = $DB->request([
                'SELECT' => ['id', 'name'],
                'FROM'   => 'glpi_softwares',
                'WHERE'  => ['id' => array_values($softwareIds)],
            ]);
            foreach ($itSoft as $sRow) {
                $softNames[(int) ($sRow['id'] ?? 0)] = PluginCvescanCompat::fromCore((string) ($sRow['name'] ?? ''));
            }
        }

        $verNames = [];
        if ($versionIds !== [] && $DB->tableExists('glpi_softwareversions')) {
            $itVer = $DB->request([
                'SELECT' => ['id', 'name'],
                'FROM'   => 'glpi_softwareversions',
                'WHERE'  => ['id' => array_values($versionIds)],
            ]);
            foreach ($itVer as $vRow) {
                $verNames[(int) ($vRow['id'] ?? 0)] = PluginCvescanCompat::fromCore((string) ($vRow['name'] ?? ''));
            }
        }

        foreach ($findings as $idx => $row) {
            $sid = (int) ($row['softwares_id'] ?? 0);
            $vid = (int) ($row['softwareversions_id'] ?? 0);

            $findings[$idx]['software_name']   = $softNames[$sid] ?? ('#' . $sid);
            $findings[$idx]['version_name']    = $verNames[$vid] ?? ('#' . $vid);
            $findings[$idx]['impacted_assets'] = self::countInstallationsForVersion($vid);
        }

        return $findings;
    }
}

if (!class_exists('PluginCvescanScanner', false)) {
    if (PluginCvescanCompat::typedRightname()) {
        class PluginCvescanScanner extends CommonGLPI implements PluginCvescanScannerConstants
        {
            use PluginCvescanScannerBody;

            public static string $rightname = 'config';
        }
    } else {
        class PluginCvescanScanner extends CommonGLPI implements PluginCvescanScannerConstants
        {
            use PluginCvescanScannerBody;

            public static $rightname = 'config';
        }
    }
}
