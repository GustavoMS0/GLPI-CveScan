<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Suíte de testes automatizados (PHP 7.4+)
 *
 * Executa todas as asserções simulando GLPI 10 (untyped $rightname), GLPI 11
 * (untyped + prefixo de assets moderno) e GLPI 12 ($rightname tipado).
 *
 * Copyright (C) 2026 by G. Martins
 * ------------------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

function assertSameValue($expected, $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        $label = $message !== '' ? $message . ': ' : '';
        throw new RuntimeException(sprintf(
            '%sExpected %s, got %s',
            $label,
            var_export($expected, true),
            var_export($actual, true)
        ));
    }
}

function assertTrueValue(bool $condition, string $message = ''): void
{
    if (!$condition) {
        throw new RuntimeException($message !== '' ? $message : 'Expected true, got false');
    }
}

function assertFalseValue(bool $condition, string $message = ''): void
{
    if ($condition) {
        throw new RuntimeException($message !== '' ? $message : 'Expected false, got true');
    }
}

function assertStringContains(string $needle, string $haystack, string $message = ''): void
{
    if (strpos($haystack, $needle) === false) {
        $label = $message !== '' ? $message . ': ' : '';
        throw new RuntimeException(sprintf('%sExpected string to contain %s', $label, var_export($needle, true)));
    }
}

function assertStringNotContains(string $needle, string $haystack, string $message = ''): void
{
    if (strpos($haystack, $needle) !== false) {
        $label = $message !== '' ? $message . ': ' : '';
        throw new RuntimeException(sprintf('%sExpected string NOT to contain %s', $label, var_export($needle, true)));
    }
}

function resetFixture(): void
{
    global $DB, $PLUGIN_HOOKS, $CFG_GLPI;

    $PLUGIN_HOOKS         = [];
    $CFG_GLPI             = ['root_doc' => ''];
    Config::$store        = [];
    Plugin::$registered   = [];
    CronTask::$registered = [];

    TestRuntime::reset();
    $DB->reset();

    plugin_init_cvescan();
    plugin_cvescan_install();
    PluginCvescanScanner::resetRuntimeState();
}

function test_plugin_manifest_and_hooks(): void
{
    global $PLUGIN_HOOKS;

    resetFixture();

    $info = plugin_version_cvescan();
    assertSameValue('CVE Scan', $info['name'], 'Plugin name');
    assertSameValue('1.0.0', $info['version'], 'Version');
    assertSameValue('G. Martins', $info['author'], 'Author');
    assertSameValue('GPLv3+', $info['license'], 'License');
    assertSameValue('10.0.0', $info['requirements']['glpi']['min'], 'Min GLPI');
    assertSameValue('12.0.99', $info['requirements']['glpi']['max'], 'Max GLPI');
    assertSameValue('7.4', $info['requirements']['php']['min'], 'Min PHP');
    assertTrueValue(plugin_cvescan_check_prerequisites(), 'Prerequisites check');
    assertTrueValue(plugin_cvescan_check_config(), 'Config check');

    assertSameValue(true, $PLUGIN_HOOKS['csrf_compliant']['cvescan'] ?? null, 'CSRF compliant');
    assertSameValue('front/config.form.php', $PLUGIN_HOOKS['config_page']['cvescan'] ?? null, 'Config page');

    $isModern    = version_compare(GLPI_VERSION, '11.0.0-dev', '>=');
    $expectedCss = $isModern ? ['css/cvescan.css'] : ['public/css/cvescan.css'];
    assertSameValue($expectedCss, $PLUGIN_HOOKS['add_css']['cvescan'] ?? null, 'CSS hook');

    assertSameValue(['addtabon' => ['Software']], Plugin::$registered['PluginCvescanTab'] ?? null, 'Software tab registration');

    assertSameValue(
        [
            'Software'        => [PluginCvescanScanner::class, 'purgeItem'],
            'SoftwareVersion' => [PluginCvescanScanner::class, 'purgeItem'],
        ],
        $PLUGIN_HOOKS['item_purge']['cvescan'] ?? null,
        'item_purge registration'
    );

    assertTrueValue(isset(CronTask::$registered['PluginCvescanScanner::CveScan']), 'CronTask CveScan registered on install');
}

function test_rightname_typing_matches_glpi_core(): void
{
    resetFixture();

    $expectedTyped = TEST_TYPED_RIGHTNAME;
    assertSameValue($expectedTyped, PluginCvescanCompat::typedRightname(), 'typedRightname detection');

    $refConfig  = new ReflectionProperty(PluginCvescanConfig::class, 'rightname');
    $refScanner = new ReflectionProperty(PluginCvescanScanner::class, 'rightname');
    $refTab     = new ReflectionProperty(PluginCvescanTab::class, 'rightname');

    assertSameValue($expectedTyped, $refConfig->hasType(), 'Config::$rightname type');
    assertSameValue($expectedTyped, $refScanner->hasType(), 'Scanner::$rightname type');
    assertSameValue($expectedTyped, $refTab->hasType(), 'Tab::$rightname type');

    assertSameValue('config', PluginCvescanConfig::$rightname, 'Config rightname');
    assertSameValue('config', PluginCvescanScanner::$rightname, 'Scanner rightname');
    assertSameValue('software', PluginCvescanTab::$rightname, 'Tab rightname');
}

function test_compat_helpers_and_sanitization(): void
{
    global $CFG_GLPI;

    resetFixture();

    $isModern      = version_compare(GLPI_VERSION, '11.0.0-dev', '>=');
    $expectedMajor = TEST_TYPED_RIGHTNAME ? 12 : ($isModern ? 11 : 10);
    assertSameValue($expectedMajor, PluginCvescanCompat::glpiMajor(), 'glpiMajor');

    assertSameValue('/plugins/cvescan', PluginCvescanCompat::webPath(), 'webPath default');
    $CFG_GLPI['root_doc'] = '/glpi';
    assertSameValue('/glpi/plugins/cvescan', PluginCvescanCompat::webPath(), 'webPath with root_doc');
    $CFG_GLPI['root_doc'] = '';

    $expectedAsset = $isModern ? 'css/cvescan.css' : 'public/css/cvescan.css';
    assertSameValue($expectedAsset, PluginCvescanCompat::assetPath('css/cvescan.css'), 'assetPath');

    if ($isModern) {
        assertSameValue("C:\\Program Files\\Vendor & <App>", PluginCvescanCompat::fromCore("C:\\Program Files\\Vendor & <App>"), 'GLPI 11+ fromCore');
        $dbVals = PluginCvescanCompat::dbValues(['summary' => "O'Brien"]);
        assertSameValue("O'Brien", $dbVals['summary'], 'GLPI 11+ dbValues');
    } else {
        assertSameValue(
            "C:\\Program Files\\Vendor & O'Brien <App>",
            PluginCvescanCompat::fromCore("C:\\Program Files\\Vendor &amp; O&#039;Brien &lt;App&gt;"),
            'GLPI 10 fromCore must preserve literal backslash'
        );
        $dbVals = PluginCvescanCompat::dbValues(['summary' => "O'Brien"]);
        assertSameValue("O\\'Brien", $dbVals['summary'], 'GLPI 10 dbValues');
    }
}

function test_execddl_falls_back_to_query_on_glpi_10_0_5(): void
{
    global $DB;

    resetFixture();
    $origDb = $DB;

    try {
        $legacyDb = new LegacyQueryOnlyDB();
        assertFalseValue(method_exists($legacyDb, 'doQuery'), 'LegacyQueryOnlyDB must not define doQuery()');

        $DB = $legacyDb;
        PluginCvescanScanner::installSchema();

        assertTrueValue($legacyDb->tableExists(PluginCvescanScanner::TABLE_FINDINGS), 'Findings table created via query()');
        assertTrueValue($legacyDb->tableExists(PluginCvescanScanner::TABLE_CACHE), 'Cache table created via query()');
        assertSameValue(2, count($legacyDb->queries), 'Expected 2 CREATE TABLE queries');

        PluginCvescanScanner::uninstallSchema();
        assertFalseValue($legacyDb->tableExists(PluginCvescanScanner::TABLE_FINDINGS), 'Findings table dropped via query()');
        assertFalseValue($legacyDb->tableExists(PluginCvescanScanner::TABLE_CACHE), 'Cache table dropped via query()');
        assertSameValue(4, count($legacyDb->queries), 'Expected 4 total DDL queries');
    } finally {
        $DB = $origDb;
    }
}

function test_deny_access_behavior(): void
{
    resetFixture();

    if (TEST_TYPED_RIGHTNAME) {
        $threwAccessDenied = false;
        try {
            PluginCvescanCompat::denyAccess('Access denied');
        } catch (\Glpi\Exception\Http\AccessDeniedHttpException $e) {
            $threwAccessDenied = true;
        }
        assertTrueValue($threwAccessDenied, 'GLPI 12+ must throw AccessDeniedHttpException');
    } else {
        $threwRightError = false;
        try {
            PluginCvescanCompat::denyAccess('Access denied');
        } catch (RuntimeException $e) {
            $threwRightError = TestRuntime::$rightErrorCalled;
        }
        assertTrueValue($threwRightError, 'GLPI 10/11 must invoke Html::displayRightError()');
    }
}

function test_package_and_version_normalization(): void
{
    resetFixture();

    assertSameValue(
        'mozilla firefox',
        PluginCvescanScanner::normalizePackageName('Mozilla Firefox (x64 en-US)', true),
        'Strip (x64 en-US)'
    );
    assertSameValue(
        'openssl',
        PluginCvescanScanner::normalizePackageName('OpenSSL (64-bit)', true),
        'Strip (64-bit)'
    );
    assertSameValue(
        '7-zip',
        PluginCvescanScanner::normalizePackageName('7-Zip x64', true),
        'Strip trailing x64'
    );
    assertSameValue(
        'openssl (64-bit)',
        PluginCvescanScanner::normalizePackageName('OpenSSL (64-bit)', false),
        'Keep arch suffix when stripArch=false'
    );

    assertSameValue(
        '1.20.1',
        PluginCvescanScanner::normalizeVersion('v1.20.1-1ubuntu2.1 (64-bit)', true),
        'Strip v prefix, distro revision, and (64-bit)'
    );
    assertSameValue(
        '3.0.12',
        PluginCvescanScanner::normalizeVersion('3.0.12+deb12u1', true),
        'Strip +deb12u1 revision'
    );
    assertSameValue(
        '1.20.1-1ubuntu2.1',
        PluginCvescanScanner::normalizeVersion('v1.20.1-1ubuntu2.1 (64-bit)', false),
        'Keep distro revision when stripRevision=false'
    );
}

function test_osv_parsing_cvss_classification_and_url_sanitization(): void
{
    resetFixture();

    assertSameValue(null, PluginCvescanScanner::parseOsvResponse('not-valid-json{{{'), 'Malformed JSON must return null');
    assertSameValue([], PluginCvescanScanner::parseOsvResponse('{}'), 'Empty OSV object must return empty array');

    $osvPayload = (string) json_encode([
        'vulns' => [
            [
                'id'               => 'GHSA-xxxx-yyyy-zzzz',
                'aliases'          => ['OSV-2026-111', 'cve-2026-10001'],
                'summary'          => 'Remote code execution in HTTP parser',
                'database_specific' => [
                    'cvss_score' => 9.8,
                ],
                'affected'         => [
                    [
                        'ranges' => [
                            [
                                'type'   => 'ECOSYSTEM',
                                'events' => [
                                    ['introduced' => '0'],
                                    ['fixed'      => '2.4.60'],
                                ],
                            ],
                        ],
                    ],
                ],
                'references'       => [
                    ['type' => 'ADVISORY', 'url' => 'javascript:alert(1)'],
                    ['type' => 'ADVISORY', 'url' => 'http://insecure.example.com/advisory'],
                    ['type' => 'ADVISORY', 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2026-10001'],
                ],
            ],
            [
                'id'       => 'GHSA-aaaa-bbbb-cccc',
                'details'  => "Denial of service\nwhen parsing headers.",
                'severity' => [
                    ['type' => 'CVSS_V3', 'score' => '7.5'],
                ],
                'references' => [
                    ['type' => 'WEB', 'url' => 'data:text/html,<script>alert(1)</script>'],
                    ['type' => 'WEB', 'url' => 'http://only-http.example.org'],
                ],
            ],
            [
                'id'                => 'CVE-2026-20002',
                'summary'           => 'Information disclosure',
                'database_specific' => [
                    'severity' => 'MODERATE',
                ],
            ],
            [
                'id'       => 'CVE-2026-30003',
                'summary'  => 'Minor timing leak',
                'severity' => [
                    ['type' => 'CVSS_V3', 'score' => '3.1'],
                ],
            ],
        ],
    ]);

    $parsed = PluginCvescanScanner::parseOsvResponse($osvPayload);
    assertTrueValue(is_array($parsed), 'Parsed result must be array');
    assertSameValue(4, count($parsed), 'Expected 4 parsed vulnerabilities');

    // 1: CVE alias prioritized, CRITICAL 9.8, fixed 2.4.60, javascript:/http: rejected in favor of https:
    assertSameValue('CVE-2026-10001', $parsed[0]['vuln_id'], 'CVE alias prioritized over GHSA');
    assertSameValue('CRITICAL', $parsed[0]['severity'], 'CVSS 9.8 -> CRITICAL');
    assertSameValue(9.8, $parsed[0]['cvss_score'], 'CVSS 9.8 score');
    assertSameValue('2.4.60', $parsed[0]['fixed_version'], 'Fixed version extracted');
    assertSameValue('https://nvd.nist.gov/vuln/detail/CVE-2026-10001', $parsed[0]['reference_url'], 'Only https:// URL accepted');

    // 2: GHSA id fallback, HIGH 7.5, fallback safe https://osv.dev URL when all references were unsafe
    assertSameValue('GHSA-aaaa-bbbb-cccc', $parsed[1]['vuln_id'], 'GHSA id fallback');
    assertSameValue('HIGH', $parsed[1]['severity'], 'CVSS 7.5 -> HIGH');
    assertSameValue(7.5, $parsed[1]['cvss_score'], 'CVSS 7.5 score');
    assertSameValue('Denial of service when parsing headers.', $parsed[1]['summary'], 'Details normalized to single-line summary');
    assertSameValue('https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc', $parsed[1]['reference_url'], 'Fallback safe OSV https URL');

    // 3: Textual MODERATE -> MEDIUM, fallback NVD https URL
    assertSameValue('MEDIUM', $parsed[2]['severity'], 'MODERATE mapped to MEDIUM');
    assertSameValue(null, $parsed[2]['cvss_score'], 'Null numeric score when only textual severity present');
    assertSameValue('https://nvd.nist.gov/vuln/detail/CVE-2026-20002', $parsed[2]['reference_url'], 'Fallback NVD https URL');

    // 4: CVSS 3.1 -> LOW
    assertSameValue('LOW', $parsed[3]['severity'], 'CVSS 3.1 -> LOW');
    assertSameValue(3.1, $parsed[3]['cvss_score'], 'CVSS 3.1 score');
}

function test_cache_ttl_skip_vs_force_rescan_and_cron_batch(): void
{
    global $DB;

    resetFixture();

    $DB->insert('glpi_softwares', [
        'id'          => 10,
        'name'        => 'OpenSSL (64-bit)',
        'entities_id' => 0,
        'is_deleted'  => 0,
    ]);
    $DB->insert('glpi_softwareversions', [
        'id'           => 100,
        'softwares_id' => 10,
        'name'         => '3.0.11',
        'entities_id'  => 0,
    ]);
    $DB->insert('glpi_items_softwareversions', [
        'id'                  => 1,
        'softwareversions_id' => 100,
        'items_id'            => 500,
        'itemtype'            => 'Computer',
        'is_deleted'          => 0,
    ]);
    $DB->insert('glpi_items_softwareversions', [
        'id'                  => 2,
        'softwareversions_id' => 100,
        'items_id'            => 501,
        'itemtype'            => 'Computer',
        'is_deleted'          => 1,
    ]);

    $httpCalls = 0;
    PluginCvescanScanner::setHttpTransport(function (string $url, string $payload, int $timeout) use (&$httpCalls): array {
        $httpCalls++;
        assertSameValue('https://api.osv.dev/v1/query', $url, 'Immutable OSV endpoint');
        $req = json_decode($payload, true);
        assertSameValue('openssl', $req['package']['name'] ?? '', 'Normalized package name sent');
        assertSameValue('3.0.11', $req['version'] ?? '', 'Normalized version sent');

        return [
            'status' => 200,
            'body'   => (string) json_encode([
                'vulns' => [
                    [
                        'id'       => 'CVE-2026-9999',
                        'summary'  => 'Buffer overflow in X.509 verification',
                        'severity' => [['type' => 'CVSS_V3', 'score' => '8.2']],
                        'affected' => [['ranges' => [['events' => [['fixed' => '3.0.12']]]]]],
                    ],
                ],
            ]),
        ];
    });

    PluginCvescanScanner::setNowForTest('2026-11-16 08:00:00');
    $res1 = PluginCvescanScanner::scanSoftwareVersion(100, false);
    assertSameValue('ok', $res1['status'], 'First scan status');
    assertSameValue(1, $res1['findings_count'], 'First scan findings_count');
    assertFalseValue($res1['skipped'], 'First scan not skipped');
    assertSameValue(1, $httpCalls, 'HTTP transport called once');

    // Segunda chamada 2 horas depois (dentro do TTL de 24h) deve usar cache sem chamar HTTP
    PluginCvescanScanner::setNowForTest('2026-11-16 10:00:00');
    $resCached = PluginCvescanScanner::scanSoftwareVersion(100, false);
    assertSameValue('cached', $resCached['status'], 'Second scan within TTL must return cached');
    assertTrueValue($resCached['skipped'], 'Second scan within TTL must mark skipped=true');
    assertSameValue(1, $httpCalls, 'HTTP transport must NOT be called when cache is fresh');

    // Chamada com $force = true deve ignorar cache mesmo dentro do TTL
    $resForced = PluginCvescanScanner::scanSoftwareVersion(100, true);
    assertSameValue('ok', $resForced['status'], 'Force scan status');
    assertFalseValue($resForced['skipped'], 'Force scan must not skip');
    assertSameValue(2, $httpCalls, 'HTTP transport called on force rescan');

    // Chamada via cronCveScan após expirar as 24h de cache (no dia seguinte)
    PluginCvescanScanner::setNowForTest('2026-11-17 11:00:00');
    $cronTask = new CronTask();
    $cronRet  = PluginCvescanScanner::cronCveScan($cronTask);
    assertSameValue(1, $cronRet, 'cronCveScan must return 1 when versions were scanned');
    assertSameValue(1, $cronTask->volume, 'CronTask volume must record 1 scanned version');
    assertSameValue(3, $httpCalls, 'HTTP transport called by cron after cache expiry');

    // Verifica contagem de ativos impactados (ignora is_deleted = 1)
    $findings = PluginCvescanScanner::getFindingsForSoftware(10);
    assertSameValue(1, count($findings), '1 finding stored for software 10');
    assertSameValue(1, $findings[0]['impacted_assets'], 'Only non-deleted installation counted');
}

function test_software_tab_authorization_entity_isolation_and_xss_escaping(): void
{
    global $DB;

    resetFixture();

    $isModern = version_compare(GLPI_VERSION, '11.0.0-dev', '>=');
    $rawVer   = $isModern ? '1.0 <script>alert(1)</script>' : '1.0 &lt;script&gt;alert(1)&lt;/script&gt;';

    $DB->insert('glpi_softwares', [
        'id'          => 25,
        'name'        => 'Apache HTTP Server',
        'entities_id' => 5,
        'is_deleted'  => 0,
    ]);
    $DB->insert('glpi_softwareversions', [
        'id'           => 250,
        'softwares_id' => 25,
        'name'         => $rawVer,
        'entities_id'  => 5,
    ]);

    $row = PluginCvescanCompat::dbValues([
        'softwares_id'        => 25,
        'softwareversions_id' => 250,
        'vuln_id'             => 'CVE-2026-5555',
        'severity'            => 'CRITICAL',
        'cvss_score'          => 9.8,
        'summary'             => "RCE via <img src=x onerror=alert(1)> & O'Brien",
        'fixed_version'       => '2.4.62',
        'reference_url'       => 'javascript:alert(9)',
        'detected_at'         => '2026-11-16 12:00:00',
    ]);
    $DB->insert(PluginCvescanScanner::TABLE_FINDINGS, $row);

    $tab      = new PluginCvescanTab();
    $software = new Software(25, ['entities_id' => 5]);

    // 1. Entidade não autorizada (usuário só tem acesso à entidade 0)
    TestRuntime::$activeEntities = [0 => true];
    assertSameValue('', $tab->getTabNameForItem($software), 'Tab hidden when user lacks access to software entity');
    ob_start();
    $renderedUnauthEntity = PluginCvescanTab::displayTabContentForItem($software);
    ob_end_clean();
    assertFalseValue($renderedUnauthEntity, 'Tab content blocked for unauthorized entity');

    // 2. Autoriza entidade 5, mas canViewItem() = false
    TestRuntime::$activeEntities = [0 => true, 5 => true];
    $software->canView           = false;
    assertSameValue('', $tab->getTabNameForItem($software), 'Tab hidden when canViewItem() is false');
    $software->canView = true;

    // 3. Usuário autenticado com acesso à entidade 5: exibe aba e escapa XSS + bloqueia javascript: URL
    assertSameValue('CVEs (1)', $tab->getTabNameForItem($software), 'Tab badge shows CVEs (1)');

    ob_start();
    $rendered = PluginCvescanTab::displayTabContentForItem($software);
    $html     = (string) ob_get_clean();

    assertTrueValue($rendered, 'Tab content rendered for authorized user');
    assertStringContains('CVE-2026-5555', $html, 'CVE ID rendered');
    assertStringContains('CRITICAL (9.8)', $html, 'Severity and CVSS rendered');
    assertStringContains('2.4.62', $html, 'Fixed version rendered');
    assertStringNotContains('<script>', $html, 'Raw script tag from version name must be escaped');
    assertStringNotContains('<img src=x', $html, 'Raw img tag from summary must be escaped');
    assertStringNotContains('javascript:alert', $html, 'Unsafe javascript: reference URL must be stripped');
}

function test_item_purge_cleans_up_software_and_versions(): void
{
    global $DB;

    resetFixture();

    $DB->insert('glpi_softwares', ['id' => 30, 'name' => 'Nginx', 'is_deleted' => 0]);
    $DB->insert('glpi_softwareversions', ['id' => 301, 'softwares_id' => 30, 'name' => '1.24.0']);
    $DB->insert('glpi_softwareversions', ['id' => 302, 'softwares_id' => 30, 'name' => '1.25.0']);

    $DB->insert(PluginCvescanScanner::TABLE_FINDINGS, [
        'softwares_id'        => 30,
        'softwareversions_id' => 301,
        'vuln_id'             => 'CVE-2026-301',
        'severity'            => 'HIGH',
    ]);
    $DB->insert(PluginCvescanScanner::TABLE_FINDINGS, [
        'softwares_id'        => 30,
        'softwareversions_id' => 302,
        'vuln_id'             => 'CVE-2026-302',
        'severity'            => 'MEDIUM',
    ]);
    $DB->insert(PluginCvescanScanner::TABLE_CACHE, ['softwareversions_id' => 301, 'status' => 'ok']);
    $DB->insert(PluginCvescanScanner::TABLE_CACHE, ['softwareversions_id' => 302, 'status' => 'ok']);

    assertSameValue(2, PluginCvescanScanner::countFindingsForSoftware(30), '2 findings before version purge');

    // Expurga apenas a versão 301
    PluginCvescanScanner::purgeItem(new SoftwareVersion(301, ['softwares_id' => 30]));
    assertSameValue(1, PluginCvescanScanner::countFindingsForSoftware(30), '1 finding remains after purging version 301');

    // Expurga o software 30 inteiro
    PluginCvescanScanner::purgeItem(new Software(30));
    assertSameValue(0, PluginCvescanScanner::countFindingsForSoftware(30), '0 findings after purging software 30');
}

function test_config_form_get_and_post(): void
{
    resetFixture();

    $origServer = $_SERVER;
    $origPost   = $_POST;

    try {
        $_SERVER = ['REQUEST_METHOD' => 'GET'];
        $_POST   = [];

        ob_start();
        include GLPI_ROOT . '/cvescan/front/config.form.php';
        $html = (string) ob_get_clean();

        assertStringContains('name="batch_size"', $html, 'batch_size input rendered');
        assertStringContains('name="cache_hours"', $html, 'cache_hours input rendered');
        assertStringContains('name="timeout_seconds"', $html, 'timeout_seconds input rendered');

        $_SERVER = [
            'REQUEST_METHOD'      => 'POST',
            'HTTP_SEC_FETCH_SITE' => 'same-origin',
        ];
        $_POST = [
            'update'            => '1',
            'batch_size'        => '50',
            'cache_hours'       => '12',
            'timeout_seconds'   => '15',
            'strip_arch_suffix' => '0',
        ];

        ob_start();
        include GLPI_ROOT . '/cvescan/front/config.form.php';
        ob_end_clean();

        $saved = PluginCvescanConfig::getConfig();
        assertSameValue(50, $saved['batch_size'], 'Updated batch_size');
        assertSameValue(12, $saved['cache_hours'], 'Updated cache_hours');
        assertSameValue(15, $saved['timeout_seconds'], 'Updated timeout_seconds');
        assertSameValue(0, $saved['strip_arch_suffix'], 'Updated strip_arch_suffix');

        // Cross-site POST deve ser bloqueado
        $_SERVER = [
            'REQUEST_METHOD'      => 'POST',
            'HTTP_SEC_FETCH_SITE' => 'cross-site',
        ];
        $blocked = false;
        try {
            include GLPI_ROOT . '/cvescan/front/config.form.php';
        } catch (RuntimeException $e) {
            $blocked = true;
        }
        assertTrueValue($blocked, 'Cross-site POST must be rejected');
    } finally {
        $_SERVER = $origServer;
        $_POST   = $origPost;
    }
}

$tests = [
    'test_plugin_manifest_and_hooks',
    'test_rightname_typing_matches_glpi_core',
    'test_compat_helpers_and_sanitization',
    'test_execddl_falls_back_to_query_on_glpi_10_0_5',
    'test_deny_access_behavior',
    'test_package_and_version_normalization',
    'test_osv_parsing_cvss_classification_and_url_sanitization',
    'test_cache_ttl_skip_vs_force_rescan_and_cron_batch',
    'test_software_tab_authorization_entity_isolation_and_xss_escaping',
    'test_item_purge_cleans_up_software_and_versions',
    'test_config_form_get_and_post',
];

$isGlpi11Flag = in_array('--glpi11', $argv ?? [], true) || getenv('CVESCAN_TEST_GLPI11') === '1';
if (TEST_TYPED_RIGHTNAME) {
    $modeLabel = 'GLPI 12.0.0 (typed $rightname)';
} elseif ($isGlpi11Flag) {
    $modeLabel = 'GLPI 11.0.0 (untyped $rightname, modern assets/webPath)';
} else {
    $modeLabel = 'GLPI 10.0.18 (untyped $rightname)';
}

echo "Running CVE Scan tests in {$modeLabel}...\n";

foreach ($tests as $testFn) {
    $testFn();
    echo "  [PASS] {$testFn}\n";
}

echo count($tests) . " tests passed in {$modeLabel}.\n";

if (!TEST_TYPED_RIGHTNAME && !$isGlpi11Flag) {
    foreach (['--glpi11', '--typed-rightname'] as $flag) {
        $cmd    = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' ' . $flag . ' 2>&1';
        $output = [];
        $code   = 0;
        exec($cmd, $output, $code);
        foreach ($output as $line) {
            echo $line . "\n";
        }
        if ($code !== 0) {
            exit($code);
        }
    }
}
