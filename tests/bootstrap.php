<?php

/**
 * ------------------------------------------------------------------------
 * CVE Scan - Bootstrap de testes independentes (sem Composer)
 *
 * Simula GLPI 10 (untyped $rightname), GLPI 11 (untyped + prefixo moderno)
 * e GLPI 12 ($rightname tipado + AccessDeniedHttpException).
 *
 * Copyright (C) 2026 by G. Martins
 * ------------------------------------------------------------------------
 */

namespace Glpi\Toolbox {
    class Sanitizer
    {
        /**
         * @param mixed $value
         * @return mixed
         */
        public static function sanitize($value)
        {
            if (is_array($value)) {
                $out = [];
                foreach ($value as $k => $v) {
                    $out[$k] = self::sanitize($v);
                }
                return $out;
            }
            if (is_string($value)) {
                return addslashes(htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
            }
            return $value;
        }

        /**
         * @param mixed $value
         * @return mixed
         */
        public static function unsanitize($value)
        {
            if (is_array($value)) {
                $out = [];
                foreach ($value as $k => $v) {
                    $out[$k] = self::unsanitize($v);
                }
                return $out;
            }
            if (is_string($value)) {
                return stripslashes(htmlspecialchars_decode($value, ENT_QUOTES));
            }
            return $value;
        }

        /**
         * @param mixed $value
         * @return mixed
         */
        public static function decodeHtmlSpecialChars($value)
        {
            if (is_array($value)) {
                $out = [];
                foreach ($value as $k => $v) {
                    $out[$k] = self::decodeHtmlSpecialChars($v);
                }
                return $out;
            }
            if (is_string($value)) {
                return htmlspecialchars_decode($value, ENT_QUOTES);
            }
            return $value;
        }
    }
}

namespace Glpi\Exception\Http {
    class AccessDeniedHttpException extends \RuntimeException
    {
    }
}

namespace {
    $typedMode = in_array('--typed-rightname', $argv ?? [], true)
        || getenv('CVESCAN_TEST_TYPED') === '1';
    $glpi11Mode = in_array('--glpi11', $argv ?? [], true)
        || getenv('CVESCAN_TEST_GLPI11') === '1';

    if (!defined('TEST_TYPED_RIGHTNAME')) {
        define('TEST_TYPED_RIGHTNAME', $typedMode);
    }
    if (!defined('GLPI_ROOT')) {
        define('GLPI_ROOT', dirname(__DIR__));
    }
    if (!defined('GLPI_VERSION')) {
        if (TEST_TYPED_RIGHTNAME) {
            define('GLPI_VERSION', '12.0.0');
        } elseif ($glpi11Mode) {
            define('GLPI_VERSION', '11.0.0');
        } else {
            define('GLPI_VERSION', '10.0.18');
        }
    }
    if (!defined('READ')) {
        define('READ', 1);
    }
    if (!defined('UPDATE')) {
        define('UPDATE', 2);
    }
    if (!defined('CREATE')) {
        define('CREATE', 4);
    }
    if (!defined('PURGE')) {
        define('PURGE', 128);
    }
    if (!defined('INFO')) {
        define('INFO', 0);
    }
    if (!defined('DAY_TIMESTAMP')) {
        define('DAY_TIMESTAMP', 86400);
    }

    global $PLUGIN_HOOKS, $CFG_GLPI, $DB;
    $PLUGIN_HOOKS = [];
    $CFG_GLPI     = ['root_doc' => ''];

    class TestRuntime
    {
        /** @var bool */
        public static $isCli = false;
        /** @var int */
        public static $userId = 10;
        /** @var string */
        public static $interface = 'central';
        /** @var bool */
        public static $rightErrorCalled = false;
        /** @var array<string, int> */
        public static $rights = [
            'config'   => 3,
            'software' => 1,
        ];
        /** @var array<int, bool> */
        public static $activeEntities = [0 => true];
        /** @var array<int, string> */
        public static $messages = [];

        public static function reset(): void
        {
            self::$isCli            = false;
            self::$userId           = 10;
            self::$interface        = 'central';
            self::$rightErrorCalled = false;
            self::$rights           = ['config' => 3, 'software' => 1];
            self::$activeEntities   = [0 => true];
            self::$messages         = [];
        }
    }

    function __($str, $domain = 'glpi'): string
    {
        return (string) $str;
    }

    if (TEST_TYPED_RIGHTNAME) {
        class CommonGLPI
        {
            public static string $rightname = '';

            public static function createTabEntry($text, $nb = 0): string
            {
                return (int) $nb > 0 ? ($text . ' (' . (int) $nb . ')') : (string) $text;
            }
        }
    } else {
        class CommonGLPI
        {
            public static $rightname = '';

            public static function createTabEntry($text, $nb = 0): string
            {
                return (int) $nb > 0 ? ($text . ' (' . (int) $nb . ')') : (string) $text;
            }
        }
    }

    class CommonDBTM extends CommonGLPI
    {
        /** @var array<string, mixed> */
        public $fields = [];

        public function getID(): int
        {
            return (int) ($this->fields['id'] ?? 0);
        }

        public function getType(): string
        {
            return static::class;
        }

        public function getEntityID(): int
        {
            return (int) ($this->fields['entities_id'] ?? 0);
        }

        public function canViewItem(): bool
        {
            return true;
        }
    }

    class Software extends CommonDBTM
    {
        /** @var bool */
        public $canView = true;

        /**
         * @param array<string, mixed> $fields
         */
        public function __construct(int $id = 0, array $fields = [])
        {
            $this->fields = array_merge([
                'id'          => $id,
                'entities_id' => 0,
                'name'        => '',
                'is_deleted'  => 0,
            ], $fields);
        }

        public function getType(): string
        {
            return 'Software';
        }

        public function canViewItem(): bool
        {
            return $this->canView;
        }
    }

    class SoftwareVersion extends CommonDBTM
    {
        /**
         * @param array<string, mixed> $fields
         */
        public function __construct(int $id = 0, array $fields = [])
        {
            $this->fields = array_merge([
                'id'           => $id,
                'softwares_id' => 0,
                'entities_id'  => 0,
                'name'         => '',
            ], $fields);
        }

        public function getType(): string
        {
            return 'SoftwareVersion';
        }
    }

    class CronTask
    {
        /** @var array<string, array<string, mixed>> */
        public static $registered = [];
        /** @var int */
        public $volume = 0;

        public static function register(string $itemtype, string $name, int $frequency, array $options = []): bool
        {
            self::$registered[$itemtype . '::' . $name] = [
                'itemtype'  => $itemtype,
                'name'      => $name,
                'frequency' => $frequency,
                'options'   => $options,
            ];
            return true;
        }

        public static function unregister(string $pluginName): bool
        {
            self::$registered = [];
            return true;
        }

        public function addVolume(int $volume): void
        {
            $this->volume += $volume;
        }
    }

    class Session
    {
        /**
         * @return int|false
         */
        public static function getLoginUserID(bool $force_human = false)
        {
            return TestRuntime::$userId > 0 ? TestRuntime::$userId : false;
        }

        public static function getCurrentInterface(): string
        {
            return TestRuntime::$interface;
        }

        public static function haveRight(string $module, int $right): bool
        {
            return ((int) (TestRuntime::$rights[$module] ?? 0) & $right) === $right;
        }

        public static function checkRight(string $module, int $right): void
        {
            if (!self::haveRight($module, $right)) {
                throw new \RuntimeException("Missing right {$module}:{$right}");
            }
        }

        public static function haveAccessToEntity(int $entity_id): bool
        {
            return !empty(TestRuntime::$activeEntities[$entity_id]);
        }

        public static function addMessageAfterRedirect(string $msg, bool $check_once = false, int $message_type = INFO): void
        {
            TestRuntime::$messages[] = $msg;
        }
    }

    class Config
    {
        /** @var array<string, array<string, mixed>> */
        public static $store = [];

        public static function getConfigurationValues(string $context): array
        {
            return self::$store[$context] ?? [];
        }

        public static function setConfigurationValues(string $context, array $values): void
        {
            if (!isset(self::$store[$context])) {
                self::$store[$context] = [];
            }
            foreach ($values as $k => $v) {
                self::$store[$context][$k] = $v;
            }
        }

        public static function deleteConfigurationValues(string $context, array $keys): void
        {
            foreach ($keys as $k) {
                unset(self::$store[$context][$k]);
            }
        }
    }

    class Plugin
    {
        /** @var array<string, array<string, mixed>> */
        public static $registered = [];

        public static function registerClass(string $class, array $options = []): void
        {
            self::$registered[$class] = $options;
        }

        public static function getWebDir(string $plugin, bool $full = true): string
        {
            throw new \RuntimeException('Deprecated Plugin::getWebDir() must not be called');
        }
    }

    if (TEST_TYPED_RIGHTNAME) {
        class Html
        {
            public static function convDateTime(string $date): string
            {
                return $date;
            }

            public static function closeForm(): void
            {
                echo '</form>';
            }

            public static function header(string $title = '', string $url = '', string $sector = '', string $item = ''): void
            {
            }

            public static function footer(): void
            {
            }

            public static function back(): void
            {
            }
        }
    } else {
        class Html
        {
            public static function convDateTime(string $date): string
            {
                return $date;
            }

            public static function closeForm(): void
            {
                echo '</form>';
            }

            public static function displayRightError(): void
            {
                TestRuntime::$rightErrorCalled = true;
                throw new \RuntimeException('Html::displayRightError called');
            }

            public static function displayErrorAndDie(string $msg, bool $minimal = false): void
            {
                throw new \RuntimeException($msg);
            }

            public static function header(string $title = '', string $url = '', string $sector = '', string $item = ''): void
            {
            }

            public static function footer(): void
            {
            }

            public static function back(): void
            {
            }
        }
    }

    class DBConnection
    {
        public static function getDefaultCharset(): string
        {
            return 'utf8mb4';
        }

        public static function getDefaultCollation(): string
        {
            return 'utf8mb4_unicode_ci';
        }
    }

    class Toolbox
    {
        /**
         * @param mixed $value
         * @return mixed
         */
        public static function addslashes_deep($value)
        {
            if (is_array($value)) {
                return array_map([self::class, 'addslashes_deep'], $value);
            }
            return is_string($value) ? addslashes($value) : $value;
        }
    }

    class MockGlpiIterator implements \IteratorAggregate
    {
        /** @var array<int, array<string, mixed>> */
        private $rows;

        /**
         * @param array<int, array<string, mixed>> $rows
         */
        public function __construct(array $rows)
        {
            $this->rows = $rows;
        }

        public function getIterator(): \ArrayIterator
        {
            return new \ArrayIterator($this->rows);
        }

        public function count(): int
        {
            return count($this->rows);
        }
    }

    /**
     * Simula GLPI 10.0.0–10.0.10 onde DBmysql::doQuery() não existia (apenas query()).
     */
    class LegacyQueryOnlyDB
    {
        /** @var array<string, array<int, array<string, mixed>>> */
        public $tables = [];

        /** @var array<int, string> */
        public $queries = [];

        public function tableExists(string $table): bool
        {
            return isset($this->tables[$table]);
        }

        public function query(string $sql): bool
        {
            $this->queries[] = $sql;
            if (preg_match('/^\s*CREATE\s+TABLE\s+`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $this->tables[$m[1]] = [];
                return true;
            }
            if (preg_match('/^\s*DROP\s+TABLE(?:\s+IF\s+EXISTS)?\s+`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                unset($this->tables[$m[1]]);
                return true;
            }
            return true;
        }
    }

    class MockGlpiDB
    {
        /** @var array<string, array<int, array<string, mixed>>> */
        public $tables = [];

        /** @var array<string, int> */
        public $autoInc = [];

        /** @var array<string, array<string, bool>> */
        public $fieldsMap = [];

        public function __construct()
        {
            $this->reset();
        }

        public function reset(): void
        {
            $this->tables = [
                'glpi_softwares'              => [],
                'glpi_softwareversions'       => [],
                'glpi_items_softwareversions' => [],
            ];
            $this->autoInc = [
                'glpi_softwares'              => 1,
                'glpi_softwareversions'       => 1,
                'glpi_items_softwareversions' => 1,
            ];
            $this->fieldsMap = [
                'glpi_softwares'              => ['id' => true, 'name' => true, 'entities_id' => true, 'is_deleted' => true],
                'glpi_softwareversions'       => ['id' => true, 'softwares_id' => true, 'name' => true, 'entities_id' => true],
                'glpi_items_softwareversions' => ['id' => true, 'softwareversions_id' => true, 'items_id' => true, 'itemtype' => true, 'is_deleted' => true],
            ];
        }

        public function tableExists(string $table): bool
        {
            return isset($this->tables[$table]);
        }

        public function fieldExists(string $table, string $field): bool
        {
            return !empty($this->fieldsMap[$table][$field]);
        }

        public function doQuery(string $sql): bool
        {
            if (preg_match('/^\s*CREATE\s+TABLE\s+`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $name = $m[1];
                if (!isset($this->tables[$name])) {
                    $this->tables[$name]  = [];
                    $this->autoInc[$name] = 1;
                }
                return true;
            }
            if (preg_match('/^\s*DROP\s+TABLE(?:\s+IF\s+EXISTS)?\s+`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $name = $m[1];
                unset($this->tables[$name], $this->autoInc[$name]);
                return true;
            }
            return true;
        }

        public function escape(string $value): string
        {
            return addslashes($value);
        }

        public function insert(string $table, array $params): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }

            $row = $this->normalizeRowForStorage($params);
            if (!isset($row['id'])) {
                $nextId                = $this->autoInc[$table] ?? 1;
                $row['id']             = $nextId;
                $this->autoInc[$table] = $nextId + 1;
            } else {
                $id = (int) $row['id'];
                if (($this->autoInc[$table] ?? 1) <= $id) {
                    $this->autoInc[$table] = $id + 1;
                }
            }

            $this->tables[$table][] = $row;
            return true;
        }

        public function update(string $table, array $params, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }

            $updates = $this->normalizeRowForStorage($params);
            foreach ($this->tables[$table] as $idx => $row) {
                if ($this->matchesWhere($row, $where)) {
                    foreach ($updates as $k => $v) {
                        $this->tables[$table][$idx][$k] = $v;
                    }
                }
            }
            return true;
        }

        public function delete(string $table, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }

            $remaining = [];
            foreach ($this->tables[$table] as $row) {
                if (!$this->matchesWhere($row, $where)) {
                    $remaining[] = $row;
                }
            }
            $this->tables[$table] = $remaining;
            return true;
        }

        public function request(array $criteria): MockGlpiIterator
        {
            $fromSpec = (string) ($criteria['FROM'] ?? '');
            if (!isset($this->tables[$fromSpec])) {
                return new MockGlpiIterator([]);
            }

            $rows  = $this->tables[$fromSpec];
            $where = $criteria['WHERE'] ?? [];
            if (is_array($where) && $where !== []) {
                $filtered = [];
                foreach ($rows as $row) {
                    if ($this->matchesWhere($row, $where)) {
                        $filtered[] = $row;
                    }
                }
                $rows = $filtered;
            }

            if (isset($criteria['COUNT'])) {
                $alias = (string) $criteria['COUNT'];
                return new MockGlpiIterator([[$alias => count($rows)]]);
            }

            if (isset($criteria['ORDER'])) {
                $orders = is_array($criteria['ORDER']) ? $criteria['ORDER'] : [$criteria['ORDER']];
                usort($rows, function (array $a, array $b) use ($orders): int {
                    foreach ($orders as $orderExpr) {
                        $parts = preg_split('/\s+/', trim((string) $orderExpr));
                        $col   = $parts[0] ?? 'id';
                        $dir   = strtoupper($parts[1] ?? 'ASC');
                        $valA  = $a[$col] ?? '';
                        $valB  = $b[$col] ?? '';
                        if (is_numeric($valA) && is_numeric($valB)) {
                            $cmp = ((float) $valA <=> (float) $valB);
                        } else {
                            $cmp = strcmp((string) $valA, (string) $valB);
                        }
                        if ($cmp !== 0) {
                            return $dir === 'DESC' ? -$cmp : $cmp;
                        }
                    }
                    return 0;
                });
            }

            if (isset($criteria['SELECT']) && is_array($criteria['SELECT'])) {
                $projected = [];
                foreach ($rows as $row) {
                    $proj = [];
                    foreach ($criteria['SELECT'] as $sel) {
                        $col        = trim((string) $sel);
                        $proj[$col] = $row[$col] ?? null;
                    }
                    $projected[] = $proj;
                }
                $rows = $projected;
            }

            if (isset($criteria['LIMIT'])) {
                $rows = array_slice($rows, 0, max(0, (int) $criteria['LIMIT']));
            }

            return new MockGlpiIterator($rows);
        }

        private function normalizeRowForStorage(array $values): array
        {
            if (version_compare(GLPI_VERSION, '11.0.0-dev', '<')) {
                foreach ($values as $k => $v) {
                    if (is_string($v)) {
                        $values[$k] = stripslashes($v);
                    }
                }
            }
            return $values;
        }

        private function matchesWhere(array $row, array $where): bool
        {
            foreach ($where as $k => $expected) {
                $actual = $row[$k] ?? null;
                if (is_array($expected)) {
                    $found = false;
                    foreach ($expected as $candidate) {
                        if ((string) $actual === (string) $candidate) {
                            $found = true;
                            break;
                        }
                    }
                    if (!$found) {
                        return false;
                    }
                } else {
                    if ((string) $actual !== (string) $expected) {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    $DB = new MockGlpiDB();

    require_once __DIR__ . '/../cvescan/setup.php';
    require_once __DIR__ . '/../cvescan/hook.php';
}
