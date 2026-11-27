<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Tests;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;

final class IncidentLensPackageTest extends TestCase
{
    public function test_config_is_merged_and_runtime_collector_is_disabled_by_default(): void
    {
        $this->assertTrue((bool) config('incidentlens.enabled'));
        $this->assertFalse((bool) config('incidentlens.runtime.enabled'));
        $this->assertFalse((bool) config('incidentlens.privacy.collect_request_body'));
        $this->assertFalse((bool) config('incidentlens.privacy.collect_query_bindings'));
    }

    public function test_project_inspector_does_not_expose_secret_values(): void
    {
        config()->set('app.key', 'base64:SUPER_SECRET_TEST_KEY_VALUE');
        config()->set('database.connections.mysql.password', 'SUPER_SECRET_DB_PASS');

        /** @var ProjectInspector $inspector */
        $inspector = $this->app->make(ProjectInspector::class);
        $metadata = $inspector->inspect();

        $encoded = json_encode($metadata, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString('SUPER_SECRET_TEST_KEY_VALUE', $encoded);
        $this->assertStringNotContainsString('SUPER_SECRET_DB_PASS', $encoded);
        $this->assertTrue($metadata['config_flags']['app_key_set']);
    }

    public function test_engine_client_throws_helpful_error_when_binary_is_missing(): void
    {
        $client = new EngineClient('/nonexistent/path/to/incidentlens', 10, $this->app->basePath());

        $this->expectException(EngineException::class);
        $this->expectExceptionMessage('IncidentLens Rust engine binary not found');
        $client->resolveBinary();
    }

    public function test_artisan_commands_are_registered(): void
    {
        $commands = array_keys($this->app->make('Illuminate\Contracts\Console\Kernel')->all());
        $this->assertContains('incidentlens:audit', $commands);
        $this->assertContains('incidentlens:doctor', $commands);
        $this->assertContains('incidentlens:status', $commands);
        $this->assertContains('incidentlens:scan', $commands);
    }

    public function test_engine_client_communicates_with_rust_binary_over_protocol_v1(): void
    {
        $binary = dirname(__DIR__, 3) . '/target/debug/incidentlens';
        if (! is_file($binary)) {
            $this->markTestSkipped('Rust binary not built at ' . $binary);
        }

        $fixtureRoot = dirname(__DIR__, 3) . '/fixtures/sample-laravel-app';
        $client = new EngineClient($binary, 15, $fixtureRoot);

        $protocol = $client->protocolInfo();
        $this->assertSame('1.0', $protocol['protocol_version']);

        $result = $client->scan([
            'root' => $fixtureRoot,
            'name' => 'SampleApp',
            'laravel_version' => '12.0.0',
            'php_version' => PHP_VERSION,
            'environment' => 'production',
            'debug' => true,
            'drivers' => [
                'cache' => 'redis',
                'queue' => 'sync',
                'database' => 'mysql',
                'session' => 'redis',
                'log' => 'stack',
            ],
            'log_paths' => [$fixtureRoot . '/storage/logs/laravel.log'],
            'config_flags' => ['app_key_set' => true, 'app_debug' => true],
        ], [], true);

        $this->assertSame(1, $result['exit_code']);
        $this->assertSame('1.0', $result['response']['protocol_version']);
        $this->assertSame('ok', $result['response']['status']);
        $this->assertNotEmpty($result['response']['findings']);
    }

    public function test_runtime_collector_normalizes_sql_without_collecting_bindings(): void
    {
        $sql = \Gaurav\IncidentLens\Collectors\RuntimeCollector::normalizeSql(
            "select * from users where email = 'secret@example.com' and id = 42"
        );
        $this->assertSame('select * from users where email = ? and id = ?', $sql);
        $this->assertStringNotContainsString('secret@example.com', $sql);
        $this->assertStringNotContainsString('42', $sql);
    }

    public function test_runtime_collector_buffers_and_flushes_jsonl_safely(): void
    {
        $tmpDir = sys_get_temp_dir() . '/incidentlens_test_' . bin2hex(random_bytes(4));
        $collector = new \Gaurav\IncidentLens\Collectors\RuntimeCollector($tmpDir, 1.0, false, true, false);
        $collector->appendEvent(['type' => 'cache', 'timestamp' => gmdate('c'), 'hit' => true, 'store' => 'redis']);
        $collector->resetRequestState();

        $jsonl = $tmpDir . '/runtime.jsonl';
        $this->assertFileExists($jsonl);
        $content = (string) file_get_contents($jsonl);
        $this->assertStringContainsString('"type":"cache"', $content);

        @unlink($jsonl);
        @rmdir($tmpDir);
    }
}
