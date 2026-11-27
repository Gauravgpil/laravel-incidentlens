<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;

final class ProjectInspector
{
    public function __construct(
        private readonly Application $app,
        private readonly ConfigRepository $config,
    ) {
    }

    /**
     * Collects non-secret Laravel project metadata for the Rust diagnostic engine.
     * Secret values (app.key, database passwords, API tokens) are never exported.
     *
     * @return array<string, mixed>
     */
    public function inspect(): array
    {
        $basePath = $this->app->basePath();
        $logPaths = $this->discoverLogPaths($basePath);

        return [
            'root' => $basePath,
            'name' => $this->stringOrNull($this->config->get('app.name')),
            'laravel_version' => $this->app->version(),
            'php_version' => PHP_VERSION,
            'environment' => $this->app->environment(),
            'debug' => (bool) $this->config->get('app.debug', false),
            'drivers' => [
                'cache' => $this->stringOrNull($this->config->get('cache.default')),
                'queue' => $this->stringOrNull($this->config->get('queue.default')),
                'database' => $this->stringOrNull($this->config->get('database.default')),
                'session' => $this->stringOrNull($this->config->get('session.driver')),
                'log' => $this->stringOrNull($this->config->get('logging.default')),
            ],
            'log_paths' => $logPaths,
            'config_flags' => [
                'app_key_set' => ! empty($this->config->get('app.key')),
                'app_debug' => (bool) $this->config->get('app.debug', false),
                'runtime_collector_enabled' => (bool) $this->config->get('incidentlens.runtime.enabled', false),
            ],
        ];
    }

    /**
     * @return list<string>
     */
    private function discoverLogPaths(string $basePath): array
    {
        $configured = $this->config->get('incidentlens.logs.paths', []);
        if (is_array($configured) && $configured !== []) {
            $valid = [];
            foreach ($configured as $path) {
                if (is_string($path) && is_file($path)) {
                    $valid[] = $path;
                }
            }
            return $valid;
        }

        $logsDir = $basePath . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'logs';
        if (! is_dir($logsDir)) {
            return [];
        }

        $files = glob($logsDir . DIRECTORY_SEPARATOR . '*.log');
        if ($files === false) {
            return [];
        }

        return array_values(array_filter($files, 'is_file'));
    }

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
