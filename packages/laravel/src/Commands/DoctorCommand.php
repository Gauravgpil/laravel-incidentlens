<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Console\Command;

final class DoctorCommand extends Command
{
    protected $signature = 'incidentlens:doctor {--json : Output as JSON}';
    protected $description = 'Verify IncidentLens Rust engine, protocol compatibility, and Laravel project readiness';

    public function handle(EngineClient $engine, ProjectInspector $inspector): int
    {
        $project = $inspector->inspect();

        try {
            $binary = $engine->resolveBinary();
            $protocol = $engine->protocolInfo();
        } catch (EngineException $e) {
            if ($this->option('json')) {
                $this->line((string) json_encode([
                    'status' => 'error',
                    'error' => $e->getMessage(),
                ], JSON_PRETTY_PRINT));
            } else {
                $this->error($e->getMessage());
            }
            return self::FAILURE;
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'status' => 'ok',
                'binary' => $binary,
                'protocol' => $protocol,
                'project' => $project,
            ], JSON_PRETTY_PRINT));
            return self::SUCCESS;
        }

        $this->info('IncidentLens Doctor');
        $this->line("  [OK] Engine Binary: {$binary}");
        $this->line("  [OK] Engine Version: v{$protocol['engine_version']} (Protocol v{$protocol['protocol_version']})");
        $this->line("  [OK] Laravel Project: {$project['root']} (Laravel {$project['laravel_version']}, PHP {$project['php_version']})");

        return self::SUCCESS;
    }
}
