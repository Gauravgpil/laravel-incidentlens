<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Console\Command;

final class StatusCommand extends Command
{
    protected $signature = 'incidentlens:status {--json : Output as JSON}';
    protected $description = 'Display Laravel application health summary via IncidentLens';

    public function handle(EngineClient $engine, ProjectInspector $inspector): int
    {
        try {
            $result = $engine->scan($inspector->inspect());
        } catch (EngineException $e) {
            $this->error($e->getMessage());
            return self::FAILURE;
        }

        $response = $result['response'];
        if ($this->option('json')) {
            $this->line((string) json_encode($response, JSON_PRETTY_PRINT));
            return self::SUCCESS;
        }

        $project = $response['project'] ?? [];
        $summary = $response['summary'] ?? [];
        $this->info('Laravel IncidentLens — Status');
        $this->line('  Project: ' . ($project['name'] ?? 'unknown') . ' (' . ($project['environment'] ?? 'unknown') . ')');
        $this->line('  Errors: ' . ($summary['errors'] ?? 0) . ' | Warnings: ' . ($summary['warnings'] ?? 0));

        return self::SUCCESS;
    }
}
