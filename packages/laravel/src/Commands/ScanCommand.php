<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Commands\Concerns\RendersLiveSpinner;
use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Console\Command;

final class ScanCommand extends Command
{
    use RendersLiveSpinner;
    protected $signature = 'incidentlens:scan {--ci : Exit non-zero if high/critical findings exist} {--json : Output as JSON}';
    protected $description = 'Run a diagnostic scan using the Rust IncidentLens engine';

    public function handle(EngineClient $engine, ProjectInspector $inspector): int
    {
        $ci = (bool) $this->option('ci');

        try {
            $result = $this->scanWithSpinner($engine, $inspector->inspect(), [], $ci, 'Scanning Laravel application...');
        } catch (EngineException $e) {
            $this->error($e->getMessage());
            return 3;
        }

        $response = $result['response'];
        if ($this->option('json')) {
            $this->line((string) json_encode($response, JSON_PRETTY_PRINT));
            return $result['exit_code'];
        }

        $findings = $response['findings'] ?? [];
        $this->info('IncidentLens Scan Complete — ' . count($findings) . ' finding(s)');
        foreach ($findings as $finding) {
            $this->line(sprintf(
                '  [%s] %s (%s) — %s',
                $finding['id'] ?? '?',
                $finding['title'] ?? '',
                strtoupper((string) ($finding['severity'] ?? 'info')),
                $finding['next_step'] ?? ''
            ));
        }

        return $result['exit_code'];
    }
}
