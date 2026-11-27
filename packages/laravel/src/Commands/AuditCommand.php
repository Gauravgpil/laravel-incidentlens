<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Console\Command;

final class AuditCommand extends Command
{
    protected $signature = 'incidentlens:audit
        {module=all : Audit module (all, performance, n1, memory, security, database, queue, api, code, production, frontend, scalability)}
        {--ci : Exit non-zero if high/critical findings exist}
        {--json : Output as JSON}';

    protected $aliases = [
        'audit:all',
        'audit:performance',
        'audit:n1',
        'audit:memory',
        'audit:security',
        'audit:database',
        'audit:queue',
        'audit:api',
        'audit:code',
        'audit:production',
        'audit:frontend',
        'audit:scalability',
    ];

    protected $description = 'Run Laravel Production Readiness & Code Quality Audit via IncidentLens Rust engine';

    public function handle(EngineClient $engine, ProjectInspector $inspector): int
    {
        $calledName = (string) $this->getName();
        $module = str_starts_with($calledName, 'audit:')
            ? substr($calledName, 6)
            : (string) $this->argument('module');

        $ci = (bool) $this->option('ci');

        try {
            $result = $engine->scan($inspector->inspect(), [], $ci);
        } catch (EngineException $e) {
            $this->error($e->getMessage());
            return 3;
        }

        $response = $result['response'];
        $findings = $response['findings'] ?? [];
        $filtered = $this->filterFindings($findings, $module);
        $response['findings'] = $filtered;

        if ($this->option('json')) {
            $this->line((string) json_encode($response, JSON_PRETTY_PRINT));
            return $result['exit_code'];
        }

        $score = $response['telemetry']['health_score'] ?? 100;
        $this->info("Laravel Production Readiness Audit ({$module}) — Score: {$score}/100");
        foreach ($filtered as $f) {
            $this->line(sprintf(
                '  [%s] (%s) %s — %s',
                strtoupper((string) ($f['severity'] ?? 'info')),
                $f['id'] ?? '?',
                $f['title'] ?? '',
                $f['next_step'] ?? ''
            ));
        }

        return $result['exit_code'];
    }

    /**
     * @param list<array<string, mixed>> $findings
     * @return list<array<string, mixed>>
     */
    private function filterFindings(array $findings, string $module): array
    {
        if ($module === 'all' || $module === '') {
            return $findings;
        }

        $targetModules = match ($module) {
            'n1' => ['database'],
            'memory' => ['resources', 'performance'],
            'production' => ['project', 'security', 'scalability'],
            default => [$module],
        };

        return array_values(array_filter(
            $findings,
            static fn (array $f): bool => in_array($f['module'] ?? '', $targetModules, true)
        ));
    }
}
