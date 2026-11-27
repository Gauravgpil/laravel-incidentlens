<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Commands\Concerns\RendersLiveSpinner;
use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Console\Command;

final class SecurityAuditCommand extends Command
{
    use RendersLiveSpinner;
    protected $signature = 'security:audit
        {--scope=all : Scope (all, secrets, ai, git, auth, vulnerabilities, storage, webhooks, leaks)}
        {--ci : Exit non-zero if high/critical security findings exist}
        {--json : Output as JSON}';

    protected $aliases = [
        'security:secrets',
        'security:ai',
        'security:git',
        'security:leaks',
        'security:auth',
        'security:vulnerabilities',
        'security:storage',
    ];

    protected $description = 'Run Laravel Security Vulnerability & Sensitive Data Leakage Audit via IncidentLens';

    public function handle(EngineClient $engine, ProjectInspector $inspector): int
    {
        $calledName = (string) $this->getName();
        $scope = str_starts_with($calledName, 'security:') && $calledName !== 'security:audit'
            ? substr($calledName, 9)
            : (string) $this->option('scope');

        $ci = (bool) $this->option('ci');

        try {
            $result = $this->scanWithSpinner(
                $engine,
                $inspector->inspect(),
                ['modules' => ['security'], 'scope' => $scope],
                $ci,
                "Running Security Engine ({$scope})..."
            );
        } catch (EngineException $e) {
            $this->error($e->getMessage());
            return 3;
        }

        $response = $result['response'];
        $findings = array_values(array_filter(
            $response['findings'] ?? [],
            static fn (array $f): bool => ($f['module'] ?? '') === 'security'
        ));
        $response['findings'] = $findings;

        if ($this->option('json')) {
            $this->line((string) json_encode($response, JSON_PRETTY_PRINT));
            return $result['exit_code'];
        }

        $this->info("Laravel Security Intelligence Engine (scope: {$scope}) — " . count($findings) . ' finding(s)');
        foreach ($findings as $f) {
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
}
