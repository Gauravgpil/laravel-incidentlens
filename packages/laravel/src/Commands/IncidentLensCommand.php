<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Illuminate\Console\Command;
use function Laravel\Prompts\search;

final class IncidentLensCommand extends Command
{
    protected $signature = 'incidentlens {--tui : Launch the interactive Rust TUI dashboard directly}';
    protected $description = 'Interactive Laravel IncidentLens Command Center (searchable menu for all audits & TUI)';

    public function handle(EngineClient $engine): int
    {
        if ($this->option('tui')) {
            return $this->launchRustTui($engine);
        }

        $this->newLine();
        $this->line('  <fg=cyan;options=bold>LARAVEL INCIDENTLENS</>  <fg=gray>v0.1.0 — Rust Diagnostic Engine</>');
        $this->newLine();

        $choices = [
            'tui'                      => '[TUI]    Interactive Dashboard (Full-Screen)',
            'audit:all'                => '[AUDIT]  Full Production Readiness Scan',
            'preflight'                => '[OPS]    Deployment Preflight Check',
            'incident'                 => '[OPS]    Production Incident Timeline',
            'security:audit'           => '[SEC]    Full Security Audit (All Scopes)',
            'security:secrets'         => '[SEC]    Exposed API Keys, Tokens & .env',
            'security:ai'              => '[SEC]    AI Credentials & Inertia/JS Leakage',
            'security:git'             => '[SEC]    Git Commit History Secret Scan',
            'security:auth'            => '[SEC]    Auth, Session, CORS, IDOR & Filament',
            'security:vulnerabilities' => '[SEC]    SQLi, XSS, SSRF, Uploads & Webhooks',
            'audit:n1'                 => '[DB]     Database & N+1 Query Detection',
            'audit:memory'             => '[PERF]   Memory Overflow & Disk Resources',
            'audit:performance'        => '[PERF]   Endpoint Latency (P50/P95/P99)',
            'audit:code'               => '[CODE]   Routes, Controllers, Models & Catch',
            'audit:architecture'       => '[ARCH]   Circular Dependencies & Boundaries',
            'audit:frontend'           => '[ASSET]  Vite, React & Inertia Bundle Audit',
            'audit:scalability'        => '[INFRA]  Horizontal Scalability Readiness',
            'report:html'              => '[EXPORT] Generate HTML Diagnostic Report',
            'incidentlens:doctor'      => '[DIAG]   Verify Rust Engine & Configuration',
        ];

        $selected = function_exists('Laravel\\Prompts\\search')
            ? search(
                label: 'Select a command to run',
                options: fn (string $value): array => $value === ''
                    ? $choices
                    : array_filter(
                        $choices,
                        static fn (string $label, string $key): bool => str_contains(strtolower($label), strtolower($value))
                            || str_contains(strtolower($key), strtolower($value)),
                        ARRAY_FILTER_USE_BOTH
                    ),
                placeholder: 'Filter (e.g. security, n1, preflight, tui)...',
                scroll: 12,
            )
            : (string) $this->choice('Select an IncidentLens command', $choices, 'tui');

        return match ($selected) {
            'tui' => $this->launchRustTui($engine),
            'preflight' => $this->runRustSubcommand($engine, ['preflight']),
            'incident' => $this->runRustSubcommand($engine, ['incident']),
            'audit:architecture' => $this->runRustSubcommand($engine, ['architecture']),
            'report:html' => $this->runRustSubcommand($engine, ['report', '--format=html', '--output=incidentlens-report.html']),
            default => (int) $this->call($selected),
        };
    }

    private function launchRustTui(EngineClient $engine): int
    {
        return $this->runRustSubcommand($engine, []);
    }

    /**
     * @param list<string> $args
     */
    private function runRustSubcommand(EngineClient $engine, array $args): int
    {
        try {
            $binary = $engine->resolveBinary();
        } catch (EngineException $e) {
            $this->error($e->getMessage());
            return self::FAILURE;
        }

        $cmd = array_merge([$binary], $args);
        $descriptors = [0 => STDIN, 1 => STDOUT, 2 => STDERR];
        $process = proc_open($cmd, $descriptors, $pipes);
        if (! is_resource($process)) {
            $this->error('Failed to launch Rust IncidentLens engine.');
            return self::FAILURE;
        }

        return (int) proc_close($process);
    }
}
