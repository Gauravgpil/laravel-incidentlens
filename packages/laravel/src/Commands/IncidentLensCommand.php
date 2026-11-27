<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Illuminate\Console\Command;
use function Laravel\Prompts\info;
use function Laravel\Prompts\note;
use function Laravel\Prompts\search;
use function Laravel\Prompts\select;

final class IncidentLensCommand extends Command
{
    protected $signature = 'incidentlens {--tui : Launch the interactive Rust TUI dashboard directly}';
    protected $description = 'Interactive Laravel IncidentLens Command Center (dropdown menu for all audits & TUI)';

    public function handle(EngineClient $engine): int
    {
        if ($this->option('tui')) {
            return $this->launchRustTui($engine);
        }

        $this->newLine();
        info('LARAVEL INCIDENTLENS — Interactive Command Center');
        note('Select any diagnostic, security audit, or launch the full-screen Rust TUI (no flags to memorize).');

        $choices = [
            'tui' => '🚀 Launch Interactive Rust TUI Dashboard (Full-Screen)',
            'audit:all' => '🔍 Full Production Readiness Audit (All Modules)',
            'preflight' => '🛫 Deployment Preflight Check ([PASS]/[WARN]/[FAIL])',
            'incident' => '🚨 Production Incident Timeline & Correlation',
            'security:audit' => '🛡️  Security Audit (All Scopes)',
            'security:secrets' => '🔑 Scan Exposed API Keys, AI Tokens & .env',
            'security:ai' => '🤖 AI Security (OpenAI/Gemini/Anthropic/Inertia/Frontend)',
            'security:git' => '📜 Git History Secret Scanner',
            'security:auth' => '🔐 Auth, Session, CORS, IDOR & Filament Access Control',
            'security:vulnerabilities' => '⚠️  SQLi, XSS, SSRF, File Upload & Webhook Audit',
            'audit:n1' => '🐘 Database & N+1 Query Detection',
            'audit:memory' => '🧠 Memory Overflow & Resource Audit',
            'audit:performance' => '⚡ Performance (P50/P95/P99 & External HTTP)',
            'audit:code' => '🧩 Code Quality (Routes, Controllers, Models, Exceptions)',
            'audit:architecture' => '🏛️  Architecture & Circular Dependency Graph',
            'audit:frontend' => '⚛️  Frontend & Vite/React/Inertia Asset Audit',
            'audit:scalability' => '📈 Horizontal Scalability & Infra Audit',
            'report:html' => '📄 Export Styled HTML Report (incidentlens-report.html)',
            'incidentlens:doctor' => '🩺 Doctor (Verify Rust Engine & Setup)',
        ];

        $selected = function_exists('Laravel\\Prompts\\search')
            ? search(
                label: 'What would you like IncidentLens to run?',
                options: fn (string $value): array => $value === ''
                    ? $choices
                    : array_filter(
                        $choices,
                        static fn (string $label, string $key): bool => str_contains(strtolower($label), strtolower($value))
                            || str_contains(strtolower($key), strtolower($value)),
                        ARRAY_FILTER_USE_BOTH
                    ),
                placeholder: 'Type to filter (e.g. security, n1, preflight, tui)...',
                scroll: 12,
            )
            : (string) $this->choice('Select an IncidentLens action', $choices, 'tui');

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
