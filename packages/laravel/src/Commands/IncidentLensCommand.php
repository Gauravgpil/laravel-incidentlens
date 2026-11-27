<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Illuminate\Console\Command;
use Symfony\Component\Process\ExecutableFinder;
use function Laravel\Prompts\confirm;
use function Laravel\Prompts\search;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;

final class IncidentLensCommand extends Command
{
    protected $signature = 'incidentlens {--tui : Launch the interactive Rust TUI dashboard directly}';
    protected $description = 'Interactive Laravel IncidentLens Command Center (searchable menu, .md export & agy CLI)';

    public function handle(EngineClient $engine): int
    {
        if ($this->option('tui')) {
            return $this->launchRustTui($engine);
        }

        $agyBinary = $this->detectAgyBinary();
        $agyStatus = $agyBinary !== null
            ? '<fg=green>connected</>'
            : '<fg=gray>not detected</>';

        $this->newLine();
        $this->line("  <fg=cyan;options=bold>LARAVEL INCIDENTLENS</>  <fg=gray>v0.1.0</>  |  <fg=gray>Antigravity CLI (agy):</> {$agyStatus}");
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
            'report:md'                => '[EXPORT] Save Diagnostic Report as Markdown (.md)',
            'report:html'              => '[EXPORT] Save Diagnostic Report as HTML (.html)',
            'incidentlens:doctor'      => '[DIAG]   Verify Rust Engine & Configuration',
        ];

        if ($agyBinary !== null) {
            $choices['agy:fix'] = '[AGY]    Fix Reported Issues with Antigravity CLI';
        }

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
                placeholder: 'Filter (e.g. security, n1, md, agy, tui)...',
                scroll: 12,
            )
            : (string) $this->choice('Select an IncidentLens command', $choices, 'tui');

        if ($selected === 'agy:fix') {
            return $this->runAgyFixWorkflow($engine, $agyBinary);
        }
        if ($selected === 'report:md') {
            return $this->exportMarkdownInteractive($engine);
        }
        if ($selected === 'report:html') {
            return $this->runRustSubcommand($engine, ['report', '--format=html', '--output=incidentlens-report.html']);
        }

        $exitCode = match ($selected) {
            'tui' => $this->launchRustTui($engine),
            'preflight' => $this->runRustSubcommand($engine, ['preflight']),
            'incident' => $this->runRustSubcommand($engine, ['incident']),
            'audit:architecture' => $this->runRustSubcommand($engine, ['architecture']),
            default => (int) $this->call($selected),
        };

        if ($selected !== 'tui' && $selected !== 'incidentlens:doctor' && function_exists('Laravel\\Prompts\\select')) {
            $this->offerPostScanActions($engine, $agyBinary);
        }

        return $exitCode;
    }

    private function offerPostScanActions(EngineClient $engine, ?string $agyBinary): void
    {
        $actions = [
            'done' => 'Done (Exit)',
            'md'   => 'Save report as Markdown (.md)',
        ];
        if ($agyBinary !== null) {
            $actions['agy'] = 'Open in Antigravity CLI (agy) to fix issues';
        }

        $next = select(
            label: 'Next action',
            options: $actions,
            default: 'done',
        );

        if ($next === 'md') {
            $this->exportMarkdownInteractive($engine);
        } elseif ($next === 'agy' && $agyBinary !== null) {
            $this->runAgyFixWorkflow($engine, $agyBinary);
        }
    }

    private function exportMarkdownInteractive(EngineClient $engine): int
    {
        $path = function_exists('Laravel\\Prompts\\text')
            ? text(
                label: 'Markdown file path',
                default: 'incidentlens-report.md',
                required: true,
            )
            : 'incidentlens-report.md';

        $code = $this->runRustSubcommand($engine, ['report', '--format=markdown', '--output=' . $path]);
        if ($code === self::SUCCESS) {
            $this->info("Saved Markdown report to: {$path}");
        }
        return $code;
    }

    private function runAgyFixWorkflow(EngineClient $engine, ?string $agyBinary): int
    {
        if ($agyBinary === null) {
            $this->error('Antigravity CLI (`agy`) was not found on PATH.');
            return self::FAILURE;
        }

        $reportFile = 'incidentlens-report.md';
        $code = $this->runRustSubcommand($engine, ['report', '--format=markdown', '--output=' . $reportFile]);
        if ($code !== self::SUCCESS) {
            return $code;
        }

        $this->line("  Generated redacted report: {$reportFile}");
        $confirmed = function_exists('Laravel\\Prompts\\confirm')
            ? confirm(
                label: "Launch Antigravity CLI ({$agyBinary}) with {$reportFile} to review and fix findings?",
                default: false,
            )
            : $this->confirm("Launch Antigravity CLI with {$reportFile}?", false);

        if (! $confirmed) {
            $this->line('  Cancelled. You can review the report manually in ' . $reportFile);
            return self::SUCCESS;
        }

        $prompt = "Review the Laravel IncidentLens diagnostic report in {$reportFile}. Prioritize high/critical security and N+1 findings, explain each fix, and apply safe fixes.";
        return $this->runExternalTty([$agyBinary, '-i', $prompt]);
    }

    private function detectAgyBinary(): ?string
    {
        $finder = new ExecutableFinder();
        $found = $finder->find('agy');
        if ($found !== null) {
            return $found;
        }

        $home = getenv('HOME') ?: '';
        if ($home !== '') {
            $local = $home . DIRECTORY_SEPARATOR . '.local' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'agy';
            if (is_file($local) && is_executable($local)) {
                return $local;
            }
        }

        return null;
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

        return $this->runExternalTty(array_merge([$binary], $args));
    }

    /**
     * @param list<string> $cmd
     */
    private function runExternalTty(array $cmd): int
    {
        $descriptors = [0 => STDIN, 1 => STDOUT, 2 => STDERR];
        $process = proc_open($cmd, $descriptors, $pipes);
        if (! is_resource($process)) {
            $this->error('Failed to launch external process.');
            return self::FAILURE;
        }

        return (int) proc_close($process);
    }
}
