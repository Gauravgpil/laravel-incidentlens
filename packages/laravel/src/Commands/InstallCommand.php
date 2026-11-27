<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands;

use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Engine\EngineException;
use Illuminate\Console\Command;

final class InstallCommand extends Command
{
    protected $signature = 'incidentlens:install
        {--publish : Publish config/incidentlens.php}
        {--verify-checksum= : Expected SHA-256 checksum of the Rust binary}';

    protected $description = 'Install, verify, and configure Laravel IncidentLens and its Rust diagnostic engine';

    public function handle(EngineClient $engine): int
    {
        $platform = self::detectPlatformTarget();
        $this->info("Laravel IncidentLens Installer (Platform: {$platform})");

        if ($this->option('publish')) {
            $this->call('vendor:publish', ['--tag' => 'incidentlens-config']);
        }

        try {
            $binary = $engine->resolveBinary();
            $expected = $this->option('verify-checksum');
            if (is_string($expected) && $expected !== '') {
                $actual = hash_file('sha256', $binary);
                if (! is_string($actual) || ! hash_equals(strtolower($expected), strtolower($actual))) {
                    $this->error("Checksum verification failed for {$binary}!");
                    return self::FAILURE;
                }
                $this->line("  [OK] SHA-256 checksum verified.");
            }

            $protocol = $engine->protocolInfo();
            $this->line("  [OK] Rust Engine located: {$binary}");
            $this->line("  [OK] Engine v{$protocol['engine_version']} (Protocol v{$protocol['protocol_version']})");
            $this->info('IncidentLens is ready! Run `php artisan incidentlens:status` or `./vendor/bin/incidentlens`.');

            return self::SUCCESS;
        } catch (EngineException $e) {
            $this->warn('Rust engine binary not found locally.');
            $this->line("  Target triple: {$platform}");
            $this->line('  Option 1 (Source build): `cargo build --release -p incidentlens-cli` and set INCIDENTLENS_BINARY.');
            $this->line('  Option 2 (Verified release): Download `incidentlens-' . $platform . '` + `SHA256SUMS.txt` from GitHub Releases and verify checksum before placing in PATH.');
            return self::FAILURE;
        }
    }

    public static function detectPlatformTarget(): string
    {
        $arch = strtolower(php_uname('m'));
        $normArch = match (true) {
            str_contains($arch, 'arm64') || str_contains($arch, 'aarch64') => 'aarch64',
            default => 'x86_64',
        };

        return match (PHP_OS_FAMILY) {
            'Darwin' => "{$normArch}-apple-darwin",
            'Windows' => "{$normArch}-pc-windows-msvc",
            default => "{$normArch}-unknown-linux-gnu",
        };
    }
}
