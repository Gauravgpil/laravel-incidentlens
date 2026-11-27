<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Engine;

use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

final class EngineClient
{
    public const PROTOCOL_VERSION = '1.0';
    public const SUPPORTED_MAJOR = '1';

    public function __construct(
        private readonly ?string $configuredBinary = null,
        private readonly int $timeoutSeconds = 120,
        private readonly ?string $projectBasePath = null,
    ) {
    }

    /**
     * Resolves the Rust engine binary path without falling back to PHP analysis.
     */
    public function resolveBinary(): string
    {
        $candidates = [];

        $envBinary = $this->configuredBinary ?? (getenv('INCIDENTLENS_BINARY') ?: null);
        if ($envBinary !== null && $envBinary !== '') {
            $candidates[] = $envBinary;
            if ($this->isExecutableFile($envBinary)) {
                return $envBinary;
            }
        }

        if ($this->projectBasePath !== null) {
            $vendorEngine = $this->projectBasePath . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'incidentlens-engine' . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
            $candidates[] = $vendorEngine;
            if ($this->isExecutableFile($vendorEngine)) {
                return $vendorEngine;
            }

            $vendorBin = $this->projectBasePath . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . $this->binaryName();
            $candidates[] = $vendorBin;
            if ($this->isExecutableFile($vendorBin)) {
                return $vendorBin;
            }
        }

        $finder = new ExecutableFinder();
        $found = $finder->find($this->binaryName());
        if ($found !== null && $this->isExecutableFile($found)) {
            return $found;
        }
        $candidates[] = 'PATH:' . $this->binaryName();

        throw EngineException::binaryNotFound(implode(', ', $candidates));
    }

    /**
     * Queries engine version & protocol compatibility.
     *
     * @return array<string, mixed>
     */
    public function protocolInfo(): array
    {
        $binary = $this->resolveBinary();
        $process = new Process([$binary, 'protocol', '--no-interaction']);
        $process->setTimeout($this->timeoutSeconds);
        $process->run();

        if (! $process->isSuccessful()) {
            throw EngineException::executionFailed(
                $process->getExitCode() ?? 3,
                $process->getErrorOutput()
            );
        }

        $decoded = json_decode($process->getOutput(), true);
        if (! is_array($decoded) || ! isset($decoded['protocol_version'])) {
            throw new EngineException('Malformed protocol response from IncidentLens engine.');
        }

        $version = (string) $decoded['protocol_version'];
        $major = explode('.', $version)[0] ?? '';
        if ($major !== self::SUPPORTED_MAJOR) {
            throw EngineException::incompatibleProtocol($version, self::SUPPORTED_MAJOR);
        }

        return $decoded;
    }

    /**
     * Sends a versioned RequestEnvelope to the Rust engine over stdin and returns the decoded response + exit code.
     *
     * @param array<string, mixed> $projectMetadata
     * @param array<string, mixed> $options
     * @param callable(float):void|null $onTick Optional progress callback invoked with elapsed seconds while Rust runs
     * @return array{exit_code: int, response: array<string, mixed>}
     */
    public function scan(array $projectMetadata, array $options = [], bool $ci = false, ?callable $onTick = null): array
    {
        $binary = $this->resolveBinary();

        $envelope = [
            'protocol_version' => self::PROTOCOL_VERSION,
            'command' => 'scan',
            'project' => $projectMetadata,
            'options' => $options,
        ];

        $payload = json_encode($envelope, JSON_THROW_ON_ERROR);

        $args = [$binary, 'scan', '--stdin-json', '--format=json', '--no-interaction'];
        if ($ci) {
            $args[] = '--ci';
        }

        $process = new Process($args);
        $process->setTimeout($this->timeoutSeconds);
        $process->setInput($payload);
        $process->start();

        $started = microtime(true);
        while ($process->isRunning()) {
            if ($onTick !== null) {
                $onTick(microtime(true) - $started);
            }
            usleep(80_000);
        }

        $exitCode = $process->getExitCode() ?? 3;
        if (! in_array($exitCode, [0, 1], true)) {
            throw EngineException::executionFailed($exitCode, $process->getErrorOutput());
        }

        $decoded = json_decode($process->getOutput(), true);
        if (! is_array($decoded)) {
            throw new EngineException('Malformed JSON response from IncidentLens engine.');
        }

        $version = (string) ($decoded['protocol_version'] ?? '');
        $major = explode('.', $version)[0] ?? '';
        if ($major !== self::SUPPORTED_MAJOR) {
            throw EngineException::incompatibleProtocol($version, self::SUPPORTED_MAJOR);
        }

        return [
            'exit_code' => $exitCode,
            'response' => $decoded,
        ];
    }

    private function binaryName(): string
    {
        return DIRECTORY_SEPARATOR === '\\' ? 'incidentlens.exe' : 'incidentlens';
    }

    private function isExecutableFile(string $path): bool
    {
        $real = realpath($path);
        if ($real === false || ! is_file($real)) {
            return false;
        }
        if (DIRECTORY_SEPARATOR !== '\\' && ! is_executable($real)) {
            return false;
        }
        // Never treat the Composer PHP shim itself as the native Rust engine binary.
        $head = @file_get_contents($real, false, null, 0, 64);
        if (is_string($head) && (str_contains($head, '<?php') || str_contains($head, 'env php'))) {
            return false;
        }
        return true;
    }
}
