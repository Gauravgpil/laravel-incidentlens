<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Engine;

use RuntimeException;

final class EngineException extends RuntimeException
{
    public static function binaryNotFound(string $searched): self
    {
        return new self(
            "IncidentLens Rust engine binary not found. Searched: {$searched}. "
            . 'Configure INCIDENTLENS_BINARY or build the Rust binary with `cargo build --release`.'
        );
    }

    public static function incompatibleProtocol(string $engineProtocol, string $expectedMajor): self
    {
        return new self(
            "Incompatible IncidentLens protocol version '{$engineProtocol}'. Expected major version '{$expectedMajor}'."
        );
    }

    public static function executionFailed(int $exitCode, string $stderr): self
    {
        $detail = trim($stderr) !== '' ? trim($stderr) : 'no error output';
        return new self("IncidentLens engine failed with exit code {$exitCode}: {$detail}");
    }
}
