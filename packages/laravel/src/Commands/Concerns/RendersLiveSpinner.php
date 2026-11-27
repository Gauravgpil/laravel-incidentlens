<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Commands\Concerns;

use Gaurav\IncidentLens\Engine\EngineClient;

trait RendersLiveSpinner
{
    /**
     * Runs an EngineClient scan while rendering a live animated spinner + elapsed timer
     * so the terminal never appears frozen or blinking.
     *
     * @param array<string, mixed> $projectMetadata
     * @param array<string, mixed> $options
     * @return array{exit_code: int, response: array<string, mixed>}
     */
    protected function scanWithSpinner(
        EngineClient $engine,
        array $projectMetadata,
        array $options,
        bool $ci,
        string $label,
    ): array {
        $isInteractive = ! $this->option('json') && $this->output->isDecorated();
        $frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        $tick = 0;

        $result = $engine->scan(
            $projectMetadata,
            $options,
            $ci,
            $isInteractive ? function (float $elapsed) use (&$tick, $frames, $label): void {
                $frame = $frames[$tick % count($frames)];
                $tick++;
                $timeStr = number_format($elapsed, 1) . 's';
                $this->output->write("\r\033[2K<fg=cyan>{$frame}</> <options=bold>IncidentLens</> │ {$label} <fg=yellow>({$timeStr})</>");
            } : null
        );

        if ($isInteractive) {
            $this->output->write("\r\033[2K");
        }

        return $result;
    }
}
