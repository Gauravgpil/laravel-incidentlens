<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Collectors;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;

final class RuntimeCollector
{
    private const MAX_RUNTIME_LOG_BYTES = 10 * 1024 * 1024; // 10 MB bounded storage

    private ?string $currentRequestId = null;

    /** @var array<string, float> */
    private array $jobStartTimes = [];

    public function __construct(
        private readonly string $storagePath,
        private readonly float $samplingRate = 1.0,
        private readonly bool $captureQueries = false,
        private readonly bool $captureQueue = true,
    ) {
    }

    public function register(Dispatcher $events): void
    {
        $this->currentRequestId = bin2hex(random_bytes(8));

        if ($this->captureQueries && class_exists(QueryExecuted::class)) {
            $events->listen(QueryExecuted::class, function (QueryExecuted $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $this->appendEvent([
                    'type' => 'query',
                    'timestamp' => gmdate('c'),
                    'duration_ms' => round($event->time, 3),
                    'sql_normalized' => self::normalizeSql($event->sql),
                    'connection' => $event->connectionName,
                    'request_id' => $this->currentRequestId,
                ]);
            });
        }

        if ($this->captureQueue && class_exists(JobProcessing::class)) {
            $events->listen(JobProcessing::class, function (JobProcessing $event): void {
                $this->jobStartTimes[$event->job->getJobId()] = microtime(true);
            });

            $events->listen(JobProcessed::class, function (JobProcessed $event): void {
                $id = $event->job->getJobId();
                $durationMs = isset($this->jobStartTimes[$id])
                    ? round((microtime(true) - $this->jobStartTimes[$id]) * 1000, 3)
                    : null;
                unset($this->jobStartTimes[$id]);

                $this->appendEvent([
                    'type' => 'job',
                    'timestamp' => gmdate('c'),
                    'job_class' => $event->job->resolveName(),
                    'queue' => $event->job->getQueue(),
                    'status' => 'processed',
                    'duration_ms' => $durationMs,
                    'exception' => null,
                    'attempt' => $event->job->attempts(),
                ]);
            });

            $events->listen(JobFailed::class, function (JobFailed $event): void {
                $id = $event->job->getJobId();
                $durationMs = isset($this->jobStartTimes[$id])
                    ? round((microtime(true) - $this->jobStartTimes[$id]) * 1000, 3)
                    : null;
                unset($this->jobStartTimes[$id]);

                $this->appendEvent([
                    'type' => 'job',
                    'timestamp' => gmdate('c'),
                    'job_class' => $event->job->resolveName(),
                    'queue' => $event->job->getQueue(),
                    'status' => 'failed',
                    'duration_ms' => $durationMs,
                    'exception' => $event->exception::class . ': ' . $event->exception->getMessage(),
                    'attempt' => $event->job->attempts(),
                ]);
            });
        }

        if (class_exists(RequestHandled::class)) {
            $events->listen(RequestHandled::class, function (RequestHandled $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $startTime = defined('LARAVEL_START') ? (float) LARAVEL_START : microtime(true);
                $durationMs = round((microtime(true) - $startTime) * 1000, 3);
                $route = $event->request->route()?->uri() ?? $event->request->path();

                $this->appendEvent([
                    'type' => 'request',
                    'timestamp' => gmdate('c'),
                    'method' => $event->request->method(),
                    'route' => '/' . ltrim((string) $route, '/'),
                    'status' => $event->response->getStatusCode(),
                    'duration_ms' => $durationMs,
                    'memory_peak_bytes' => memory_get_peak_usage(true),
                    'request_id' => $this->currentRequestId,
                ]);
            });
        }
    }

    /**
     * Normalizes SQL statements by replacing string and numeric literals with `?`.
     * Bindings are never collected.
     */
    public static function normalizeSql(string $sql): string
    {
        $sql = (string) preg_replace("/'[^']*'/", '?', $sql);
        $sql = (string) preg_replace('/"[^"]*"/', '?', $sql);
        $sql = (string) preg_replace('/\b\d+\b/', '?', $sql);
        return trim((string) preg_replace('/\s+/', ' ', $sql));
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function appendEvent(array $payload): void
    {
        $dir = rtrim($this->storagePath, DIRECTORY_SEPARATOR);
        if (! is_dir($dir) && ! @mkdir($dir, 0755, true) && ! is_dir($dir)) {
            return;
        }

        $file = $dir . DIRECTORY_SEPARATOR . 'runtime.jsonl';
        if (is_file($file) && (int) @filesize($file) >= self::MAX_RUNTIME_LOG_BYTES) {
            @rename($file, $dir . DIRECTORY_SEPARATOR . 'runtime.jsonl.prev');
        }

        $line = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($line !== false) {
            @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    private function shouldSample(): bool
    {
        if ($this->samplingRate >= 1.0) {
            return true;
        }
        if ($this->samplingRate <= 0.0) {
            return false;
        }
        return (mt_rand() / mt_getrandmax()) <= $this->samplingRate;
    }
}
