<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Collectors;

use Illuminate\Cache\Events\CacheHit;
use Illuminate\Cache\Events\CacheMissed;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Http\Client\Events\ResponseReceived;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;

final class RuntimeCollector
{
    private const MAX_RUNTIME_LOG_BYTES = 10 * 1024 * 1024; // 10 MB bounded storage
    private const MAX_EVENTS_PER_REQUEST = 500;
    private const MAX_JOB_TIMERS = 1000;

    private ?string $currentRequestId = null;

    /** @var array<string, float> */
    private array $jobStartTimes = [];

    /** @var list<array<string, mixed>> */
    private array $requestBuffer = [];

    /** @var array<string, int> */
    private array $requestQueryCounts = [];

    public function __construct(
        private readonly string $storagePath,
        private readonly float $samplingRate = 1.0,
        private readonly bool $captureQueries = false,
        private readonly bool $captureQueue = true,
        private readonly bool $detectLazyLoading = false,
        private readonly ?string $projectBasePath = null,
    ) {
    }

    public function __destruct()
    {
        $this->flushBuffer();
    }

    public function resetRequestState(): void
    {
        $this->flushBuffer();
        $this->currentRequestId = bin2hex(random_bytes(8));
        $this->requestQueryCounts = [];
    }

    public function register(Dispatcher $events): void
    {
        $this->currentRequestId = bin2hex(random_bytes(8));

        if (class_exists('Laravel\\Octane\\Events\\RequestReceived')) {
            $events->listen('Laravel\\Octane\\Events\\RequestReceived', function (): void {
                $this->resetRequestState();
            });
        }

        if ($this->captureQueries && class_exists(QueryExecuted::class)) {
            $events->listen(QueryExecuted::class, function (QueryExecuted $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $sqlNormalized = self::normalizeSql($event->sql);
                $count = ($this->requestQueryCounts[$sqlNormalized] ?? 0) + 1;
                $this->requestQueryCounts[$sqlNormalized] = $count;

                // Capture lightweight PHP call-site only when a query repeats >= 3x in one request
                $location = $count >= 3 ? $this->captureCallSite() : null;

                $this->bufferEvent([
                    'type' => 'query',
                    'timestamp' => gmdate('c'),
                    'duration_ms' => round($event->time, 3),
                    'sql_normalized' => $sqlNormalized,
                    'connection' => $event->connectionName,
                    'request_id' => $this->currentRequestId,
                    'location' => $location,
                ]);
            });
        }

        if ($this->detectLazyLoading && class_exists(Model::class) && method_exists(Model::class, 'handleLazyLoadingViolationUsing')) {
            Model::handleLazyLoadingViolationUsing(function (Model $model, string $relation): void {
                $this->bufferEvent([
                    'type' => 'lazy_loading',
                    'timestamp' => gmdate('c'),
                    'model' => $model::class,
                    'relation' => $relation,
                    'location' => $this->captureCallSite(),
                    'request_id' => $this->currentRequestId,
                ]);
            });
        }

        if ($this->captureQueue && class_exists(JobProcessing::class)) {
            $events->listen(JobProcessing::class, function (JobProcessing $event): void {
                if (count($this->jobStartTimes) >= self::MAX_JOB_TIMERS) {
                    array_shift($this->jobStartTimes);
                }
                $this->jobStartTimes[$event->job->getJobId()] = microtime(true);
            });

            $events->listen(JobProcessed::class, function (JobProcessed $event): void {
                $id = $event->job->getJobId();
                $durationMs = isset($this->jobStartTimes[$id])
                    ? round((microtime(true) - $this->jobStartTimes[$id]) * 1000, 3)
                    : null;
                unset($this->jobStartTimes[$id]);

                $this->bufferEvent([
                    'type' => 'job',
                    'timestamp' => gmdate('c'),
                    'job_class' => $event->job->resolveName(),
                    'queue' => $event->job->getQueue(),
                    'status' => 'processed',
                    'duration_ms' => $durationMs,
                    'exception' => null,
                    'attempt' => $event->job->attempts(),
                ]);
                $this->flushBuffer();
            });

            $events->listen(JobFailed::class, function (JobFailed $event): void {
                $id = $event->job->getJobId();
                $durationMs = isset($this->jobStartTimes[$id])
                    ? round((microtime(true) - $this->jobStartTimes[$id]) * 1000, 3)
                    : null;
                unset($this->jobStartTimes[$id]);

                $this->bufferEvent([
                    'type' => 'job',
                    'timestamp' => gmdate('c'),
                    'job_class' => $event->job->resolveName(),
                    'queue' => $event->job->getQueue(),
                    'status' => 'failed',
                    'duration_ms' => $durationMs,
                    'exception' => $event->exception::class . ': ' . $event->exception->getMessage(),
                    'attempt' => $event->job->attempts(),
                ]);
                $this->flushBuffer();
            });
        }

        if (class_exists(RequestHandled::class)) {
            $events->listen(RequestHandled::class, function (RequestHandled $event): void {
                if ($this->shouldSample()) {
                    $startTime = defined('LARAVEL_START') ? (float) LARAVEL_START : microtime(true);
                    $durationMs = round((microtime(true) - $startTime) * 1000, 3);
                    $route = $event->request->route()?->uri() ?? $event->request->path();

                    $this->bufferEvent([
                        'type' => 'request',
                        'timestamp' => gmdate('c'),
                        'method' => $event->request->method(),
                        'route' => '/' . ltrim((string) $route, '/'),
                        'status' => $event->response->getStatusCode(),
                        'duration_ms' => $durationMs,
                        'memory_peak_bytes' => memory_get_peak_usage(true),
                        'request_id' => $this->currentRequestId,
                    ]);
                }
                $this->flushBuffer();
            });
        }

        if (class_exists(CacheHit::class)) {
            $events->listen(CacheHit::class, function (CacheHit $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $this->bufferEvent([
                    'type' => 'cache',
                    'timestamp' => gmdate('c'),
                    'hit' => true,
                    'store' => $event->storeName ?? null,
                ]);
            });
        }

        if (class_exists(CacheMissed::class)) {
            $events->listen(CacheMissed::class, function (CacheMissed $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $this->bufferEvent([
                    'type' => 'cache',
                    'timestamp' => gmdate('c'),
                    'hit' => false,
                    'store' => $event->storeName ?? null,
                ]);
            });
        }

        if (class_exists(ResponseReceived::class)) {
            $events->listen(ResponseReceived::class, function (ResponseReceived $event): void {
                if (! $this->shouldSample()) {
                    return;
                }
                $host = (string) (parse_url($event->request->url(), PHP_URL_HOST) ?? 'external');
                $stats = $event->response->handlerStats();
                $durationMs = isset($stats['total_time']) ? round((float) $stats['total_time'] * 1000, 3) : 0.0;

                $this->bufferEvent([
                    'type' => 'http_client',
                    'timestamp' => gmdate('c'),
                    'method' => $event->request->method(),
                    'host' => $host,
                    'status' => $event->response->status(),
                    'duration_ms' => $durationMs,
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
        $this->bufferEvent($payload);
        $this->flushBuffer();
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function bufferEvent(array $payload): void
    {
        if (count($this->requestBuffer) >= self::MAX_EVENTS_PER_REQUEST) {
            return;
        }
        $this->requestBuffer[] = $payload;
    }

    public function flushBuffer(): void
    {
        if ($this->requestBuffer === []) {
            return;
        }

        $dir = rtrim($this->storagePath, DIRECTORY_SEPARATOR);
        if (! is_dir($dir) && ! @mkdir($dir, 0755, true) && ! is_dir($dir)) {
            $this->requestBuffer = [];
            return;
        }

        $file = $dir . DIRECTORY_SEPARATOR . 'runtime.jsonl';
        if (is_file($file) && (int) @filesize($file) >= self::MAX_RUNTIME_LOG_BYTES) {
            @rename($file, $dir . DIRECTORY_SEPARATOR . 'runtime.jsonl.prev');
        }

        $chunk = '';
        foreach ($this->requestBuffer as $payload) {
            $line = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if ($line !== false) {
                $chunk .= $line . "\n";
            }
        }
        $this->requestBuffer = [];

        if ($chunk !== '') {
            @file_put_contents($file, $chunk, FILE_APPEND | LOCK_EX);
        }
    }

    private function captureCallSite(): ?string
    {
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 12);
        foreach ($frames as $frame) {
            $file = $frame['file'] ?? null;
            $line = $frame['line'] ?? null;
            if (! is_string($file) || ! is_int($line)) {
                continue;
            }
            if (str_contains($file, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)
                || str_contains($file, 'RuntimeCollector.php')) {
                continue;
            }
            if ($this->projectBasePath !== null && str_starts_with($file, $this->projectBasePath)) {
                $file = ltrim(substr($file, strlen($this->projectBasePath)), DIRECTORY_SEPARATOR);
            }
            return "{$file}:{$line}";
        }
        return null;
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
