<?php

declare(strict_types=1);

return [
    'enabled' => env('INCIDENTLENS_ENABLED', true),

    'engine' => [
        'binary' => env('INCIDENTLENS_BINARY', null),
        'timeout' => (int) env('INCIDENTLENS_TIMEOUT', 120),
    ],

    'logs' => [
        'enabled' => true,
        'paths' => [],
        'max_file_size' => null,
    ],

    'database' => [
        'enabled' => true,
        'capture_queries' => false,
        'capture_bindings' => false,
        'detect_lazy_loading' => false,
        'slow_query_threshold_ms' => 500,
    ],

    'queue' => [
        'enabled' => true,
    ],

    'performance' => [
        'enabled' => true,
        'sampling_rate' => 1.0,
    ],

    'runtime' => [
        'enabled' => env('INCIDENTLENS_RUNTIME_ENABLED', false),
    ],

    'privacy' => [
        'redact_secrets' => true,
        'collect_request_body' => false,
        'collect_query_bindings' => false,
    ],

    'storage' => [
        'path' => function_exists('storage_path') ? storage_path('app/incidentlens') : null,
        'retention_days' => 7,
    ],
];
