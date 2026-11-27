# Laravel IncidentLens — Architecture Document

## 1. Overview

**Laravel IncidentLens** (`gaurav/laravel-incidentlens`, CLI `incidentlens`) is an offline-first, read-only-by-default diagnostic tool for Laravel applications. It combines a lightweight Laravel Composer package with a high-performance Rust diagnostic engine and interactive Ratatui TUI.

### Core Design Principles

1. **Rust owns heavy processing**: Log parsing, normalization, fingerprinting, query/queue/performance analysis, correlation, snapshot diffing, reporting, and the TUI run in Rust.
2. **PHP owns Laravel integration**: Project discovery, configuration inspection, Artisan command integration, and optional lightweight runtime event collection run in PHP.
3. **Offline-first & read-only by default**: No external SaaS, no automatic mutations, no automatic `EXPLAIN` or migrations, no secret values printed or stored.
4. **Evidence-based diagnostics**: Every finding separates directly observed evidence, correlated evidence, possible explanations, and unverified hypotheses.

---

## 2. Monorepo Structure

```text
laravel-incidentlens/
├── packages/
│   └── laravel/                    # Composer package (gaurav/laravel-incidentlens)
│       ├── config/
│       │   └── incidentlens.php
│       ├── src/
│       │   ├── Commands/           # Artisan commands (install, scan, doctor, etc.)
│       │   ├── Collectors/         # Optional runtime collectors (DB, Queue, Request, Exception)
│       │   ├── Engine/             # Rust binary locator, process runner, protocol client
│       │   ├── Events/             # Internal package events
│       │   ├── Facades/
│       │   ├── Support/            # Project inspector, config redactor, path validator
│       │   └── IncidentLensServiceProvider.php
│       ├── tests/                  # Pest + Orchestra Testbench tests
│       └── composer.json
│
├── crates/                         # Rust workspace
│   ├── incidentlens-core/          # Shared types, protocol v1 schemas, errors, redaction, config
│   ├── incidentlens-parser/        # Streaming Laravel/Monolog log parser & normalizer
│   ├── incidentlens-analyzer/      # Domain analyzers (Project, Log, DB, Queue, Perf, Sec, Migration, Deps)
│   ├── incidentlens-correlator/    # Cross-module incident correlation & regression engine
│   ├── incidentlens-storage/       # Snapshot persistence, incremental state, bounded retention
│   ├── incidentlens-reporter/      # JSON, Markdown, HTML, and plain-text CI formatters
│   ├── incidentlens-tui/           # Ratatui + Crossterm interactive terminal dashboard
│   └── incidentlens-cli/           # Clap CLI binary (`incidentlens`)
│
├── protocols/
│   ├── schemas/                    # JSON Schema definitions (v1)
│   └── examples/                   # Validated sample payloads
│
├── fixtures/                       # Realistic test fixtures (logs, db, queues, runtime)
├── benchmarks/                     # Criterion benchmarks & large-file generators
├── docs/                           # Architecture, protocol, roadmap, compatibility, testing
├── scripts/                        # Build, checksum, and release helpers
├── Cargo.toml
└── composer.json
```

---

## 3. Component Responsibilities

### A. Laravel Package (`packages/laravel`)

- **Project Inspector**: Reads `composer.json`, `composer.lock`, `config/*.php` (via Laravel's Config repository), PHP/Laravel versions, and directory structure. Redacts all sensitive keys (`password`, `secret`, `token`, `key`, `dsn`, etc.) before emitting metadata, reporting only key names and presence/validity states.
- **Engine Bridge**: Locates the `incidentlens` binary (configured path -> `vendor/bin` -> package `bin/` -> system `PATH`), verifies version & protocol compatibility (`--protocol-version`), invokes it via `Symfony\Component\Process\Process` with explicit argument arrays (no shell interpolation), and streams JSON/JSONL over `stdin`/`stdout`.
- **Optional Runtime Collector** (disabled by default): Subscribes to `QueryExecuted`, `JobProcessing`, `JobFailed`, `JobProcessed`, `RequestHandled`, and exception events with sampling, bounded local JSONL storage, no query bindings by default, and no request bodies.

### B. Rust Diagnostic Engine (`crates/*`)

- **`incidentlens-core`**: Protocol v1 request/response/event structs, severity/confidence enums, finding model, secret redaction patterns, safe path validation, and exit codes.
- **`incidentlens-parser`**: Streaming, bounded-memory Monolog/Laravel log parser (standard, daily, single, JSON logs, multiline stack traces, nested exceptions, malformed entry fallback) + exception message normalizer + stable SHA-256/BLAKE3 fingerprinting.
- **`incidentlens-analyzer`**: Modular analyzers for Project, Logs, Database, Queue, Performance, Security, Migrations, and Dependencies. Uses `rayon` for parallelizable workloads (e.g., multi-file log scanning).
- **`incidentlens-correlator`**: Rule-based cross-module correlation engine connecting slow requests, repeated query fingerprints, exceptions, queue failures, and deployment snapshot diffs into evidence-backed incidents.
- **`incidentlens-storage`**: Local snapshot storage, incremental log offset tracking, and retention cleanup.
- **`incidentlens-reporter`**: Renders findings and incidents to JSON, Markdown, HTML, and non-interactive terminal tables.
- **`incidentlens-tui`**: Interactive Ratatui + Crossterm application with responsive layout, module navigation, search/filter, expandable findings, help overlay, `NO_COLOR` support, and clean terminal teardown.
- **`incidentlens-cli`**: Clap-based CLI entry point supporting both standalone execution in a Laravel directory and piped/invoked execution from PHP Artisan.

---

## 4. Security & Privacy Architecture

- **No secret leakage**: Secret redaction runs in both PHP (before export) and Rust (defense-in-depth on log/config ingestion).
- **No arbitrary command execution**: PHP uses array-based process arguments; Rust never executes shell commands parsed from logs or project files.
- **Path & symlink safety**: All target paths are canonicalized and checked against allowed project/storage boundaries; max file size / bounded streaming prevents resource exhaustion.
- **Read-only by default**: No `EXPLAIN`, no migrations, no queue retries/deletes, no config edits without explicit future opt-in.
