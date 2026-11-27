# Laravel IncidentLens — Implementation Roadmap

## Phase 1: Foundation (Current Target)

**Goal**: Monorepo, Composer package skeleton, Rust workspace, CLI executable, Laravel project detection, PHP-to-Rust protocol v1, version checking, and basic terminal/JSON output.

**Deliverables**:
- Monorepo layout (`packages/laravel`, `crates/*`, `protocols/`, `fixtures/`, `docs/`).
- `crates/incidentlens-core` with protocol v1 types, exit codes, secret redactor, and finding model.
- `crates/incidentlens-analyzer` with `ProjectAnalyzer` (detects Laravel project structure, `composer.json`, `.env` key names without printing secrets, directory layout, basic config checks).
- `crates/incidentlens-cli` with `incidentlens` binary (`status`, `scan`, `doctor`, `version`, `protocol` subcommands + `--format=json` / `--project` / `--no-interaction` flags).
- `packages/laravel` (`gaurav/laravel-incidentlens`) with `IncidentLensServiceProvider`, `config/incidentlens.php`, `EngineClient` (binary detection + protocol handshake + safe `Process` invocation), `ProjectInspector`, and Artisan commands (`incidentlens:status`, `incidentlens:doctor`, `incidentlens:scan`).
- Tests: Rust unit/integration tests (`cargo test`) + PHP Pest/Orchestra Testbench tests.

**Acceptance Criteria**:
- A developer can install/load the package, run the CLI (`incidentlens` / `php artisan incidentlens:status`), detect a Laravel project, verify protocol compatibility, and see working terminal & JSON output.

---

## Phase 2: Log Intelligence
- `incidentlens-parser`: Streaming Laravel/Monolog log parser (standard, daily, JSON logs, multiline stack traces, nested exceptions, malformed fallback).
- Exception normalization, stable fingerprinting, duplicate grouping, spike detection, `--follow`, `--since`, `--level`, `--search`, `--fingerprint`.
- Large file streaming benchmarks.

## Phase 3: Interactive TUI
- `incidentlens-tui` using Ratatui + Crossterm: Main dashboard, 10 module views, keyboard navigation, search/filter, expandable findings, help modal, responsive resize, `NO_COLOR`, non-interactive CI fallback.

## Phase 4: Database & Queue Intelligence
- Optional runtime collectors in PHP (`QueryExecuted`, `JobProcessing`, `JobFailed`, `JobProcessed`) with bounded JSONL storage and no bindings by default.
- Rust analyzers for slow queries, query fingerprinting, observed N+1 detection, failed job grouping, retry/timeout patterns.

## Phase 5: Performance & Incident Correlation
- Request lifecycle timing collector + P50/P95/P99 performance analyzer.
- `incidentlens-correlator`: Rule-based cross-module correlation engine linking slow requests, repeated queries, exceptions, and queue events with confidence levels.

## Phase 6: Deployment & Regression Intelligence
- `incidentlens-storage`: Diagnostic snapshots and Git revision comparison (`incidentlens compare`).
- Regression engine for new/resolved errors, query growth, and latency regressions.

## Phase 7: Security, Migration & Dependency Intelligence
- Read-only security configuration & exposed file checks.
- Migration file AST/regex risk analyzer (destructive ops, missing `down()`).
- Composer audit / outdated / abandoned dependency integration.

## Phase 8: Production Readiness
- Cross-platform release builds (Linux x86_64/ARM64, macOS Intel/Apple Silicon, Windows x86_64) with SHA-256 checksum manifests.
- Full `incidentlens install` binary verification flow.
- Criterion benchmarks (100MB–5GB logs), end-to-end sample Laravel app verification, full GitHub Actions CI/CD, and complete user documentation.
