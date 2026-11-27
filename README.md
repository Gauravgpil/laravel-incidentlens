# Laravel IncidentLens

**Laravel IncidentLens** (`incidentlens/laravel`) is an offline-first, read-only-by-default, Rust-powered diagnostic engine and interactive Ratatui TUI for Laravel applications.

---

## Capabilities

- **Interactive Enterprise TUI (`incidentlens`)**: Ratatui + Crossterm terminal dashboard with 10 diagnostic modules, KPI health strip, severity filters, live search (`/`), evidence inspector modal (`Enter`), and CI/non-TTY fallback.
- **Log Intelligence**: Streaming Monolog/daily/JSONL parser, multiline stack traces, exception normalization, stable SHA-256 fingerprinting, and duplicate grouping.
- **Database & Queue Intelligence**: Optional, disabled-by-default Laravel runtime collectors (`QueryExecuted`, `JobProcessing`, `JobProcessed`, `JobFailed`, `RequestHandled`) with SQL literal normalization (no bindings collected by default), slow query & observed N+1 detection.
- **Performance & Incident Correlation**: P50/P95/P99 latency metrics and cross-module correlation engine linking slow requests, repeated query fingerprints, log errors, and queue failures with evidence-backed confidence.
- **Deployment & Regression Intelligence**: Diagnostic snapshots (`incidentlens snapshot`) and diffing (`incidentlens compare`).
- **Security, Migration & Dependency Intelligence**: Read-only `.env`/webroot checks, static migration risk detection (`dropIfExists`, `dropColumn`, missing `down()`), and Composer manifest constraint checks.
- **Multi-Format Reporting**: Colorful ANSI terminal output, JSON (`--format=json`), Markdown (`--format=markdown`), and styled HTML (`--format=html`).

---

## Commands

```bash
incidentlens                                  # Launch interactive TUI (or plain status in CI)
incidentlens scan --ci --format=json          # Full diagnostic scan for CI
incidentlens preflight --ci                   # Pre-deployment readiness check ([PASS]/[WARN]/[FAIL])
incidentlens incident                         # Production incident timeline & correlation mode
incidentlens logs --level=error --follow      # Filter, group, or tail log exceptions
incidentlens code                             # Static code intelligence (routes, controllers, models, exceptions)
incidentlens database --slow-ms=500           # Analyze query fingerprints & N+1 patterns
incidentlens api                              # API routes, 5xx error rates, latency & throttle checks
incidentlens queue                            # Analyze queue job failures
incidentlens cache                            # Cache driver & hit/miss ratio diagnostics
incidentlens scheduler                        # Scheduled task overlap protection checks
incidentlens performance --slow-ms=1000       # Endpoint P50/P95/P99 & external HTTP analysis
incidentlens security                         # Read-only security checks
incidentlens migration                        # Static migration risk scan
incidentlens dependencies                     # Composer constraint checks
incidentlens snapshot pre-deploy              # Save diagnostic snapshot
incidentlens compare pre-deploy post-deploy   # Compare snapshots for regressions
incidentlens report --format=html -o out.html # Export HTML/Markdown/JSON/CSV report
incidentlens doctor                           # Verify engine & Laravel project readiness
```

Laravel Artisan commands:

```bash
php artisan incidentlens:doctor
php artisan incidentlens:status
php artisan incidentlens:scan --ci
```

---

## Development & Testing

```bash
# Rust workspace tests & benchmarks
cargo test --workspace
cargo bench -p incidentlens-parser

# Laravel package tests (PHPUnit + Orchestra Testbench)
cd packages/laravel
composer install
composer test
```

See [docs/architecture.md](docs/architecture.md), [docs/protocol.md](docs/protocol.md), [docs/compatibility-and-risks.md](docs/compatibility-and-risks.md), and [docs/testing-strategy.md](docs/testing-strategy.md).

## License

MIT — see [LICENSE](LICENSE).
