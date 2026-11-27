# Testing Strategy

## 1. Philosophy

No feature is complete until it compiles, has automated tests, passes all checks, and has been verified against realistic inputs. Failing tests are never removed or relaxed to make a build pass.

---

## 2. Test Layers

### A. Rust Tests (`cargo test`, `cargo clippy`, `cargo fmt --check`)
- **Unit tests**: Protocol serialization/deserialization, malformed JSON handling, secret redaction, path validation, project detection rules, log entry parsing, fingerprinting stability.
- **Integration tests**: End-to-end CLI invocations (`assert_cmd` / `std::process::Command`) verifying stdout JSON, stderr diagnostics, and exact exit codes (`0`, `1`, `2`, `3`, `4`).
- **Benchmarks (`criterion`)**: Large-file log parsing (100MB–5GB), peak memory, throughput (MB/s), and fingerprinting speed (Phase 2 & Phase 8).

### B. PHP Package Tests (`vendor/bin/pest` / `vendor/bin/phpunit`)
- **Orchestra Testbench**: Service provider registration, config merging/validation, Artisan command registration.
- **Engine Bridge tests**: Binary discovery order, argument escaping, protocol version handshake, graceful error handling when binary is missing or incompatible.
- **Security & Redaction tests**: Verify sensitive keys (`APP_KEY`, `DB_PASSWORD`, tokens) are never exposed in exported project metadata.
- **Runtime Collector tests** (Phase 4+): Verify disabled-by-default behavior, sampling, bounded storage, and zero binding collection by default.

### C. End-to-End Verification
- Install `gaurav/laravel-incidentlens` into a real sample Laravel application.
- Verify package discovery, `incidentlens:doctor`, `incidentlens:status`, `incidentlens:scan`, CI exit codes, and report generation.

---

## 3. Phase 1 Verification Checklist
1. `cargo fmt --check` & `cargo clippy --all-targets -- -D warnings`
2. `cargo test --workspace`
3. `composer install` & `vendor/bin/pest` (or `phpunit`) inside `packages/laravel`
4. Live CLI smoke test against a Laravel fixture directory (`incidentlens status`, `incidentlens scan --format=json`, `incidentlens doctor`)
