# Laravel IncidentLens

**Laravel IncidentLens** (`gaurav/laravel-incidentlens`) is an offline-first, read-only-by-default diagnostic tool for Laravel applications, powered by a Rust diagnostic engine and a lightweight Laravel Composer package.

> **Status**: Phase 1 (Foundation) — Project detection, PHP-to-Rust protocol `v1.0`, CLI diagnostics (`status`, `scan`, `doctor`, `version`, `protocol`), and Laravel Artisan integration.

---

## Architecture

- **Laravel Package (`packages/laravel`)**: Lightweight project metadata inspection (with secret redaction), binary discovery, protocol handshaking, and Artisan commands (`incidentlens:doctor`, `incidentlens:status`, `incidentlens:scan`).
- **Rust Diagnostic Engine (`crates/`)**:
  - `incidentlens-core`: Protocol `v1.0` schemas, exit codes, secret redaction, path validation.
  - `incidentlens-analyzer`: Project structure and configuration diagnostics.
  - `incidentlens-cli`: `incidentlens` CLI executable.

See [docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md) for details.

---

## Quick Start (Development)

### Build the Rust Engine

```bash
cargo build --release
```

### Run PHP Package Tests

```bash
cd packages/laravel
composer install
composer test
```

### CLI Usage

```bash
incidentlens status --project /path/to/laravel-app
incidentlens scan --project /path/to/laravel-app --format=json
incidentlens doctor --project /path/to/laravel-app
incidentlens protocol
```

---

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success; no CI threshold-breaking findings |
| `1` | Findings exceeded CI thresholds (`--ci`) |
| `2` | Invalid arguments or malformed protocol input |
| `3` | Internal engine error |
| `4` | Unsupported or incompatible project / protocol version |

---

## License

MIT — see [LICENSE](LICENSE).
