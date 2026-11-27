# Compatibility Matrix & Technical Risks

## 1. Compatibility Matrix

| Component | Supported Versions / Targets | Notes |
| :--- | :--- | :--- |
| **PHP** | `^8.2`, `^8.3`, `^8.4`, `^8.5` | Tested locally on PHP 8.5.13 |
| **Laravel** | `^10.0`, `^11.0`, `^12.0` (and `13.x` when released) | Via Orchestra Testbench & `illuminate/*` contracts |
| **Rust Toolchain** | Rust `stable` (MSRV `1.80+`) | Edition `2021` |
| **OS / Arch** | Linux (`x86_64`, `aarch64`), macOS (`x86_64`, `aarch64`), Windows (`x86_64`) | Cross-platform path & process handling |
| **Protocol** | `1.0` | Major version must match between PHP package and Rust binary |

---

## 2. Technical Risks & Mitigations

1. **Rust Toolchain Availability in Current Environment**
   - *Observation*: During environment inspection, `php` (8.5.13), `composer` (2.11.2), and `git` (2.56.1) are installed, while `rustc` and `cargo` are not currently present in `$PATH`.
   - *Impact*: Compiling and running `cargo test` for the Rust crates requires `rustc`/`cargo` to be available (via `rustup` or system packages) when Phase 1 execution begins.
   - *Mitigation*: Check/install Rust toolchain or verify build environment before marking Phase 1 acceptance criteria as passed; never mark Rust tests as passing without actually executing `cargo test`.

2. **PHP 8.5 + Orchestra Testbench / Pest Compatibility**
   - *Risk*: Some older Pest or Testbench releases may emit deprecation notices on PHP 8.5.
   - *Mitigation*: Pin modern compatible versions in `packages/laravel/composer.json` (e.g., `orchestra/testbench: ^9.0|^10.0`, `pestphp/pest: ^3.0` or `phpunit/phpunit: ^11.0`) and verify with `composer test`.

3. **Binary Distribution & Path Resolution Across Platforms**
   - *Risk*: Developers running `php artisan incidentlens:*` or `incidentlens` directly need reliable binary discovery without requiring a global Rust toolchain.
   - *Mitigation*: Implement ordered binary resolution (`config('incidentlens.engine.binary')` -> project `vendor/bin` -> package `bin/<os>-<arch>` -> `PATH`), with clear actionable error messages and checksum verification in `install`.

4. **Secret Leakage in Logs & Configs**
   - *Risk*: `.env` values, DB DSNs, or stack trace frames may contain credentials.
   - *Mitigation*: Never read/print raw `.env` values (only key names); apply regex/heuristic redaction in both PHP and Rust before output or storage.

5. **Large Log Memory Exhaustion**
   - *Risk*: Loading multi-GB logs into memory causes OOM.
   - *Mitigation*: Use buffered streaming readers (`BufReader`) and bounded line/entry buffers in `incidentlens-parser` from Phase 2 onward.
