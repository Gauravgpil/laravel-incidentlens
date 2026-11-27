# Laravel IncidentLens — PHP-to-Rust Communication Protocol (`v1`)

## 1. Transport & Process Contract

- **Invocation**: PHP invokes the `incidentlens` binary directly using `Symfony\Component\Process\Process` with an argument array (never shell string interpolation).
- **Streams**:
  - `stdin`: Structured JSON request envelope or streaming JSONL events.
  - `stdout`: Machine-readable JSON response (when `--format=json` or `--protocol=v1`) or human-readable output in interactive/CLI mode.
  - `stderr`: Engine diagnostics, tracing logs, and structured fatal errors.
- **Cancellation**: `SIGTERM` / `SIGINT` triggers graceful shutdown, flushing partial/valid state if applicable and restoring terminal state if TUI is active.

---

## 2. Protocol Versioning

Every payload includes `protocol_version: "1.0"`.

- **Handshaking**: PHP can query `incidentlens protocol --json` (or `incidentlens version --json`) to verify:
  - `engine_version` (SemVer, e.g. `0.1.0`)
  - `protocol_version` (e.g. `1.0`)
  - `supported_protocols` (e.g. `["1.0"]`)
- **Compatibility Rule**: Major version must match (`1.x` <-> `1.y`). Unknown optional fields in JSON are ignored (`#[serde(default)]`) for forward compatibility; missing required fields fail with exit code `2`.

---

## 3. Request Envelope (PHP -> Rust)

```json
{
  "protocol_version": "1.0",
  "command": "scan",
  "project": {
    "root": "/var/www/app",
    "name": "my-laravel-app",
    "laravel_version": "11.0.0",
    "php_version": "8.3.12",
    "environment": "local",
    "debug": true,
    "drivers": {
      "cache": "redis",
      "queue": "redis",
      "database": "mysql",
      "session": "redis",
      "log": "stack"
    },
    "log_paths": [
      "/var/www/app/storage/logs/laravel.log"
    ],
    "config_flags": {
      "app_key_set": true,
      "app_debug": true
    }
  },
  "options": {
    "since": "24h",
    "limit": 100,
    "modules": ["project", "logs"]
  }
}
```

### Streaming JSONL Mode

For large runtime event datasets or log streams, PHP or collectors pass `--input-format=jsonl` and stream one JSON object per line on `stdin` (or from a bounded local `.jsonl` file path):

```json
{"protocol_version":"1.0","type":"query","timestamp":"2026-11-27T09:00:00Z","duration_ms":612.4,"sql_normalized":"select * from orders where user_id = ?","connection":"mysql","request_id":"req_abc123"}
{"protocol_version":"1.0","type":"request","timestamp":"2026-11-27T09:00:00Z","method":"GET","route":"/checkout","status":200,"duration_ms":2104.2,"memory_peak_bytes":33554432,"request_id":"req_abc123"}
```

---

## 4. Response Envelope (Rust -> PHP / CLI `--format=json`)

```json
{
  "protocol_version": "1.0",
  "engine_version": "0.1.0",
  "status": "ok",
  "summary": {
    "errors": 12,
    "warnings": 8,
    "performance": 4,
    "security": 2
  },
  "findings": [
    {
      "id": "f_01",
      "module": "project",
      "title": "Debug mode enabled in production configuration",
      "severity": "high",
      "confidence": "high",
      "affected_component": "config/app.php (app.debug)",
      "evidence": [
        {
          "kind": "observed",
          "source": "project_inspector",
          "detail": "app.env is 'production' while app.debug is true"
        }
      ],
      "first_observed": null,
      "last_observed": null,
      "next_step": "Set APP_DEBUG=false in production environment configuration."
    }
  ],
  "incidents": [],
  "errors": []
}
```

---

## 5. Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success; no CI threshold-breaking findings |
| `1` | Diagnostic findings exceeded configured CI thresholds |
| `2` | Invalid arguments, malformed protocol input, or invalid configuration |
| `3` | Internal engine error |
| `4` | Unsupported or incompatible project / protocol version |
