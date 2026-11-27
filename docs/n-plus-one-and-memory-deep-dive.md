# Deep Technical Analysis & Implementation Roadmap: N+1 Queries & Memory Overflow Prevention

## 1. Executive Summary

This document presents a comprehensive audit of **N+1 query detection** and **memory overflow prevention** across two dimensions:
1. **IncidentLens Engine & Package Internals** (Rust parser/analyzer + PHP `RuntimeCollector`) — ensuring IncidentLens itself can process multi-GB logs and high-throughput runtime telemetry in strictly bounded memory (`O(unique_fingerprints + limit)` rather than `O(total_lines)`), and remain leak-free under Laravel Octane and long-lived queue workers.
2. **Target Laravel Application Diagnostics** — extending IncidentLens to detect both **static** (codebase/Blade/ServiceProvider) and **runtime** N+1 queries and memory-exhaustion anti-patterns in Laravel 10/11/12 applications.

---

## 2. Part A: Audit of IncidentLens Internals (Memory & N+1 Gaps)

### 2.1 Memory Overflow Risks in the Rust Engine

| Component & Location | Root Cause | Impact at Scale (1–5 GB Logs / High Traffic) | Remediation |
| :--- | :--- | :--- | :--- |
| `crates/incidentlens-parser/src/log_parser.rs` (`parse_log_file`) | `entries: Vec<LogEntry>` accumulates *every* matching entry in memory and only calls `entries.truncate(limit)` after EOF. | On a 5 GB log with 5M error entries, `entries` consumes several GB of RAM even when `--limit=100` or when only `groups` are needed. | Replace with **streaming aggregation**: group directly into `HashMap<String, LogGroup>` (capped at `MAX_GROUPS`, e.g., 50,000, with LRU/overflow bucket) and maintain a bounded `BinaryHeap` / ring buffer of size `limit` for recent sample entries. |
| `crates/incidentlens-parser/src/log_parser.rs` (`parse_log_files_parallel`) | Collects full `Vec<LogEntry>` from every Rayon worker thread and sorts all entries in memory. | Peak memory = sum of all files' entries across threads. | Merge `HashMap<String, LogGroup>` per file (commutative monoid merge) and keep only top-`limit` entries via k-way merge. |
| `crates/incidentlens-parser/src/runtime_parser.rs` (`parse_runtime_jsonl`) | Loads all `RuntimeEvent` structs from `runtime.jsonl` into a single `Vec<RuntimeEvent>`. | High-traffic `runtime.jsonl` (10 MB+) creates unnecessary heap allocations and duplicates strings (`sql_normalized`, `request_id`). | Introduce a **streaming visitor/fold API** (`stream_runtime_jsonl(path, |ev| ...)`) so `DatabaseAnalyzer`, `QueueAnalyzer`, `PerformanceAnalyzer`, and `CorrelationEngine` process events in a single pass with `O(unique_fingerprints + active_requests)` memory. |
| `crates/incidentlens-analyzer/src/database.rs` (`per_request` map) | `HashMap<(String, String), usize>` stores every `(request_id, query_fp)` pair seen across the entire file. | Unbounded growth if millions of unique `request_id`s are analyzed. | Use a bounded window / LRU or evict completed `request_id`s once `Request` end event is seen in the stream. |

### 2.2 Memory Leak & Overhead Risks in the PHP Package

| Component & Location | Root Cause | Impact | Remediation |
| :--- | :--- | :--- | :--- |
| `packages/laravel/src/Collectors/RuntimeCollector.php` (`$currentRequestId`, `$jobStartTimes`) | `$currentRequestId` is generated once in `register()`, and `$jobStartTimes` is only unset on `JobProcessed`/`JobFailed`. | Under **Laravel Octane** (long-lived workers), `$currentRequestId` is shared across multiple HTTP requests, corrupting N+1 correlation! In **queue workers**, timed-out/killed jobs leave stale entries in `$jobStartTimes`. | 1. Reset `$currentRequestId` on `Octane\Events\RequestReceived` and `RequestHandled`.<br>2. Cap `$jobStartTimes` (e.g., max 1,000 entries, evicting oldest) and reset on `JobExceptionOccurred`. |
| `RuntimeCollector.php` (`appendEvent`) | Calls `file_put_contents(..., FILE_APPEND \| LOCK_EX)` per event. | Under high query volume, synchronous file locking per SQL query adds I/O latency to every request. | Buffer events in memory per request (capped at e.g. 500 events/request) and flush once in `RequestHandled` / `terminating()` (or immediately for queue jobs), reducing syscalls by ~20–50x. |

### 2.3 N+1 Detection Blind Spots in IncidentLens

1. **No PHP Call-Site Origin for Runtime N+1s**: `DatabaseAnalyzer` knows *which SQL* repeated 35 times in `req_123`, but not *which PHP file & line* triggered it.
2. **No Static N+1 Analysis**: When `RuntimeCollector` is disabled (the default), IncidentLens does not flag obvious N+1 patterns in `app/` or `resources/views/*.blade.php`.
3. **No `LazyLoadingViolation` Hook**: Laravel 10–12's `Model::handleLazyLoadingViolationUsing(...)` is not yet integrated as an optional lightweight collector source.

---

## 3. Part B: Deep Technical Analysis of Laravel N+1 & Memory Overflow

### 3.1 Taxonomy of N+1 Queries in Laravel

1. **Classic Loop Lazy-Loading**: `foreach ($orders as $order) { $order->customer->name; }` without `with('customer')`.
2. **Nested / Polymorphic N+1**: `with('items')` loaded, but `$item->product->category` lazy-loaded inside nested loop (`morphTo` / `hasManyThrough`).
3. **Blade / API Resource N+1**: Hidden lazy-loading inside `JsonResource::toArray()` or `@foreach` in `.blade.php` templates.
4. **Aggregate N+1 (`->count()` / `->sum()` on Relations)**: `$post->comments->count()` loads every `Comment` model into memory just to count them, instead of `Post::withCount('comments')`.
5. **Query-in-Loop Anti-Pattern**: Calling `User::find($id)`, `Model::where(...)->first()`, or `DB::table(...)` inside `foreach`/`for`/`while`.
6. **Accessor / `$appends` Hidden N+1**: Model `$appends = ['author_name']` accessing `$this->author->name` on every serialized model.

### 3.2 Taxonomy of Memory Overflow in Laravel / PHP

1. **Unbounded Eloquent Hydration (`Model::all()` / `->get()`)**: Hydrating 100k+ Eloquent models exhausts PHP `memory_limit` due to model attributes, `$original`, `$relations`, and event dispatcher overhead.
   - *Fix*: `lazyById(1000)` or `cursor()` (or `toBase()` / `DB::table()` for read-only exports).
2. **`chunk()` Offset Trap**: `chunk()` uses `OFFSET`/`LIMIT` (`O(N^2)` DB scan) and skips rows when updating the filtered column.
   - *Fix*: Keyset pagination via `chunkById()` / `lazyById()`.
3. **Laravel Query Log Leak**: `DB::enableQueryLog()` (or forgetting `DB::connection()->disableQueryLog()` in long-running Artisan commands/jobs) stores every SQL string + bindings in memory indefinitely.
4. **Eloquent Relation Cache Retention**: Inside long loops, `$model->setRelation(...)` retains child models until `$model->unsetRelations()` + `gc_collect_cycles()` are called.
5. **MySQL Buffered Queries (`PDO::MYSQL_ATTR_USE_BUFFERED_QUERY`)**: Default buffered queries load entire result sets into PHP C-level memory before `cursor()` even yields row 1.
6. **Laravel Octane State Leaks**: Mutable `static` properties, singleton services holding request arrays, or `APP_DEBUG=true` in production.

---

## 4. Comprehensive Implementation Roadmap (Next Phase)

### Phase N1-M1: Streaming & Bounded Memory in Rust Engine (Foundation)
- **Step 1**: Refactor `incidentlens-parser/src/log_parser.rs` to stream directly into `HashMap<String, LogGroup>` (with `MAX_UNIQUE_GROUPS = 50_000` cap) + bounded `VecDeque`/`BinaryHeap` of size `limit` for sample entries. Peak memory becomes `O(unique_groups + limit)` regardless of 5 GB+ file size.
- **Step 2**: Add `stream_runtime_jsonl` in `runtime_parser.rs` and refactor `DatabaseAnalyzer`, `QueueAnalyzer`, `PerformanceAnalyzer`, and `CorrelationEngine` to consume a single streaming pass instead of materializing `Vec<RuntimeEvent>`.
- **Step 3**: Add a Criterion benchmark for 100 MB+ synthetic log streaming + peak RSS verification.

### Phase N1-M2: High-Performance & Octane-Safe `RuntimeCollector` (PHP)
- **Step 1**: Add per-request in-memory event buffering (capped at 500 events) flushed once in `RequestHandled` / `terminating()`.
- **Step 2**: Add **Octane lifecycle hooks** (`RequestReceived` / `RequestTerminated`) to reset `$currentRequestId` and request buffers cleanly.
- **Step 3**: Capture lightweight PHP call-site (`file:line` via `debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 8)`, filtering `vendor/`) **only** when a query repeats `>= 3` times in the same request (zero overhead on normal queries!).
- **Step 4**: Add optional `Model::handleLazyLoadingViolationUsing(...)` integration (opt-in via config `incidentlens.database.detect_lazy_loading`) to emit structured `lazy_loading` events into `runtime.jsonl`.

### Phase N1-M3: Static N+1 & Memory Overflow Analyzer (`crates/incidentlens-analyzer`)
- **Step 1**: Add `n_plus_one_static.rs` / extend `DatabaseAnalyzer` & `CodeAnalyzer`:
  - Check `app/Providers/AppServiceProvider.php` for `Model::preventLazyLoading(...)` — recommend enabling `! app()->isProduction()`.
  - Scan `app/Console/Commands/`, `app/Jobs/`, and `app/Services/` for `::all()` / `->get()` inside loops, `->chunk(` (recommend `chunkById`/`lazyById`), and missing `DB::disableQueryLog()` in batch commands.
  - Scan `app/` & `resources/views/*.blade.php` for `->count()` on loaded relations (`withCount()` candidate) and query calls inside `foreach` loops.
- **Step 2**: Add `APP_DEBUG=true` + Octane memory-leak severity escalation in `FrameworkAnalyzer`.

### Phase N1-M4: TUI, Reporting & Verification
- **Step 1**: Surface call-site `file:line` and Eloquent fix hints (`with(...)`, `withCount(...)`, `lazyById()`, `unsetRelations()`) in the TUI Live Inspector and HTML/Markdown reports.
- **Step 2**: Add regression tests for bounded memory (`limit` on large logs), Octane request isolation, static N+1/memory pattern detection, and `LazyLoadingViolation` event ingestion.
