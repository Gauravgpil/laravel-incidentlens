# Laravel IncidentLens — Feature Matrix & Dependency Map

All capabilities are classified into priority tiers so each module is built incrementally, tested, and verified before expansion:

- **P0**: Required for initial release (Core engine, Log/Project/DB/Queue/Perf/Security/Migration/Deps, TUI, Preflight, Code, API, Cache, Scheduler, Incident timeline, Snapshots, JSON/MD/HTML/CSV)
- **P1**: Next release (Extended Laravel AST/framework compatibility, Boot & Container profiling, Testing report ingestion, GitHub Actions annotations, Baseline learning)
- **P2**: Advanced capability (Application Dependency Graph, Full Request Trace spans, Technical Debt scoring, Custom YAML/TOML diagnostic rules)
- **P3**: Experimental / future (Optional local AI explanation provider, Multi-project TUI, Plugin SDK)

---

## Feature Classification Matrix

| Module | Tier | Status | Dependencies |
| :--- | :--- | :--- | :--- |
| Project Intelligence & Config Drift | P0 | **Implemented** | `incidentlens-core` |
| Log Intelligence (Monolog/JSONL, Fingerprinting, Follow) | P0 | **Implemented** | `incidentlens-core`, `incidentlens-parser` |
| Interactive Ratatui TUI (Gauge, Sparkline, Split Inspector) | P0 | **Implemented** | `incidentlens-core`, `incidentlens-tui` |
| Database & Eloquent Intelligence (Slow, N+1, Fingerprints) | P0 | **Implemented** | `incidentlens-parser` |
| Queue & Background Job Intelligence | P0 | **Implemented** | `incidentlens-parser` |
| Performance Intelligence (P50/P95/P99, Memory, External HTTP) | P0 | **Implemented** | `incidentlens-parser` |
| Incident Correlation Engine | P0 | **Implemented** | `incidentlens-analyzer`, `incidentlens-parser` |
| Security & Vulnerability Static Checks | P0 | **Implemented** | `incidentlens-core` |
| Migration Risk Intelligence | P0 | **Implemented** | `incidentlens-core` |
| Dependency Constraint Intelligence | P0 | **Implemented** | `incidentlens-core` |
| Deployment Readiness Scanner (`preflight`) | P0 | **Implemented** | `ProjectAnalyzer`, `MigrationAnalyzer`, `SecurityAnalyzer` |
| Production Incident Mode (`incident` timeline) | P0 | **Implemented** | `LogAnalyzer`, `CorrelationEngine`, `RuntimeEvent` |
| Advanced Code Intelligence (`code`: Routes, Controllers, Models, Exceptions) | P0 | **Implemented** | `incidentlens-core` |
| API Intelligence (`api`: API routes, latency, error rate, throttle checks) | P0 | **Implemented** | `incidentlens-parser` |
| Cache Intelligence (`cache`: driver checks, hit/miss ratio) | P0 | **Implemented** | `incidentlens-parser` |
| Scheduler Intelligence (`scheduler`: overlap & task inventory) | P0 | **Implemented** | `incidentlens-core` |
| Git Change-to-Error Candidate Correlation | P0 | **Implemented** | `LogAnalyzer`, `git` CLI (read-only) |
| Reporting (`json`, `markdown`, `html`, `csv`, ANSI) | P0 | **Implemented** | `incidentlens-core` |
| Snapshot & Regression Comparison (`snapshot`, `compare`) | P0 | **Implemented** | `incidentlens-storage` |
| Laravel Framework Compatibility & Service Provider Profiling | P1 | Planned | `ProjectInspector` |
| Testing Intelligence (PHPUnit/Pest JUnit XML ingestion) | P1 | Planned | `incidentlens-parser` |
| Application Dependency Graph & Request Trace Spans | P2 | Planned | `RuntimeCollector`, `code` |
| Optional Local AI Explanation Provider & Plugin System | P3 | Planned | `CorrelationEngine` |
