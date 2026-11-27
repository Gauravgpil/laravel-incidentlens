use criterion::{black_box, criterion_group, criterion_main, Criterion};
use incidentlens_parser::{parse_log_file, LogFilter};
use std::io::Write;
use tempfile::NamedTempFile;

fn bench_log_parsing(c: &mut Criterion) {
    let mut file = NamedTempFile::new().expect("temp file");
    for i in 0..10_000 {
        writeln!(
            file,
            "[2026-11-27 10:00:00] production.ERROR: Illuminate\\Database\\QueryException: Deadlock for order {i} at app/Services/OrderService.php:45"
        )
        .expect("write");
    }

    c.bench_function("parse_10k_monolog_entries", |b| {
        b.iter(|| {
            let res = parse_log_file(black_box(file.path()), &LogFilter::default()).expect("parse");
            black_box(res.groups.len());
        });
    });
}

criterion_group!(benches, bench_log_parsing);
criterion_main!(benches);
