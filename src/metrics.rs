use metrics::{counter, histogram};
use std::time::Instant;

pub fn measure_operation<T, F>(operation_name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();

    let duration_histogram =
        histogram!("operation_duration", "operation" => operation_name.to_string());
    duration_histogram.record(duration);

    let operation_count = counter!("operation_count", "operation" => operation_name.to_string());
    operation_count.increment(1);

    eprintln!("Operation: {} took {:?}", operation_name, duration);

    result
}
