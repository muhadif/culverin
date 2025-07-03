use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::time::Duration;

use crate::models::{Metrics, Result as AttackResult};
use crate::utils::{format_duration, format_size, get_reader, get_writer};

/// Run the report command with the given arguments
pub async fn run(
    buckets: Option<String>,
    every: Option<humantime::Duration>,
    output: String,
    report_type: String,
) -> Result<()> {
    // Get reader and writer
    let reader = get_reader("stdin")?;
    let mut writer = get_writer(&output)?;

    // Parse buckets if provided
    let buckets = match buckets {
        Some(b) => parse_buckets(&b)?,
        None => vec![],
    };

    // Generate report based on the specified type
    if report_type.starts_with("hist[") && report_type.ends_with("]") {
        // Extract buckets from report type
        let buckets_str = &report_type[5..report_type.len() - 1];
        let buckets = parse_buckets(buckets_str)?;
        generate_histogram_report(reader, &mut writer, &buckets)?;
    } else {
        match report_type.as_str() {
            "text" => generate_text_report(reader, &mut writer, every)?,
            "json" => generate_json_report(reader, &mut writer, every)?,
            "hdrplot" => generate_hdrplot_report(reader, &mut writer)?,
            _ => anyhow::bail!("Unsupported report type: {}", report_type),
        }
    }

    Ok(())
}

/// Parse histogram buckets from a string like "[0,1ms,10ms]"
fn parse_buckets(buckets_str: &str) -> Result<Vec<Duration>> {
    let inner = buckets_str.trim_start_matches('[').trim_end_matches(']');
    let parts: Vec<&str> = inner.split(',').collect();

    let mut buckets = Vec::new();
    for part in parts {
        let part = part.trim();
        if part == "0" {
            buckets.push(Duration::from_secs(0));
        } else {
            let duration = humantime::parse_duration(part)
                .map_err(|_| anyhow::anyhow!("Invalid duration: {}", part))?;
            buckets.push(duration.into());
        }
    }

    Ok(buckets)
}

/// Generate a text report from attack results
fn generate_text_report<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    interval: Option<humantime::Duration>,
) -> Result<()> {
    // Parse results
    let results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    if results.is_empty() {
        writeln!(writer, "No results to report")?;
        return Ok(());
    }

    // Calculate metrics
    let metrics = calculate_metrics(&results);

    // Write report
    writeln!(writer, "Requests:\t{}", metrics.requests)?;
    writeln!(writer, "Duration:\t{}", format_duration(metrics.duration))?;
    writeln!(writer, "Rate:\t\t{:.2} req/s", metrics.rate)?;
    writeln!(writer, "Success:\t{} ({:.2}%)", metrics.success, metrics.success_rate * 100.0)?;
    writeln!(writer, "Min:\t\t{}", format_duration(metrics.min))?;
    writeln!(writer, "Mean:\t\t{}", format_duration(metrics.mean))?;
    writeln!(writer, "50th percentile:\t{}", format_duration(metrics.p50))?;
    writeln!(writer, "90th percentile:\t{}", format_duration(metrics.p90))?;
    writeln!(writer, "95th percentile:\t{}", format_duration(metrics.p95))?;
    writeln!(writer, "99th percentile:\t{}", format_duration(metrics.p99))?;
    writeln!(writer, "Max:\t\t{}", format_duration(metrics.max))?;
    writeln!(writer, "Bytes in:\t{}", format_size(metrics.bytes_in))?;
    writeln!(writer, "Bytes out:\t{}", format_size(metrics.bytes_out))?;

    Ok(())
}

/// Generate a JSON report from attack results
fn generate_json_report<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    interval: Option<humantime::Duration>,
) -> Result<()> {
    // Parse results
    let results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    if results.is_empty() {
        writeln!(writer, "{{}}")?;
        return Ok(());
    }

    // Calculate metrics
    let metrics = calculate_metrics(&results);

    // Write report
    serde_json::to_writer_pretty(writer, &metrics)?;

    Ok(())
}

/// Generate a histogram report from attack results
fn generate_histogram_report<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    buckets: &[Duration],
) -> Result<()> {
    // Parse results
    let results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    if results.is_empty() {
        writeln!(writer, "No results to report")?;
        return Ok(());
    }

    // Extract latencies
    let latencies: Vec<u64> = results
        .iter()
        .map(|r| r.latency.as_micros() as u64)
        .collect();

    // Write header
    writeln!(writer, "Bucket\t\tCount\t\tPercentage")?;

    // Write buckets
    let mut prev_bucket = 0;
    for bucket in buckets {
        let micros = bucket.as_micros() as u64;

        // Count values in range
        let count = latencies.iter()
            .filter(|&&lat| lat >= prev_bucket && lat < micros)
            .count();

        let percentage = (count as f64 / results.len() as f64) * 100.0;

        writeln!(
            writer,
            "[{} - {}]\t{}\t\t{:.2}%",
            format_duration(Duration::from_micros(prev_bucket)),
            format_duration(*bucket),
            count,
            percentage
        )?;

        prev_bucket = micros;
    }

    // Write last bucket
    let count = latencies.iter()
        .filter(|&&lat| lat >= prev_bucket)
        .count();

    let percentage = (count as f64 / results.len() as f64) * 100.0;

    writeln!(
        writer,
        "[{} - inf]\t{}\t\t{:.2}%",
        format_duration(Duration::from_micros(prev_bucket)),
        count,
        percentage
    )?;

    Ok(())
}

/// Generate an HDR plot report from attack results
fn generate_hdrplot_report<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
) -> Result<()> {
    // Parse results
    let results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    if results.is_empty() {
        writeln!(writer, "No results to report")?;
        return Ok(());
    }

    // Extract and sort latencies
    let mut latencies: Vec<Duration> = results.iter().map(|r| r.latency).collect();
    latencies.sort();

    // Generate percentiles
    let percentiles = [
        0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 95.0, 99.0, 99.9, 99.99, 100.0,
    ];

    // Write header
    writeln!(writer, "Percentile\tLatency")?;

    // Write percentiles
    for p in percentiles {
        let value = percentile(&latencies, p / 100.0);
        writeln!(
            writer,
            "{:.2}%\t\t{}",
            p,
            format_duration(value)
        )?;
    }

    Ok(())
}

/// Calculate metrics from attack results
fn calculate_metrics(results: &[AttackResult]) -> Metrics {
    if results.is_empty() {
        return Metrics {
            requests: 0,
            success: 0,
            duration: Duration::from_secs(0),
            min: Duration::from_secs(0),
            max: Duration::from_secs(0),
            mean: Duration::from_secs(0),
            p50: Duration::from_secs(0),
            p90: Duration::from_secs(0),
            p95: Duration::from_secs(0),
            p99: Duration::from_secs(0),
            rate: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            success_rate: 0.0,
        };
    }

    // Sort results by latency for percentile calculations
    let mut sorted_latencies: Vec<Duration> = results.iter().map(|r| r.latency).collect();
    sorted_latencies.sort();

    // Calculate basic metrics
    let requests = results.len();
    let success = results.iter().filter(|r| r.status_code >= 200 && r.status_code < 300).count();

    // Calculate duration (time between first request and last response)
    let first_timestamp = results.iter().map(|r| r.timestamp).min().unwrap();
    let last_timestamp = results.iter().map(|r| r.timestamp).max().unwrap();
    let duration = Duration::from_secs((last_timestamp - first_timestamp).num_seconds() as u64);

    // Calculate latency metrics
    let min = *sorted_latencies.first().unwrap();
    let max = *sorted_latencies.last().unwrap();

    let mean = if requests > 0 {
        let sum: Duration = sorted_latencies.iter().sum();
        sum / requests as u32
    } else {
        Duration::from_secs(0)
    };

    // Calculate percentiles
    let p50 = percentile(&sorted_latencies, 0.5);
    let p90 = percentile(&sorted_latencies, 0.9);
    let p95 = percentile(&sorted_latencies, 0.95);
    let p99 = percentile(&sorted_latencies, 0.99);

    // Calculate rate
    let rate = if duration.as_secs_f64() > 0.0 {
        requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    // Calculate bytes
    let bytes_in: usize = results.iter().map(|r| r.bytes_in).sum();
    let bytes_out: usize = results.iter().map(|r| r.bytes_out).sum();

    // Calculate success rate
    let success_rate = if requests > 0 {
        success as f64 / requests as f64
    } else {
        0.0
    };

    Metrics {
        requests,
        success,
        duration,
        min,
        max,
        mean,
        p50,
        p90,
        p95,
        p99,
        rate,
        bytes_in,
        bytes_out,
        success_rate,
    }
}

/// Calculate a percentile from a sorted list of durations
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::from_secs(0);
    }

    let index = (sorted.len() as f64 * p).ceil() as usize - 1;
    sorted[index.min(sorted.len() - 1)]
}
