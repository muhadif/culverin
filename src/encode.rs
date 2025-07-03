use anyhow::Result;
use std::io::{BufRead, Write};

use crate::models::Result as AttackResult;
use crate::utils::{get_reader, get_writer};

/// Run the encode command with the given arguments
pub async fn run(
    output: String,
    to: String,
) -> Result<()> {
    // Get reader and writer
    let reader = get_reader("stdin")?;
    let mut writer = get_writer(&output)?;

    // Encode based on the specified format
    match to.as_str() {
        "json" => encode_json(reader, &mut writer)?,
        "csv" => encode_csv(reader, &mut writer)?,
        _ => anyhow::bail!("Unsupported encoding format: {}", to),
    }

    Ok(())
}

/// Encode attack results to JSON
fn encode_json<R: BufRead, W: Write>(reader: R, writer: &mut W) -> Result<()> {
    let results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    serde_json::to_writer_pretty(writer, &results)?;

    Ok(())
}

/// Encode attack results to CSV
fn encode_csv<R: BufRead, W: Write>(reader: R, writer: &mut W) -> Result<()> {
    // Create CSV writer
    let mut csv_writer = csv::Writer::from_writer(writer);

    // Write header
    csv_writer.write_record(&[
        "timestamp",
        "latency",
        "status_code",
        "error",
        "method",
        "url",
        "bytes_in",
        "bytes_out",
    ])?;

    // Process each line
    for line in reader.lines() {
        let line = line?;
        let result: AttackResult = serde_json::from_str(&line)?;

        // Write record
        csv_writer.write_record(&[
            result.timestamp.to_rfc3339(),
            crate::utils::format_duration(result.latency),
            result.status_code.to_string(),
            result.error.unwrap_or_default(),
            result.target.method,
            result.target.url.to_string(),
            result.bytes_in.to_string(),
            result.bytes_out.to_string(),
        ])?;
    }

    // Flush the writer
    csv_writer.flush()?;

    Ok(())
}
