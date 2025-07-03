use anyhow::Result;
use std::io::{BufRead, Write};
use std::time::Duration;

use crate::models::Result as AttackResult;
use crate::utils::{get_reader, get_writer};

/// Run the plot command with the given arguments
pub async fn run(
    output: String,
    threshold: usize,
    title: String,
) -> Result<()> {
    // Get reader and writer
    let reader = get_reader("stdin")?;
    let mut writer = get_writer(&output)?;

    // Generate the plot
    generate_plot(reader, &mut writer, threshold, &title)?;

    Ok(())
}

/// Generate an HTML plot from attack results
fn generate_plot<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    threshold: usize,
    title: &str,
) -> Result<()> {
    // Parse results
    let mut results: Vec<AttackResult> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            serde_json::from_str(&line).ok()
        })
        .collect();

    // Sort results by timestamp
    results.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Downsample if necessary
    if results.len() > threshold {
        let factor = results.len() / threshold;
        results = results
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % factor == 0)
            .map(|(_, r)| r)
            .collect();
    }

    // Extract data for plotting
    let timestamps: Vec<f64> = results
        .iter()
        .map(|r| r.timestamp.timestamp_millis() as f64 / 1000.0)
        .collect();

    let latencies: Vec<f64> = results
        .iter()
        .map(|r| r.latency.as_secs_f64() * 1000.0) // Convert to milliseconds
        .collect();

    let status_codes: Vec<u16> = results
        .iter()
        .map(|r| r.status_code)
        .collect();

    // Generate HTML
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .plot {{ width: 100%; height: 500px; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>{title}</h1>

    <div id="latency-plot" class="plot"></div>
    <div id="status-plot" class="plot"></div>

    <script>
        // Latency plot
        var latencyData = {{
            x: {timestamps:?},
            y: {latencies:?},
            type: 'scatter',
            mode: 'lines',
            name: 'Latency (ms)'
        }};

        var latencyLayout = {{
            title: 'Request Latencies',
            xaxis: {{ title: 'Time (s)' }},
            yaxis: {{ title: 'Latency (ms)' }}
        }};

        Plotly.newPlot('latency-plot', [latencyData], latencyLayout);

        // Status code plot
        var statusData = {{
            x: {timestamps:?},
            y: {status_codes:?},
            type: 'scatter',
            mode: 'markers',
            marker: {{ size: 5 }},
            name: 'Status Codes'
        }};

        var statusLayout = {{
            title: 'Response Status Codes',
            xaxis: {{ title: 'Time (s)' }},
            yaxis: {{ title: 'Status Code' }}
        }};

        Plotly.newPlot('status-plot', [statusData], statusLayout);
    </script>
</body>
</html>"#,
        title = title,
        timestamps = timestamps,
        latencies = latencies,
        status_codes = status_codes
    );

    // Write HTML to output
    write!(writer, "{}", html)?;

    Ok(())
}
