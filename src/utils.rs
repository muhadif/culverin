use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use crate::models::{Header, Target};
use url::Url;

/// Parse a rate string like "50/1s" into requests per second
pub fn parse_rate(rate_str: &str) -> Result<f64> {
    let parts: Vec<&str> = rate_str.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid rate format. Expected format: <number>/<duration> (e.g., 50/1s)");
    }

    let requests: f64 = parts[0].parse().context("Failed to parse request count")?;
    let duration_str = parts[1];

    // Parse the duration string (e.g., "1s", "500ms")
    let duration = humantime::parse_duration(duration_str)
        .context("Failed to parse duration")?;
    
    let duration_secs = duration.as_secs_f64();
    if duration_secs <= 0.0 {
        anyhow::bail!("Duration must be greater than 0");
    }

    Ok(requests / duration_secs)
}

/// Parse HTTP targets from a reader in HTTP format
pub fn parse_http_targets<R: BufRead>(reader: R) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid target format: {}", line);
        }
        
        let method = parts[0].to_string();
        let url = Url::parse(parts[1]).context("Failed to parse URL")?;
        
        targets.push(Target {
            method,
            url,
            headers: Vec::new(),
            body: None,
        });
    }
    
    Ok(targets)
}

/// Parse HTTP targets from a reader in JSON format
pub fn parse_json_targets<R: Read>(reader: R) -> Result<Vec<Target>> {
    let targets: Vec<Target> = serde_json::from_reader(reader)
        .context("Failed to parse JSON targets")?;
    Ok(targets)
}

/// Parse HTTP headers from strings like "Name: Value"
pub fn parse_headers(headers: &[String]) -> Result<Vec<Header>> {
    let mut result = Vec::new();
    
    for header_str in headers {
        let parts: Vec<&str> = header_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid header format: {}", header_str);
        }
        
        let name = parts[0].trim().to_string();
        let value = parts[1].trim().to_string();
        
        result.push(Header { name, value });
    }
    
    Ok(result)
}

/// Get a reader for a file or stdin
pub fn get_reader(path: &str) -> Result<Box<dyn BufRead>> {
    if path == "stdin" {
        Ok(Box::new(BufReader::new(io::stdin())))
    } else {
        let file = File::open(path).context(format!("Failed to open file: {}", path))?;
        Ok(Box::new(BufReader::new(file)))
    }
}

/// Get a writer for a file or stdout
pub fn get_writer(path: &str) -> Result<Box<dyn Write>> {
    if path == "stdout" {
        Ok(Box::new(io::stdout()))
    } else {
        let file = File::create(path).context(format!("Failed to create file: {}", path))?;
        Ok(Box::new(file))
    }
}

/// Format a duration in a human-readable format
pub fn format_duration(duration: Duration) -> String {
    let total_micros = duration.as_micros();
    
    if total_micros < 1_000 {
        return format!("{}µs", total_micros);
    }
    
    let total_millis = duration.as_millis();
    if total_millis < 1_000 {
        return format!("{:.2}ms", duration.as_secs_f64() * 1000.0);
    }
    
    let total_secs = duration.as_secs_f64();
    if total_secs < 60.0 {
        return format!("{:.2}s", total_secs);
    }
    
    let minutes = (total_secs / 60.0).floor();
    let seconds = total_secs - (minutes * 60.0);
    format!("{}m{:.2}s", minutes as u64, seconds)
}

/// Format a size in a human-readable format
pub fn format_size(size: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    
    if size < KB {
        return format!("{}B", size);
    } else if size < MB {
        return format!("{:.2}KB", size as f64 / KB as f64);
    } else if size < GB {
        return format!("{:.2}MB", size as f64 / MB as f64);
    } else {
        return format!("{:.2}GB", size as f64 / GB as f64);
    }
}