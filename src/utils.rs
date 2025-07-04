use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
// use std::path::Path;
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

/// Parse HTTP targets from a reader in file format
/// 
/// This format supports:
/// - URL line (e.g., "POST http://goku:9090/things" or "POST /api/things HTTP/1.1")
/// - Headers (e.g., "Header1: asdasd")
/// - Body in JSON or HTTP param format (e.g., {"key": "value"} or file path)
/// 
/// Example 1 (Simple format):
/// ```
/// POST http://goku:9090/things
/// Header1: asdasd
/// Body:
/// {"key": "value"}
/// 
/// PATCH http://goku:9090/thing/71988591
/// Body: file/path
/// ```
///
/// Example 2 (HTTP/1.1 format):
/// ```
/// POST /api/things HTTP/1.1
/// Host: goku:9090
/// Content-Type: application/json
/// 
/// {"key": "value"}
/// ```
pub fn parse_file_targets<R: BufRead>(reader: R) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut lines = reader.lines();

    // State variables for parsing
    let mut current_method: Option<String> = None;
    let mut current_url: Option<Url> = None;
    let mut current_path: Option<String> = None;
    let mut current_headers: Vec<Header> = Vec::new();
    let mut current_body: Option<Vec<u8>> = None;
    let mut reading_body = false;
    let mut body_content = String::new();
    let mut is_http_format = false;
    let mut found_empty_line = false;

    while let Some(line_result) = lines.next() {
        let line = line_result?;
        let trimmed_line = line.trim();

        // Skip comments
        if trimmed_line.starts_with('#') {
            continue;
        }

        // Handle empty lines
        if trimmed_line.is_empty() {
            // If we're in HTTP format and we've already seen headers, an empty line indicates the start of the body
            if is_http_format && current_method.is_some() && current_path.is_some() && !found_empty_line {
                found_empty_line = true;
                reading_body = true;
                continue;
            }

            // If we were in the middle of parsing a target, finalize it
            if current_method.is_some() && (current_url.is_some() || (is_http_format && current_path.is_some())) {
                // If we're in HTTP format, construct the URL from the path and host header
                if is_http_format && current_path.is_some() {
                    // Look for the Host header
                    let host_header = current_headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host"));

                    if let Some(host) = host_header {
                        // Construct the URL from the host and path
                        let scheme = "http"; // Default to HTTP
                        let url_str = format!("{}://{}{}", scheme, host.value, current_path.as_ref().unwrap());
                        match Url::parse(&url_str) {
                            Ok(url) => {
                                current_url = Some(url);
                            },
                            Err(e) => {
                                anyhow::bail!("Failed to construct URL from host and path: {}", e);
                            }
                        }
                    } else {
                        anyhow::bail!("HTTP format request missing Host header");
                    }
                }

                targets.push(Target {
                    method: current_method.take().unwrap(),
                    url: current_url.take().unwrap(),
                    headers: std::mem::take(&mut current_headers),
                    body: current_body.take(),
                });
                reading_body = false;
                body_content.clear();
                is_http_format = false;
                found_empty_line = false;
                current_path.take();
            }
            continue;
        }

        // Check if this is a method and URL line
        if trimmed_line.contains(' ') {
            // First check if this is a method and URL line before checking if it's a header line
            // This is important because URLs contain colons, which would otherwise be mistaken for headers
            let method_url_parts: Vec<&str> = trimmed_line.splitn(2, ' ').collect();
            if method_url_parts.len() == 2 && !method_url_parts[0].contains(':') {
                let _method = method_url_parts[0];
                let url_or_path = method_url_parts[1];

                // Check if this is an HTTP/1.1 format request line (e.g., "POST /api/things HTTP/1.1")
                if url_or_path.contains("HTTP/1.1") || url_or_path.contains("HTTP/2.0") {
                    let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        // If we were in the middle of parsing a target, finalize it
                        if current_method.is_some() && (current_url.is_some() || (is_http_format && current_path.is_some())) {
                            // If we're in HTTP format, construct the URL from the path and host header
                            if is_http_format && current_path.is_some() {
                                // Look for the Host header
                                let host_header = current_headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host"));

                                if let Some(host) = host_header {
                                    // Construct the URL from the host and path
                                    let scheme = "http"; // Default to HTTP
                                    let url_str = format!("{}://{}{}", scheme, host.value, current_path.as_ref().unwrap());
                                    match Url::parse(&url_str) {
                                        Ok(url) => {
                                            current_url = Some(url);
                                        },
                                        Err(e) => {
                                            anyhow::bail!("Failed to construct URL from host and path: {}", e);
                                        }
                                    }
                                } else {
                                    anyhow::bail!("HTTP format request missing Host header");
                                }
                            }

                            targets.push(Target {
                                method: current_method.take().unwrap(),
                                url: current_url.take().unwrap(),
                                headers: std::mem::take(&mut current_headers),
                                body: current_body.take(),
                            });
                            body_content.clear();
                            current_path.take();
                        }

                        // Start a new target in HTTP format
                        let method = parts[0].to_string();
                        let path = parts[1].to_string();

                        current_method = Some(method);
                        current_path = Some(path);
                        is_http_format = true;
                        found_empty_line = false;
                        continue;
                    }
                } else {
                    // This is a simple format request line (e.g., "POST http://goku:9090/things")
                    // If we were in the middle of parsing a target, finalize it
                    if current_method.is_some() && (current_url.is_some() || (is_http_format && current_path.is_some())) {
                        // If we're in HTTP format, construct the URL from the path and host header
                        if is_http_format && current_path.is_some() {
                            // Look for the Host header
                            let host_header = current_headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host"));

                            if let Some(host) = host_header {
                                // Construct the URL from the host and path
                                let scheme = "http"; // Default to HTTP
                                let url_str = format!("{}://{}{}", scheme, host.value, current_path.as_ref().unwrap());
                                match Url::parse(&url_str) {
                                    Ok(url) => {
                                        current_url = Some(url);
                                    },
                                    Err(e) => {
                                        anyhow::bail!("Failed to construct URL from host and path: {}", e);
                                    }
                                }
                            } else {
                                anyhow::bail!("HTTP format request missing Host header");
                            }
                        }

                        targets.push(Target {
                            method: current_method.take().unwrap(),
                            url: current_url.take().unwrap(),
                            headers: std::mem::take(&mut current_headers),
                            body: current_body.take(),
                        });
                        body_content.clear();
                        current_path.take();
                    }

                    // Start a new target in simple format
                    let method = method_url_parts[0].to_string();
                    match Url::parse(method_url_parts[1]) {
                        Ok(url) => {
                            current_method = Some(method);
                            current_url = Some(url);
                            is_http_format = false;
                            found_empty_line = false;
                        },
                        Err(e) => {
                            anyhow::bail!("Failed to parse URL {}: {}", method_url_parts[1], e);
                        }
                    }
                    continue;
                }
            }
        }

        // If we're reading the body, collect lines until we hit an empty line
        if reading_body {
            // For HTTP format, we're already reading the body after an empty line
            if is_http_format && found_empty_line {
                // Accumulate the body content
                body_content.push_str(&line);
                body_content.push('\n');
                continue;
            }

            // For simple format or Body: header
            // Check if this is a file path (for Body: file/path format)
            if body_content.is_empty() && !trimmed_line.starts_with('{') && !trimmed_line.starts_with('[') {
                // This is a file path, read the file content
                let file_path = trimmed_line;
                match std::fs::read(file_path) {
                    Ok(content) => {
                        current_body = Some(content);
                    },
                    Err(e) => {
                        anyhow::bail!("Failed to read body file {}: {}", file_path, e);
                    }
                }
                reading_body = false;
            } else {
                // Accumulate the body content
                body_content.push_str(&line);
                body_content.push('\n');
            }
            continue;
        }

        // Check if this is a header line
        if trimmed_line.contains(':') {
            let parts: Vec<&str> = trimmed_line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().to_string();
                let value = parts[1].trim().to_string();

                // Special case for "Body:" header
                if name.eq_ignore_ascii_case("Body") {
                    reading_body = true;
                    if !value.is_empty() {
                        // If there's a value after "Body:", it's a file path
                        let file_path = value.trim();
                        match std::fs::read(file_path) {
                            Ok(content) => {
                                current_body = Some(content);
                            },
                            Err(e) => {
                                anyhow::bail!("Failed to read body file {}: {}", file_path, e);
                            }
                        }
                        reading_body = false;
                    }
                } else {
                    current_headers.push(Header { name, value });
                }
                continue;
            }
        }

        // If we get here, the line doesn't match any expected format
        if reading_body {
            // If we're reading the body, just add the line
            body_content.push_str(&line);
            body_content.push('\n');
        } else {
            // Otherwise, it's an unexpected line
            anyhow::bail!("Unexpected line format: {}", line);
        }
    }

    // If we were in the middle of parsing a target, finalize it
    if current_method.is_some() && (current_url.is_some() || (is_http_format && current_path.is_some())) {
        // If we're in HTTP format, construct the URL from the path and host header
        if is_http_format && current_path.is_some() {
            // Look for the Host header
            let host_header = current_headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host"));

            if let Some(host) = host_header {
                // Construct the URL from the host and path
                let scheme = "http"; // Default to HTTP
                let url_str = format!("{}://{}{}", scheme, host.value, current_path.as_ref().unwrap());
                match Url::parse(&url_str) {
                    Ok(url) => {
                        current_url = Some(url);
                    },
                    Err(e) => {
                        anyhow::bail!("Failed to construct URL from host and path: {}", e);
                    }
                }
            } else {
                anyhow::bail!("HTTP format request missing Host header");
            }
        }

        // If we were reading a body and have accumulated content, use it
        if reading_body && !body_content.is_empty() {
            current_body = Some(body_content.trim().as_bytes().to_vec());
        }

        targets.push(Target {
            method: current_method.unwrap(),
            url: current_url.unwrap(),
            headers: current_headers,
            body: current_body,
        });
    }
    Ok(targets)
}
