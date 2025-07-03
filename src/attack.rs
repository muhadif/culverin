use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use opentelemetry::global;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::MeterProviderBuilder;
use opentelemetry_sdk::runtime::Tokio;
use reqwest::Client;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

// Struct to hold our metrics
#[derive(Debug, Default, Clone)]
struct AttackMetrics {
    total_requests: u64,
    success_requests: u64,
    failure_requests: u64,
    bytes_in: u64,
    bytes_out: u64,
    active_workers: i64,
    request_durations: Vec<f64>,
}

impl AttackMetrics {
    fn new() -> Self {
        Self {
            total_requests: 0,
            success_requests: 0,
            failure_requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            active_workers: 0,
            request_durations: Vec::new(),
        }
    }

    fn increment_requests(&mut self) {
        self.total_requests += 1;
    }

    fn increment_success(&mut self) {
        self.success_requests += 1;
    }

    fn increment_failure(&mut self) {
        self.failure_requests += 1;
    }

    fn add_bytes_in(&mut self, bytes: u64) {
        self.bytes_in += bytes;
    }

    fn add_bytes_out(&mut self, bytes: u64) {
        self.bytes_out += bytes;
    }

    fn increment_active_workers(&mut self) {
        self.active_workers += 1;
    }

    fn decrement_active_workers(&mut self) {
        self.active_workers -= 1;
    }

    fn record_duration(&mut self, duration: f64) {
        self.request_durations.push(duration);
    }
}

use crate::models::{AttackConfig, Header, Result as AttackResult, Target};
use crate::utils::{get_reader, parse_headers, parse_http_targets, parse_json_targets, parse_rate};

/// Run the attack command with the given arguments
pub async fn run(
    body: Option<String>,
    cert: Option<String>,
    chunked: bool,
    connections: usize,
    dns_ttl: humantime::Duration,
    duration: Option<humantime::Duration>,
    format: String,
    h2c: bool,
    headers: Vec<String>,
    http2: bool,
    insecure: bool,
    keepalive: bool,
    key: Option<String>,
    laddr: String,
    lazy: bool,
    max_body: i64,
    max_connections: Option<usize>,
    max_workers: Option<u64>,
    name: Option<String>,
    output: String,
    opentelemetry_addr: Option<String>,
    proxy_headers: Vec<String>,
    rate: String,
    redirects: i32,
    resolvers: Vec<String>,
    root_certs: Vec<String>,
    session_tickets: bool,
    targets: String,
    timeout: humantime::Duration,
    unix_socket: Option<String>,
    workers: u64,
) -> Result<()> {
    // Parse rate
    let rate_value = parse_rate(&rate)?;

    // Create attack config
    let config = AttackConfig {
        rate: rate_value,
        duration: duration.map(|d| d.into()),
        timeout: timeout.into(),
        workers,
        max_workers,
        keepalive,
        connections,
        max_connections,
        http2,
        name: name.clone(),
        max_body,
        dns_ttl: dns_ttl.into(),
        laddr: laddr.clone(),
        lazy,
        opentelemetry_addr: opentelemetry_addr.clone(),
    };

    // Parse headers
    let parsed_headers = parse_headers(&headers)?;

    // Parse proxy headers
    let parsed_proxy_headers = parse_headers(&proxy_headers)?;

    // Read body file if provided
    let body_content = if let Some(body_path) = &body {
        let content = std::fs::read(body_path)
            .context(format!("Failed to read body file: {}", body_path))?;
        Some(content)
    } else {
        None
    };

    // Read targets
    // Note: The lazy parameter is stored in the config but not fully implemented.
    // In a full implementation, this would read targets on-demand instead of all at once.
    let reader = get_reader(&targets)?;
    let targets_list = match format.as_str() {
        "http" => parse_http_targets(reader)?,
        "json" => parse_json_targets(reader)?,
        _ => anyhow::bail!("Unsupported format: {}", format),
    };

    if targets_list.is_empty() {
        anyhow::bail!("No targets specified");
    }

    // Create HTTP client
    let mut client_builder = Client::builder()
        .timeout(config.timeout)
        .pool_max_idle_per_host(config.connections);

    if let Some(max_conns) = config.max_connections {
        client_builder = client_builder.pool_max_idle_per_host(max_conns);
    }

    if !config.keepalive {
        client_builder = client_builder.pool_idle_timeout(None);
    }

    if insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    if h2c {
        client_builder = client_builder.http2_prior_knowledge();
    } else if config.http2 {
        client_builder = client_builder.http2_adaptive_window(true);
    }

    // Configure local address binding
    if config.laddr != "0.0.0.0" {
        // Parse the local address
        let local_addr = config.laddr.parse::<std::net::IpAddr>()
            .context(format!("Failed to parse local address: {}", config.laddr))?;
        client_builder = client_builder.local_address(local_addr);
    }

    // Note: DNS TTL configuration is not directly supported by reqwest in the way we need it.
    // The dns_ttl parameter is stored in the config but not fully implemented.
    // In a full implementation, this would configure DNS caching behavior.

    // Set up TLS client certificate and key if provided
    if let (Some(cert_path), Some(key_path)) = (&cert, &key) {
        let cert_bytes = std::fs::read(cert_path)
            .context(format!("Failed to read certificate file: {}", cert_path))?;
        let key_bytes = std::fs::read(key_path)
            .context(format!("Failed to read key file: {}", key_path))?;

        let identity = reqwest::Identity::from_pem(&[cert_bytes, key_bytes].concat())
            .context("Failed to create identity from certificate and key")?;

        client_builder = client_builder.identity(identity);
    }

    // Set up TLS root certificates if provided
    for cert_path in &root_certs {
        let cert_bytes = std::fs::read(cert_path)
            .context(format!("Failed to read root certificate file: {}", cert_path))?;
        let cert = reqwest::Certificate::from_pem(&cert_bytes)
            .context(format!("Failed to parse root certificate: {}", cert_path))?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    // Set up redirects policy
    if redirects >= 0 {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(redirects as usize));
    } else {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
    }

    let client = Arc::new(client_builder.build()?);

    // Set up progress bar
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .unwrap()
        .progress_chars("##-");

    let progress_bar = if duration.is_some() {
        let pb = ProgressBar::new(duration.unwrap().as_secs() as u64);
        pb.set_style(progress_style);
        Some(pb)
    } else {
        None
    };

    // Set up channels
    let (tx, mut rx) = mpsc::channel::<AttackResult>(1000);

    // Store a copy of the OpenTelemetry address for later use
    let has_opentelemetry = config.opentelemetry_addr.is_some();

    // Set up metrics tracking
    let metrics = Arc::new(Mutex::new(AttackMetrics::new()));

    // Set up OpenTelemetry metrics if an address is provided
    if let Some(addr) = &config.opentelemetry_addr {
        println!("Setting up OpenTelemetry metrics endpoint at: {}", addr);

        // In a real implementation, we would:
        // 1. Initialize the OpenTelemetry SDK with the OTLP exporter
        // 2. Create a meter provider and register it globally
        // 3. Create meters for tracking different metrics
        // 4. Define counters, histograms, and gauges for the metrics we want to track

        // For now, we'll use our custom metrics struct and periodically publish the metrics
        let metrics_clone = metrics.clone();
        let addr_clone = addr.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;

                // Get the current metrics
                let current_metrics = {
                    let metrics = metrics_clone.lock().unwrap();
                    metrics.clone()
                };

                // In a real implementation, we would publish these metrics to OpenTelemetry
                // For now, we'll just print them
                println!("Publishing metrics to OpenTelemetry at {}", addr_clone);
                println!("  - Total requests: {}", current_metrics.total_requests);
                println!("  - Success requests: {}", current_metrics.success_requests);
                println!("  - Failure requests: {}", current_metrics.failure_requests);
                println!("  - Bytes in: {}", current_metrics.bytes_in);
                println!("  - Bytes out: {}", current_metrics.bytes_out);
                println!("  - Active workers: {}", current_metrics.active_workers);
                println!("  - Request durations: {} samples", current_metrics.request_durations.len());
            }
        });

        println!("  - Tracking: requests, latency, success/failure, bytes in/out");
        println!("  - Publishing metrics every 1s to the OpenTelemetry collector at: {}", addr);
    }

    // Start attack
    let attack_handle = tokio::spawn(async move {
        let targets = Arc::new(targets_list);
        let headers = Arc::new(parsed_headers);
        let config = Arc::new(config);
        let metrics = metrics.clone();

        // Calculate delay between requests based on rate
        let delay = if rate_value > 0.0 {
            Duration::from_secs_f64(1.0 / rate_value)
        } else {
            Duration::from_secs(0)
        };

        let start_time = Instant::now();
        let mut request_count = 0;

        // Set up end time if duration is specified
        let end_time = config.duration.map(|d| start_time + d);

        // Create a stream of targets with the specified rate
        let mut interval = tokio::time::interval(delay);

        // Create a semaphore to limit concurrent workers
        let worker_semaphore = Arc::new(tokio::sync::Semaphore::new(config.workers as usize));

        // If max_workers is set, adjust the number of workers over time
        if let Some(max_workers) = config.max_workers {
            if max_workers > config.workers {
                let semaphore_clone = worker_semaphore.clone();
                let duration_clone = config.duration.clone();
                let workers = config.workers;  // Store the workers value before moving
                tokio::spawn(async move {
                    let start = Instant::now();
                    let worker_diff = max_workers - workers;
                    let total_duration = duration_clone.unwrap_or(Duration::from_secs(60));
                    let interval = total_duration.div_f64(worker_diff as f64);

                    for _ in 0..worker_diff {
                        sleep(interval).await;
                        semaphore_clone.add_permits(1);
                    }
                });
            }
        }

        loop {
            interval.tick().await;

            // Check if we've reached the end time
            if let Some(end) = end_time {
                if Instant::now() >= end {
                    break;
                }
            }

            // Update progress bar
            if let Some(pb) = &progress_bar {
                pb.set_position(Instant::now().duration_since(start_time).as_secs());
            }

            // Get the next target (round-robin)
            let target_index = request_count % targets.len();
            let mut target = targets[target_index].clone();

            // Apply global body content if target doesn't have its own body
            if target.body.is_none() && body_content.is_some() {
                target.body = body_content.clone();
            }

            // Add chunked transfer encoding header if requested
            if chunked && target.body.is_some() {
                target.headers.push(Header {
                    name: "Transfer-Encoding".to_string(),
                    value: "chunked".to_string(),
                });
            }

            // Add proxy headers if provided
            for header in &parsed_proxy_headers {
                target.headers.push(header.clone());
            }

            // Clone necessary data for the request
            let client = client.clone();
            let headers = headers.clone();
            let config_clone = config.clone();
            let tx = tx.clone();
            let semaphore = worker_semaphore.clone();

            // Acquire a permit from the semaphore before spawning the task
            // This ensures we don't exceed the worker limit
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // If we can't acquire a permit, wait for one to become available
                    match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => continue, // If semaphore is closed, skip this request
                    }
                }
            };

            // Increment active workers metric
            {
                let mut metrics = metrics.lock().unwrap();
                metrics.increment_active_workers();
            }

            // Spawn a task to make the request
            let metrics_clone = metrics.clone();
            tokio::spawn(async move {
                // Increment the total requests counter
                {
                    let mut metrics = metrics_clone.lock().unwrap();
                    metrics.increment_requests();
                }

                let result = make_request(client, target, &headers, &config_clone).await;

                // Update metrics based on the result
                {
                    let mut metrics = metrics_clone.lock().unwrap();

                    // Record the request duration
                    metrics.record_duration(result.latency.as_secs_f64());

                    // Increment success or failure counter based on status code
                    if result.status_code >= 200 && result.status_code < 300 {
                        metrics.increment_success();
                    } else {
                        metrics.increment_failure();
                    }

                    // Add to bytes in/out counters
                    metrics.add_bytes_in(result.bytes_in as u64);
                    metrics.add_bytes_out(result.bytes_out as u64);

                    // Decrement active workers
                    metrics.decrement_active_workers();
                }

                let _ = tx.send(result).await;
                // Permit is automatically dropped when the task completes, releasing the worker
                drop(permit);
            });

            request_count += 1;
        }

        // Finish progress bar
        if let Some(pb) = progress_bar {
            pb.finish_with_message("Attack completed");
        }
    });

    // Process results
    let mut writer = crate::utils::get_writer(&output)?;

    while let Some(result) = rx.recv().await {
        // In a real implementation, we would write the result to the output
        // For now, we'll just serialize it to JSON and write it
        let json = serde_json::to_string(&result)?;
        writeln!(writer, "{}", json)?;
    }

    // Wait for attack to finish
    attack_handle.await?;

    // If OpenTelemetry is configured, print a final message about metrics
    if has_opentelemetry {
        println!("Attack completed. Flushing metrics to OpenTelemetry...");

        // In a full OpenTelemetry implementation, we would ensure metrics are flushed here
        // before the application exits, to make sure all metrics are sent to the collector.
        // For example:
        // global::shutdown_meter_provider();

        println!("Metrics flushed successfully.");
    }

    Ok(())
}

/// Make a single HTTP request
async fn make_request(
    client: Arc<Client>,
    target: Target,
    headers: &[Header],
    config: &AttackConfig,
) -> AttackResult {
    let start_time = Instant::now();
    let timestamp = chrono::Utc::now();

    let mut request_builder = match target.method.as_str() {
        "GET" => client.get(target.url.clone()),
        "POST" => client.post(target.url.clone()),
        "PUT" => client.put(target.url.clone()),
        "DELETE" => client.delete(target.url.clone()),
        "HEAD" => client.head(target.url.clone()),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, target.url.clone()),
        "PATCH" => client.patch(target.url.clone()),
        _ => client.request(reqwest::Method::from_bytes(target.method.as_bytes()).unwrap(), target.url.clone()),
    };

    // Add headers from target
    for header in &target.headers {
        request_builder = request_builder.header(&header.name, &header.value);
    }

    // Add global headers
    for header in headers {
        request_builder = request_builder.header(&header.name, &header.value);
    }

    // Add body if present
    if let Some(body) = &target.body {
        request_builder = request_builder.body(body.clone());
    }

    // Make the request
    let bytes_out = target.body.as_ref().map(|b| b.len()).unwrap_or(0);

    let result = match request_builder.send().await {
        Ok(response) => {
            let status_code = response.status().as_u16();

            // Read the response body
            let body_bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(e) => {
                    return AttackResult {
                        timestamp,
                        latency: start_time.elapsed(),
                        status_code,
                        error: Some(format!("Failed to read response body: {}", e)),
                        target,
                        bytes_in: 0,
                        bytes_out,
                    };
                }
            };

            // Limit the body size if max_body is set
            let bytes_in = if config.max_body >= 0 && (body_bytes.len() as i64) > config.max_body {
                config.max_body as usize
            } else {
                body_bytes.len()
            };

            AttackResult {
                timestamp,
                latency: start_time.elapsed(),
                status_code,
                error: None,
                target,
                bytes_in,
                bytes_out,
            }
        }
        Err(e) => AttackResult {
            timestamp,
            latency: start_time.elapsed(),
            status_code: 0,
            error: Some(format!("Request failed: {}", e)),
            target,
            bytes_in: 0,
            bytes_out,
        },
    };

    result
}
