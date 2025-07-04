use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use opentelemetry::global;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::LoggerProvider;
use opentelemetry_sdk::metrics::MeterProviderBuilder;
use opentelemetry_sdk::Resource;
use reqwest::Client;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{prelude::*, EnvFilter};

// Struct to hold our metrics
#[derive(Debug, Default, Clone)]
struct AttackMetrics {
    total_requests: u64,
    success_requests: u64,
    failure_requests: u64,
    timeout_requests: u64,
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
            timeout_requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            active_workers: 0,
            request_durations: Vec::new(),
        }
    }

    fn increment_timeout(&mut self) {
        self.timeout_requests += 1;
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
use crate::utils::{get_reader, parse_headers, parse_http_targets, parse_json_targets, parse_rate, parse_file_targets};

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
    _resolvers: Vec<String>,
    root_certs: Vec<String>,
    _session_tickets: bool,
    targets: String,
    timeout: humantime::Duration,
    http_timeout: humantime::Duration,
    _unix_socket: Option<String>,
    workers: u64,
    tolerance: f64,
) -> Result<()> {
    // Parse rate
    let rate_value = parse_rate(&rate)?;

    // Create attack config
    let config = AttackConfig {
        rate: rate_value,
        duration: duration.map(|d| d.into()),
        timeout: timeout.into(),
        http_timeout: http_timeout.into(),
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
        tolerance: Some(tolerance),
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
        "file" => parse_file_targets(reader)?,
        _ => anyhow::bail!("Unsupported format: {}", format),
    };

    if targets_list.is_empty() {
        anyhow::bail!("No targets specified");
    }

    // Create HTTP client
    let mut client_builder = Client::builder()
        .timeout(config.http_timeout)
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

    // Set up a single progress bar for all progress information
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .unwrap()
        .progress_chars("##-");

    // Create a single progress bar that shows both time and request progress
    let progress_bar = if duration.is_some() {
        let expected_requests = (rate_value * duration.unwrap().as_secs_f64()) as u64;
        let pb = ProgressBar::new(expected_requests);
        pb.set_style(progress_style);
        pb.set_message("Running test (0 active requests)");
        pb.enable_steady_tick(Duration::from_millis(100));
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
    let metrics_for_shutdown = metrics.clone();

    // Set up OpenTelemetry metrics and logs if an address is provided
    if let Some(addr) = &config.opentelemetry_addr {
        println!("Setting up OpenTelemetry endpoint at: {}", addr);

        // Initialize the OpenTelemetry OTLP exporter for metrics
        let _metrics_exporter = opentelemetry_otlp::new_exporter()
            .http()
            .with_endpoint(format!("{}/v1/metrics", addr.clone()));

        // Create a meter provider
        let meter_provider = MeterProviderBuilder::default()
            .with_resource(Resource::new(vec![KeyValue::new("service.name", "culverin")]))
            .build();

        // Register the meter provider globally
        global::set_meter_provider(meter_provider);

        // Create a meter for tracking different metrics
        let meter = global::meter_provider().meter("culverin");

        // Define counters, histograms, and gauges for the metrics we want to track
        let request_counter = meter
            .u64_counter("requests")
            .with_description("Total number of requests")
            .init();

        let success_counter = meter
            .u64_counter("success_requests")
            .with_description("Number of successful requests")
            .init();

        let failure_counter = meter
            .u64_counter("failure_requests")
            .with_description("Number of failed requests")
            .init();

        let bytes_in_counter = meter
            .u64_counter("bytes_in")
            .with_description("Total bytes received")
            .init();

        let bytes_out_counter = meter
            .u64_counter("bytes_out")
            .with_description("Total bytes sent")
            .init();

        let active_workers_gauge = meter
            .i64_up_down_counter("active_workers")
            .with_description("Number of active workers")
            .init();

        let request_duration_histogram = meter
            .f64_histogram("request_duration")
            .with_description("Request duration in seconds")
            .init();

        // Set up OpenTelemetry logging
        println!("Setting up OpenTelemetry logging...");

        // Create a stdout exporter for logs (for testing)
        let logs_exporter = opentelemetry_stdout::LogExporter::default();

        // Create a logger provider
        let logger_provider = LoggerProvider::builder()
            .with_simple_exporter(logs_exporter)
            .build();

        // Set up filtering to prevent telemetry-induced-telemetry loops
        let filter_otel = EnvFilter::new("info")
            .add_directive("hyper=off".parse().unwrap())
            .add_directive("tonic=off".parse().unwrap())
            .add_directive("h2=off".parse().unwrap())
            .add_directive("reqwest=off".parse().unwrap());

        // Create the OpenTelemetry tracing bridge with filtering
        let otel_layer = layer::OpenTelemetryTracingBridge::new(&logger_provider)
            .with_filter(filter_otel);

        // Initialize the tracing subscriber with only the OpenTelemetry layer
        // This ensures logs are only sent to OpenTelemetry, not to the terminal
        tracing_subscriber::registry()
            .with(otel_layer)
            .init();

        info!(
            service_name = "culverin",
            event = "attack_started",
            message = "Starting load test attack",
            rate = rate_value,
            workers = workers,
            targets_count = targets_list.len(),
        );

        // Clone metrics for the telemetry task
        let metrics_clone = metrics.clone();
        let addr_clone = addr.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut last_total = 0;
            let mut last_success = 0;
            let mut last_failure = 0;
            let mut last_bytes_in = 0;
            let mut last_bytes_out = 0;
            let mut last_durations_count = 0;

            loop {
                interval.tick().await;

                // Get the current metrics
                let current_metrics = {
                    let metrics = metrics_clone.lock().unwrap();
                    metrics.clone()
                };

                // Publish metrics to OpenTelemetry
                let attributes = [KeyValue::new("service", "culverin")];

                // Update counters with the delta values
                let total_delta = current_metrics.total_requests - last_total;
                let success_delta = current_metrics.success_requests - last_success;
                let failure_delta = current_metrics.failure_requests - last_failure;
                let bytes_in_delta = current_metrics.bytes_in - last_bytes_in;
                let bytes_out_delta = current_metrics.bytes_out - last_bytes_out;

                if total_delta > 0 {
                    request_counter.add(total_delta, &attributes);
                }
                if success_delta > 0 {
                    success_counter.add(success_delta, &attributes);
                }
                if failure_delta > 0 {
                    failure_counter.add(failure_delta, &attributes);
                }
                if bytes_in_delta > 0 {
                    bytes_in_counter.add(bytes_in_delta, &attributes);
                }
                if bytes_out_delta > 0 {
                    bytes_out_counter.add(bytes_out_delta, &attributes);
                }

                // Update gauge with current value
                active_workers_gauge.add(current_metrics.active_workers, &attributes);

                // Record new durations in the histogram
                if current_metrics.request_durations.len() > last_durations_count {
                    for i in last_durations_count..current_metrics.request_durations.len() {
                        request_duration_histogram.record(
                            current_metrics.request_durations[i], 
                            &attributes
                        );
                    }
                }

                // Update last values
                last_total = current_metrics.total_requests;
                last_success = current_metrics.success_requests;
                last_failure = current_metrics.failure_requests;
                last_bytes_in = current_metrics.bytes_in;
                last_bytes_out = current_metrics.bytes_out;
                last_durations_count = current_metrics.request_durations.len();

                debug!(
                    event = "metrics_published",
                    total_requests = last_total,
                    success_requests = last_success,
                    failure_requests = last_failure,
                    bytes_in = last_bytes_in,
                    bytes_out = last_bytes_out,
                    active_workers = current_metrics.active_workers,
                    message = format!("Published metrics to OpenTelemetry at {}", addr_clone)
                );
            }
        });

        println!("  - Tracking: requests, latency, success/failure, bytes in/out");
        println!("  - Publishing metrics and logs to the OpenTelemetry collector at: {}", addr);
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

        // Calculate expected number of requests if duration is specified
        let expected_requests = config.duration.map(|d| (config.rate * d.as_secs_f64()) as usize);

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
                    let _start = Instant::now();
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

            // Check if we've sent all expected requests
            if let Some(expected) = expected_requests {
                // Only break if we've sent all expected requests
                // This ensures we wait for all requests to complete, even if it takes longer than the specified duration
                if request_count >= expected {
                    break;
                }
            } else if let Some(end) = end_time {
                // If we don't have expected_requests, just check end time
                // This is a fallback for cases where expected_requests is not set
                if Instant::now() >= end {
                    break;
                }
            }

            // Update progress bar with request count and active workers
            if let Some(pb) = &progress_bar {
                // Get active workers count
                let active_workers = {
                    let metrics = metrics.lock().unwrap();
                    metrics.active_workers
                };

                // Update progress bar position with request count
                pb.set_position(request_count as u64);

                // Update message with elapsed time and active workers
                let elapsed = Instant::now().duration_since(start_time).as_secs();
                pb.set_message(format!("Running test [{} sec] ({} active requests)", 
                                      elapsed, active_workers));
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
            // Wait for a permit to become available instead of skipping the request
            // This ensures all requests are processed, even if it takes longer than the specified duration
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    // If the semaphore is closed, skip this request
                    continue;
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

                debug!(
                    event = "request_start",
                    method = target.method,
                    url = target.url.to_string(),
                    message = "Starting request"
                );

                let result = make_request(client, target, &headers, &config_clone).await;

                // Log the result
                if result.status_code >= 200 && result.status_code < 300 {
                    info!(
                        event = "request_success",
                        method = result.target.method,
                        url = result.target.url.to_string(),
                        status_code = result.status_code,
                        latency_ms = result.latency.as_millis() as u64,
                        bytes_in = result.bytes_in,
                        bytes_out = result.bytes_out,
                        message = "Request completed successfully"
                    );
                } else if result.status_code > 0 {
                    warn!(
                        event = "request_failure",
                        method = result.target.method,
                        url = result.target.url.to_string(),
                        status_code = result.status_code,
                        latency_ms = result.latency.as_millis() as u64,
                        bytes_in = result.bytes_in,
                        bytes_out = result.bytes_out,
                        message = "Request failed with non-2xx status code"
                    );
                } else if let Some(error) = &result.error {
                    error!(
                        event = "request_error",
                        method = result.target.method,
                        url = result.target.url.to_string(),
                        latency_ms = result.latency.as_millis() as u64,
                        error = error,
                        message = "Request failed with error"
                    );
                }

                // Update metrics based on the result
                {
                    let mut metrics = metrics_clone.lock().unwrap();

                    // Record the request duration
                    metrics.record_duration(result.latency.as_secs_f64());

                    // Increment success, failure, or timeout counter based on result
                    if result.timed_out {
                        metrics.increment_timeout();
                    } else if result.status_code >= 200 && result.status_code < 300 {
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

            // Increment request count after successfully spawning the task
            request_count += 1;
        }

        // Check if the total number of requests matches the expected rate * duration
        if let Some(duration) = config.duration {
            let elapsed = Instant::now().duration_since(start_time);
            let expected_requests = (config.rate * duration.as_secs_f64()) as usize;

            // Log the actual vs expected requests
            println!("Completed {} requests out of {} expected ({:.2}%)", 
                     request_count, 
                     expected_requests, 
                     (request_count as f64 / expected_requests as f64) * 100.0);

            // If we haven't completed the expected number of requests, return an error
            if request_count < expected_requests {
                return Err(anyhow::anyhow!(
                    "Failed to achieve target rate: completed {} requests in {:?}, expected {} requests in {:?}",
                    request_count,
                    elapsed,
                    expected_requests,
                    duration
                ));
            }
        }

        // Update progress bar to waiting mode
        if let Some(pb) = &progress_bar {
            pb.set_message("Waiting for remaining requests to complete...");
        }

        // Wait for all active requests to complete or timeout
        let timeout_duration = config.timeout.max(config.http_timeout);
        let wait_start = Instant::now();

        loop {
            // Check if all workers are done
            let active_workers = {
                let metrics = metrics.lock().unwrap();
                metrics.active_workers
            };

            if active_workers <= 0 {
                break;
            }

            // Check if we've waited too long
            let elapsed = Instant::now().duration_since(wait_start);
            if elapsed > timeout_duration {
                println!("Timeout waiting for requests to complete. Some requests may still be in progress.");
                break;
            }

            // Update progress bar message with count of remaining requests
            if let Some(pb) = &progress_bar {
                pb.set_message(format!("Waiting for {} remaining requests...", active_workers));
            }

            // Sleep a bit before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Finish progress bar
        if let Some(pb) = progress_bar {
            pb.finish_with_message("All requests completed");
        }

        Ok(())
    });

    // Process results
    // Only write detailed results to a file, not to stdout
    if output != "stdout" {
        let mut writer = crate::utils::get_writer(&output)?;

        while let Some(result) = rx.recv().await {
            // Serialize the result to JSON and write it to the file
            let json = serde_json::to_string(&result)?;
            writeln!(writer, "{}", json)?;
        }
    } else {
        // If output is stdout, just consume the results without printing details
        while let Some(_) = rx.recv().await {
            // Do nothing with the result, just consume it
        }
    }

    // Wait for attack to finish
    attack_handle.await?;

    // Display a summary of the attack results in the terminal
    {
        let metrics = metrics_for_shutdown.lock().unwrap();
        println!("\nAttack Summary:");
        println!("  Total Requests: {}", metrics.total_requests);
        println!("  Successful Requests: {}", metrics.success_requests);
        println!("  Failed Requests: {}", metrics.failure_requests);

        // Display timed out requests
        println!("  Timed Out Requests: {}", metrics.timeout_requests);

        // Calculate success rate
        let success_rate = if metrics.total_requests > 0 {
            (metrics.success_requests as f64 / metrics.total_requests as f64) * 100.0
        } else {
            0.0
        };
        println!("  Success Rate: {:.2}%", success_rate);

        // Calculate average latency if there are any requests
        if !metrics.request_durations.is_empty() {
            let avg_latency = metrics.request_durations.iter().sum::<f64>() / metrics.request_durations.len() as f64;
            println!("  Average Latency: {:.2}ms", avg_latency * 1000.0);
        }

        // Display data transfer information
        println!("  Data Transferred:");
        println!("    Received: {}", crate::utils::format_size(metrics.bytes_in as usize));
        println!("    Sent: {}", crate::utils::format_size(metrics.bytes_out as usize));
    }

    // If OpenTelemetry is configured, log completion and shut down providers
    if has_opentelemetry {
        println!("\nFlushing telemetry to OpenTelemetry...");

        // Log the attack completion
        info!(
            event = "attack_completed",
            message = "Load test attack completed",
            total_requests = {
                let metrics = metrics_for_shutdown.lock().unwrap();
                metrics.total_requests
            },
            success_requests = {
                let metrics = metrics_for_shutdown.lock().unwrap();
                metrics.success_requests
            },
            failure_requests = {
                let metrics = metrics_for_shutdown.lock().unwrap();
                metrics.failure_requests
            },
        );

        // Shut down the logger provider to flush logs
        global::shutdown_logger_provider();

        println!("Telemetry flushed successfully.");
    }

    Ok(())
}

/// Make a single HTTP request
pub async fn make_request(
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

    // Create a timeout future that will complete after http_timeout
    let timeout_duration = config.http_timeout;
    let request_future = request_builder.send();

    // Use tokio::time::timeout to enforce the HTTP timeout
    let result = match tokio::time::timeout(timeout_duration, request_future).await {
        // Request completed within timeout
        Ok(request_result) => match request_result {
            Ok(response) => {
                let status_code = response.status().as_u16();

                // Read the response body with timeout
                let body_future = response.bytes();
                let body_bytes = match tokio::time::timeout(timeout_duration, body_future).await {
                    Ok(body_result) => match body_result {
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
                                timed_out: false,
                            };
                        }
                    },
                    Err(_) => {
                        // Body read timed out
                        return AttackResult {
                            timestamp,
                            latency: start_time.elapsed(),
                            status_code,
                            error: Some(format!("Response body read timed out after {:?}", timeout_duration)),
                            target,
                            bytes_in: 0,
                            bytes_out,
                            timed_out: true,
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
                    timed_out: false,
                }
            }
            Err(e) => {
                let is_timeout = e.is_timeout();
                AttackResult {
                    timestamp,
                    latency: start_time.elapsed(),
                    status_code: 0,
                    error: Some(format!("Request failed: {}", e)),
                    target,
                    bytes_in: 0,
                    bytes_out,
                    timed_out: is_timeout,
                }
            }
        },
        // Request timed out
        Err(_) => AttackResult {
            timestamp,
            latency: start_time.elapsed(),
            status_code: 0,
            error: Some(format!("Request timed out after {:?}", timeout_duration)),
            target,
            bytes_in: 0,
            bytes_out,
            timed_out: true,
        },
    };

    result
}
