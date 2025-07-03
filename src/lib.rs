//! Culverin - A HTTP load testing library
//! 
//! Culverin is a HTTP load testing tool inspired by Vegeta, designed to be used
//! both as a command-line tool and as a library in other Rust applications.
//! 
//! # Example
//! 
//! ```rust,no_run
//! use culverin::{AttackBuilder, Target, Header};
//! use url::Url;
//! use std::time::Duration;
//! 
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create targets
//!     let target = Target {
//!         method: "GET".to_string(),
//!         url: Url::parse("https://example.com")?,
//!         headers: vec![
//!             Header {
//!                 name: "User-Agent".to_string(),
//!                 value: "culverin".to_string(),
//!             }
//!         ],
//!         body: None,
//!     };
//! 
//!     // Run the attack
//!     let results = AttackBuilder::new()
//!         .rate(50.0)  // 50 requests per second
//!         .duration(Duration::from_secs(30))
//!         .timeout(Duration::from_secs(5))
//!         .targets(vec![target])
//!         .run()
//!         .await?;
//! 
//!     // Process results
//!     println!("Attack completed with {} results", results.len());
//!     
//!     Ok(())
//! }
//! ```

mod attack;
mod encode;
mod models;
mod plot;
mod report;
mod utils;

// Re-export the main types for library users
pub use models::{AttackConfig, Header, Metrics, Result as AttackResult, Target};

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

/// Builder for configuring and running an attack
pub struct AttackBuilder {
    rate: f64,
    duration: Option<Duration>,
    timeout: Duration,
    workers: u64,
    max_workers: Option<u64>,
    keepalive: bool,
    connections: usize,
    max_connections: Option<usize>,
    http2: bool,
    name: Option<String>,
    max_body: i64,
    dns_ttl: Duration,
    laddr: String,
    lazy: bool,
    opentelemetry_addr: Option<String>,
    targets: Vec<Target>,
    headers: Vec<Header>,
    insecure: bool,
    h2c: bool,
    redirects: i32,
}

impl Default for AttackBuilder {
    fn default() -> Self {
        Self {
            rate: 50.0,
            duration: Some(Duration::from_secs(30)),
            timeout: Duration::from_secs(30),
            workers: 10,
            max_workers: None,
            keepalive: true,
            connections: 10000,
            max_connections: None,
            http2: true,
            name: None,
            max_body: -1,
            dns_ttl: Duration::from_secs(0),
            laddr: "0.0.0.0".to_string(),
            lazy: false,
            opentelemetry_addr: None,
            targets: Vec::new(),
            headers: Vec::new(),
            insecure: false,
            h2c: false,
            redirects: 10,
        }
    }
}

impl AttackBuilder {
    /// Create a new AttackBuilder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the request rate (requests per second)
    pub fn rate(mut self, rate: f64) -> Self {
        self.rate = rate;
        self
    }

    /// Set the attack duration
    pub fn duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of workers
    pub fn workers(mut self, workers: u64) -> Self {
        self.workers = workers;
        self
    }

    /// Set the maximum number of workers
    pub fn max_workers(mut self, max_workers: u64) -> Self {
        self.max_workers = Some(max_workers);
        self
    }

    /// Set whether to keep connections alive
    pub fn keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Set the maximum number of idle connections per host
    pub fn connections(mut self, connections: usize) -> Self {
        self.connections = connections;
        self
    }

    /// Set the maximum number of connections per host
    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = Some(max_connections);
        self
    }

    /// Set whether to use HTTP/2
    pub fn http2(mut self, http2: bool) -> Self {
        self.http2 = http2;
        self
    }

    /// Set the attack name
    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Set the maximum number of bytes to capture from response bodies
    pub fn max_body(mut self, max_body: i64) -> Self {
        self.max_body = max_body;
        self
    }

    /// Set the DNS TTL
    pub fn dns_ttl(mut self, dns_ttl: Duration) -> Self {
        self.dns_ttl = dns_ttl;
        self
    }

    /// Set the local address
    pub fn laddr(mut self, laddr: String) -> Self {
        self.laddr = laddr;
        self
    }

    /// Set whether to read targets lazily
    pub fn lazy(mut self, lazy: bool) -> Self {
        self.lazy = lazy;
        self
    }

    /// Set the OpenTelemetry exporter address for metrics and logs
    ///
    /// This enables both metrics and logging export to the specified OpenTelemetry collector.
    /// The following metrics are exported:
    /// - requests: Total number of requests
    /// - success_requests: Number of successful requests
    /// - failure_requests: Number of failed requests
    /// - bytes_in: Total bytes received
    /// - bytes_out: Total bytes sent
    /// - active_workers: Number of active workers
    /// - request_duration: Histogram of request durations in seconds
    ///
    /// The following logs are exported:
    /// - attack_started: When the attack starts
    /// - request_start: When a request starts
    /// - request_success: When a request completes successfully
    /// - request_failure: When a request fails with a non-2xx status code
    /// - request_error: When a request fails with an error
    /// - attack_completed: When the attack completes
    pub fn opentelemetry_addr(mut self, addr: String) -> Self {
        self.opentelemetry_addr = Some(addr);
        self
    }

    /// Set the targets for the attack
    pub fn targets(mut self, targets: Vec<Target>) -> Self {
        self.targets = targets;
        self
    }

    /// Add a single target to the attack
    pub fn add_target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    /// Set the global headers for the attack
    pub fn headers(mut self, headers: Vec<Header>) -> Self {
        self.headers = headers;
        self
    }

    /// Add a single header to the attack
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(Header {
            name: name.to_string(),
            value: value.to_string(),
        });
        self
    }

    /// Set whether to ignore invalid server TLS certificates
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Set whether to use HTTP/2 without TLS
    pub fn h2c(mut self, h2c: bool) -> Self {
        self.h2c = h2c;
        self
    }

    /// Set the number of redirects to follow
    pub fn redirects(mut self, redirects: i32) -> Self {
        self.redirects = redirects;
        self
    }

    /// Run the attack and collect results
    pub async fn run(self) -> Result<Vec<AttackResult>> {
        // Validate that we have targets
        if self.targets.is_empty() {
            anyhow::bail!("No targets specified");
        }

        // Create attack config
        let config = AttackConfig {
            rate: self.rate,
            duration: self.duration,
            timeout: self.timeout,
            workers: self.workers,
            max_workers: self.max_workers,
            keepalive: self.keepalive,
            connections: self.connections,
            max_connections: self.max_connections,
            http2: self.http2,
            name: self.name,
            max_body: self.max_body,
            dns_ttl: self.dns_ttl,
            laddr: self.laddr,
            lazy: self.lazy,
            opentelemetry_addr: self.opentelemetry_addr,
        };

        // Create HTTP client
        let mut client_builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(config.connections);

        if let Some(max_conns) = config.max_connections {
            client_builder = client_builder.pool_max_idle_per_host(max_conns);
        }

        if !config.keepalive {
            client_builder = client_builder.pool_idle_timeout(None);
        }

        if self.insecure {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        if self.h2c {
            client_builder = client_builder.http2_prior_knowledge();
        } else if config.http2 {
            client_builder = client_builder.http2_adaptive_window(true);
        }

        // Configure local address binding
        if config.laddr != "0.0.0.0" {
            // Parse the local address
            let local_addr = config.laddr.parse::<std::net::IpAddr>()?;
            client_builder = client_builder.local_address(local_addr);
        }

        // Set up redirects policy
        if self.redirects >= 0 {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(self.redirects as usize));
        } else {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = Arc::new(client_builder.build()?);

        // Set up channels
        let (tx, mut rx) = mpsc::channel::<AttackResult>(1000);

        // Start attack
        let attack_handle = {
            let targets = Arc::new(self.targets);
            let headers = Arc::new(self.headers);
            let config = Arc::new(config);
            let tx = tx.clone();

            tokio::spawn(async move {
                // Calculate delay between requests based on rate
                let delay = if config.rate > 0.0 {
                    Duration::from_secs_f64(1.0 / config.rate)
                } else {
                    Duration::from_secs(0)
                };

                let start_time = std::time::Instant::now();
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
                        let workers = config.workers;
                        tokio::spawn(async move {
                            let worker_diff = max_workers - workers;
                            let total_duration = duration_clone.unwrap_or(Duration::from_secs(60));
                            let interval = total_duration.div_f64(worker_diff as f64);

                            for _ in 0..worker_diff {
                                tokio::time::sleep(interval).await;
                                semaphore_clone.add_permits(1);
                            }
                        });
                    }
                }

                loop {
                    interval.tick().await;

                    // Check if we've reached the end time
                    if let Some(end) = end_time {
                        if std::time::Instant::now() >= end {
                            break;
                        }
                    }

                    // Get the next target (round-robin)
                    let target_index = request_count % targets.len();
                    let target = targets[target_index].clone();

                    // Clone necessary data for the request
                    let client = client.clone();
                    let headers = headers.clone();
                    let config_clone = config.clone();
                    let tx = tx.clone();
                    let semaphore = worker_semaphore.clone();

                    // Acquire a permit from the semaphore before spawning the task
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            match semaphore.clone().acquire_owned().await {
                                Ok(permit) => permit,
                                Err(_) => continue,
                            }
                        }
                    };

                    // Spawn a task to make the request
                    tokio::spawn(async move {
                        let result = attack::make_request(client, target, &headers, &config_clone).await;
                        let _ = tx.send(result).await;
                        drop(permit);
                    });

                    request_count += 1;
                }
            })
        };

        // Collect results
        let mut results = Vec::new();

        // Create a separate task to collect results
        let collector_handle = tokio::spawn(async move {
            let mut collected_results = Vec::new();
            while let Some(result) = rx.recv().await {
                collected_results.push(result);
            }
            collected_results
        });

        // Wait for attack to finish
        attack_handle.await?;

        // Close the channel by dropping the sender
        drop(tx);

        // Wait for collector to finish and get results
        results = collector_handle.await?;

        Ok(results)
    }
}

/// Helper function to create a target with common defaults
pub fn target(method: &str, url: &str) -> Result<Target> {
    Ok(Target {
        method: method.to_string(),
        url: Url::parse(url)?,
        headers: Vec::new(),
        body: None,
    })
}

/// Helper function to create a GET target
pub fn get(url: &str) -> Result<Target> {
    target("GET", url)
}

/// Helper function to create a POST target
pub fn post(url: &str, body: Vec<u8>) -> Result<Target> {
    let mut target = target("POST", url)?;
    target.body = Some(body);
    Ok(target)
}

/// Calculate metrics from attack results
pub fn calculate_metrics(results: &[AttackResult]) -> Option<Metrics> {
    if results.is_empty() {
        return None;
    }

    let requests = results.len();
    let success = results.iter().filter(|r| r.status_code >= 200 && r.status_code < 300).count();
    let success_rate = success as f64 / requests as f64;

    // Calculate duration from first to last request
    let first_timestamp = results.first().unwrap().timestamp;
    let last_timestamp = results.last().unwrap().timestamp;
    let duration = (last_timestamp - first_timestamp).to_std().unwrap_or(Duration::from_secs(0));

    // Calculate latency statistics
    let mut latencies: Vec<Duration> = results.iter().map(|r| r.latency).collect();
    latencies.sort();

    let min = latencies.first().cloned().unwrap_or(Duration::from_secs(0));
    let max = latencies.last().cloned().unwrap_or(Duration::from_secs(0));

    let mean = if !latencies.is_empty() {
        let sum: Duration = latencies.iter().sum();
        Duration::from_secs_f64(sum.as_secs_f64() / latencies.len() as f64)
    } else {
        Duration::from_secs(0)
    };

    // Calculate percentiles
    let p50 = percentile(&latencies, 0.5);
    let p90 = percentile(&latencies, 0.9);
    let p95 = percentile(&latencies, 0.95);
    let p99 = percentile(&latencies, 0.99);

    // Calculate rate
    let rate = if duration.as_secs_f64() > 0.0 {
        requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    // Calculate bytes
    let bytes_in: usize = results.iter().map(|r| r.bytes_in).sum();
    let bytes_out: usize = results.iter().map(|r| r.bytes_out).sum();

    Some(Metrics {
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
    })
}

/// Calculate a percentile from a sorted list of durations
fn percentile(sorted_latencies: &[Duration], percentile: f64) -> Duration {
    if sorted_latencies.is_empty() {
        return Duration::from_secs(0);
    }

    let index = (sorted_latencies.len() as f64 * percentile) as usize;
    sorted_latencies[index.min(sorted_latencies.len() - 1)]
}
