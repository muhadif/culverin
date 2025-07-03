use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// Represents a target for the load test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// The HTTP method (GET, POST, etc.)
    pub method: String,
    /// The URL to request
    pub url: Url,
    /// HTTP headers to include in the request
    pub headers: Vec<Header>,
    /// Request body
    pub body: Option<Vec<u8>>,
}

/// Represents an HTTP header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

/// Represents the result of a single request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    /// When the request was started
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// How long the request took
    pub latency: Duration,
    /// HTTP status code
    pub status_code: u16,
    /// Error message if the request failed
    pub error: Option<String>,
    /// The target that was requested
    pub target: Target,
    /// Size of the response body in bytes
    pub bytes_in: usize,
    /// Size of the request body in bytes
    pub bytes_out: usize,
}

/// Represents metrics from a load test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Total number of requests
    pub requests: usize,
    /// Number of successful requests (2xx status)
    pub success: usize,
    /// Total duration of the test
    pub duration: Duration,
    /// Minimum latency observed
    pub min: Duration,
    /// Maximum latency observed
    pub max: Duration,
    /// Mean latency
    pub mean: Duration,
    /// 50th percentile latency
    pub p50: Duration,
    /// 90th percentile latency
    pub p90: Duration,
    /// 95th percentile latency
    pub p95: Duration,
    /// 99th percentile latency
    pub p99: Duration,
    /// Requests per second
    pub rate: f64,
    /// Total bytes received
    pub bytes_in: usize,
    /// Total bytes sent
    pub bytes_out: usize,
    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,
}

/// Represents attack parameters
#[derive(Debug, Clone)]
pub struct AttackConfig {
    /// Rate of requests (requests per second)
    pub rate: f64,
    /// Duration of the attack
    pub duration: Option<Duration>,
    /// Timeout for each request
    pub timeout: Duration,
    /// Number of workers
    pub workers: u64,
    /// Maximum number of workers
    pub max_workers: Option<u64>,
    /// Whether to keep connections alive
    pub keepalive: bool,
    /// Maximum number of connections per host
    pub connections: usize,
    /// Maximum number of connections per host
    pub max_connections: Option<usize>,
    /// HTTP/2 support
    pub http2: bool,
    /// Name of the attack
    pub name: Option<String>,
    /// Maximum number of bytes to capture from response bodies
    pub max_body: i64,
    /// Cache DNS lookups for the given duration
    pub dns_ttl: Duration,
    /// Local IP address
    pub laddr: String,
    /// Read targets lazily
    pub lazy: bool,
    /// Prometheus exporter listen address
    pub prometheus_addr: Option<String>,
}
