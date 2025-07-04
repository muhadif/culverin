# Culverin

Culverin is a powerful HTTP load testing tool inspired by Vegeta (https://github.com/tsenart/vegeta), written in Rust. It's designed to help you test the performance and reliability of your HTTP services under various load conditions.

## Features

- **High Performance**: Written in Rust for maximum efficiency and minimal resource usage
- **Flexible Rate Control**: Specify request rates with precision (e.g., 50 requests per second)
- **Detailed Metrics**: Get comprehensive statistics about your load tests
- **Beautiful Visualizations**: Generate plots to visualize test results
- **UNIX Composability**: Designed with UNIX composability in mind, allowing you to pipe commands together
- **Multiple Output Formats**: Export results in various formats (JSON, CSV)
- **HTTP/2 Support**: Test services using the latest HTTP protocols
- **Customizable Headers and Payloads**: Full control over request properties

## Installation

### Linux

```bash
# Clone the repository
git clone https://github.com/muhadif/culverin.git
cd culverin

# Run the installation script
chmod +x install.sh
./install.sh
```

### macOS

```bash
# Clone the repository
git clone https://github.com/muhadif/culverin.git
cd culverin

# Run the installation script
chmod +x install_mac.sh
./install_mac.sh
```

### Windows

```powershell
# Clone the repository
git clone https://github.com/muhadif/culverin.git
cd culverin

# Run the installation script (in PowerShell)
.\install_windows.ps1
```

> **Note for Windows users**: Visual Studio Build Tools with C++ support is required. The installation script will check for this and offer to download and install it if not found. Alternatively, you can install it manually from [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/). During installation, make sure to select the "Desktop development with C++" workload.

### Manual Installation (All Platforms)

If you prefer to install manually or the installation scripts don't work for you:

```bash
# Make sure you have Rust and Cargo installed
# Visit https://rustup.rs/ for installation instructions

# Clone the repository
git clone https://github.com/muhadif/culverin.git
cd culverin

# Build and install
cargo install --path .
```

> **Note for Windows manual installation**: You'll still need Visual Studio Build Tools with C++ support installed. Make sure to install it from [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the "Desktop development with C++" workload during installation.

## Usage

Culverin provides several commands for load testing and analyzing results:

- `attack`: Run a load test against a target
- `encode`: Convert results to different formats
- `plot`: Generate visualizations from results
- `report`: Generate detailed reports from results

### Basic Example

```bash
# Create a targets file
echo "GET http://example.com/" > targets.txt

# Run a load test for 5 seconds at 50 requests per second
culverin attack --duration=5s --rate=50/1s --targets=targets.txt --output=results.bin

# Generate a report
cat results.bin | culverin report
```

### Command Pipeline Example

Culverin commands can be piped together for a seamless workflow:

```bash
echo "GET http://example.com/" | culverin attack --duration=10s | tee results.bin | culverin report
```

## Command Reference

### Global Flags

```
--cpus int
      Number of CPUs to use (default = number of cpus)
--profile string
      Enable profiling of [cpu, heap]
--version
      Print version and exit
```

### Attack Command

```
culverin attack [flags]

Flags:
  --body string
        Requests body file
  --cert string
        TLS client PEM encoded certificate file
  --chunked
        Send body with chunked transfer encoding
  --connect-to value
        A mapping of (ip|host):port to use instead of a target URL's (ip|host):port
  --connections int
        Max open idle connections per target host (default 10000)
  --dns-ttl value
        Cache DNS lookups for the given duration [-1 = disabled, 0 = forever] (default 0s)
  --duration duration
        Duration of the test [0 = forever]
  --format string
        Targets format [http, json, file] (default "http")
  --h2c
        Send HTTP/2 requests without TLS encryption
  --header value
        Request header
  --http2
        Send HTTP/2 requests when supported by the server (default true)
  --insecure
        Ignore invalid server TLS certificates
  --keepalive
        Use persistent connections (default true)
  --key string
        TLS client PEM encoded private key file
  --laddr value
        Local IP address (default 0.0.0.0)
  --lazy
        Read targets lazily
  --max-body value
        Maximum number of bytes to capture from response bodies. [-1 = no limit] (default -1)
  --max-connections int
        Max connections per target host
  --max-workers uint
        Maximum number of workers
  --name string
        Attack name
  --output string
        Output file (default "stdout")
  --opentelemetry-addr string
        OpenTelemetry exporter listen address [empty = disabled]
  --proxy-header value
        Proxy CONNECT header
  --rate value
        Number of requests per time unit [0 = infinity] (default 50/1s)
  --redirects int
        Number of redirects to follow. -1 will not follow but marks as success (default 10)
  --resolvers value
        List of addresses (ip:port) to use for DNS resolution
  --root-certs value
        TLS root certificate files (comma separated list)
  --session-tickets
        Enable TLS session resumption using session tickets
  --targets string
        Targets file (default "stdin")
  --timeout duration
        Requests timeout (default 30s)
  --http_timeout duration
        HTTP requests timeout (default 10s)
  --unix-socket string
        Connect over a unix socket. This overrides the host address in target URLs
  --workers uint
        Initial number of workers (default 10)
  --tolerance float
        Tolerance for request rate (percentage as decimal, e.g., 0.1 for 10%) (default 0.1)
```

### Encode Command

```
culverin encode [flags]

Flags:
  --output string
        Output file (default "stdout")
  --to string
        Output encoding [csv, json] (default "json")
```

### Plot Command

```
culverin plot [flags]

Flags:
  --output string
        Output file (default "stdout")
  --threshold int
        Threshold of data points above which series are downsampled. (default 4000)
  --title string
        Title and header of the resulting HTML page (default "Culverin Plot")
```

### Report Command

```
culverin report [flags]

Flags:
  --buckets string
        Histogram buckets, e.g.: "[0,1ms,10ms]"
  --every duration
        Report interval
  --output string
        Output file (default "stdout")
  --type string
        Report type to generate [text, json, hist[buckets], hdrplot] (default "text")
```

## Advanced Examples

### Custom Headers and Body

```bash
echo "POST http://api.example.com/data" | culverin attack \
  --header="Content-Type: application/json" \
  --header="Authorization: Bearer token123" \
  --body=payload.json \
  --duration=30s \
  --rate=10/1s
```

### Generate a Histogram Report

```bash
cat results.bin | culverin report --type="hist[0,10ms,25ms,50ms,100ms,250ms,500ms]"
```

### Generate an HTML Plot

```bash
cat results.bin | culverin plot --output=results.html --title="API Performance Test"
```

### Export Results to CSV

```bash
cat results.bin | culverin encode --to=csv --output=results.csv
```

### High-Performance Testing with Timeouts and Tolerance

This example demonstrates how to use the HTTP timeout and tolerance parameters for high-performance testing:

```bash
echo "GET http://api.example.com/data" | culverin attack \
  --rate=1000/1s \
  --duration=30s \
  --workers=100 \
  --http_timeout=5s \
  --timeout=60s \
  --tolerance=0.2
```

This configuration:
- Attempts to send 1000 requests per second for 30 seconds (30,000 total requests)
- Uses 100 concurrent workers to handle the high request rate
- Sets a 5-second timeout for individual HTTP requests
- Sets a 60-second overall timeout for the entire attack
- Allows a 20% tolerance in the request rate, which is useful for high-performance testing where some variation is expected

### Using the File Format for Targets

Culverin supports a special file format for targets that allows you to specify HTTP method, URL, headers, and body in a single file. This is useful for complex requests with different headers and bodies.

```bash
# Create a file with multiple targets using both formats
cat > targets.txt << EOF
# Simple format example
POST http://api.example.com/data
Content-Type: application/json
Authorization: Bearer token123
Body:
{"key": "value", "another_key": "another_value"}

# HTTP/1.1 format example
POST /api/data/123 HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer token123

{"updated_key": "updated_value"}

# Another simple format example
GET http://api.example.com/status
Authorization: Bearer token123
EOF

# Run the attack using the file format
culverin attack --format=file --targets=targets.txt --duration=10s --rate=5/1s
```

The file format supports:

#### Simple Format
- HTTP method and full URL on the first line (e.g., "POST http://api.example.com/data")
- Headers on subsequent lines (Name: Value format)
- Body content after a "Body:" line
- Body can be inline JSON/text or a file path (e.g., "Body: /path/to/file.json")
- Multiple targets separated by blank lines

#### HTTP/1.1 Format
- HTTP method, path, and HTTP version on the first line (e.g., "POST /api/data HTTP/1.1")
- Headers on subsequent lines, including a required "Host:" header
- Body content after an empty line
- Multiple targets separated by blank lines

Both formats can be mixed in the same file.

## Request Rate Handling and Timeouts

Culverin is designed to accurately maintain the specified request rate while ensuring all requests are completed:

### Request Rate and Duration

- When you specify a rate (e.g., `--rate=100/1s`) and duration (e.g., `--duration=10s`), Culverin will attempt to send exactly that number of requests (e.g., 1000 requests total).
- The tool will wait for all requests to complete, even if it takes longer than the specified duration.
- If the actual number of completed requests is less than the expected number (rate * duration), Culverin will return an error.

### Timeouts

Culverin has two separate timeout parameters:
- `--timeout`: General timeout for the entire attack operation (default 30s)
- `--http_timeout`: Specific timeout for individual HTTP requests (default 10s)

The HTTP timeout ensures that individual requests don't hang indefinitely, while still allowing the overall attack to continue until all requests are completed or the general timeout is reached.

### Worker Management

- The `--workers` parameter controls the number of concurrent workers (default 10)
- Workers are spawned at the specified rate, regardless of whether previous workers have completed
- This ensures that the actual request rate matches the specified rate, even if some requests take longer to complete

### Tolerance

The `--tolerance` parameter (default 0.1 or 10%) allows for some flexibility in the request rate. This is useful when:
- The system under test is experiencing high latency
- Network conditions are variable
- You want to ensure a minimum number of requests are completed

## Terminal Output and Logging

By default, Culverin only displays progress information and a summary of results in the terminal. Detailed response information is not printed to the terminal to avoid cluttering the output.

The summary includes:
- Total requests
- Successful requests
- Failed requests
- Success rate
- Average latency
- Data transferred (received and sent)

If you want to save detailed response information, use the `--output` flag to specify a file:

```bash
echo "GET http://example.com/" | culverin attack \
  --duration=30s \
  --rate=50/1s \
  --output=results.bin
```

### Using OpenTelemetry for Metrics and Logs

Culverin supports exporting metrics and logs to an OpenTelemetry collector, which allows you to monitor your load tests in real-time using tools like Prometheus, Grafana, or any other system that can consume OpenTelemetry data.

```bash
echo "GET http://example.com/" | culverin attack \
  --duration=30s \
  --rate=50/1s \
  --opentelemetry-addr="http://localhost:4318"
```

When an OpenTelemetry address is provided, detailed logs and metrics are sent to the collector. This is useful for monitoring and debugging load tests without cluttering the terminal output.

The following metrics are exported:
- `requests`: Total number of requests
- `success_requests`: Number of successful requests
- `failure_requests`: Number of failed requests
- `bytes_in`: Total bytes received
- `bytes_out`: Total bytes sent
- `active_workers`: Number of active workers
- `request_duration`: Histogram of request durations in seconds

To use this feature, you need to have an OpenTelemetry collector running. You can set up a collector using the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) project.

## Using Culverin as a Library

Culverin can also be used as a library in your Rust applications, allowing you to integrate load testing capabilities directly into your code.

### Adding Culverin to Your Project

Add Culverin to your `Cargo.toml`:

```toml
[dependencies]
culverin = { git = "https://github.com/muhadif/culverin.git" }
tokio = { version = "1.35", features = ["full"] }
anyhow = "1.0"
```

### Basic Example

Here's a simple example of using Culverin as a library:

```rust
use culverin::{AttackBuilder, get, calculate_metrics};
use std::time::Duration;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a target using the helper function
    let target = get("https://example.com")?;

    // Configure and run the attack
    let results = AttackBuilder::new()
        .rate(10.0)                        // 10 requests per second
        .duration(Duration::from_secs(5))  // Run for 5 seconds
        .timeout(Duration::from_secs(30))  // 30 second general timeout
        .http_timeout(Duration::from_secs(10))  // 10 second HTTP timeout
        .tolerance(0.1)                    // 10% tolerance for request rate
        .workers(4)                        // Use 4 worker threads
        .add_header("User-Agent", "culverin-example")
        .add_target(target)
        .run()
        .await?;

    // Calculate and display metrics
    if let Some(metrics) = calculate_metrics(&results) {
        println!("Attack completed!");
        println!("Total requests: {}", metrics.requests);
        println!("Success rate: {:.2}%", metrics.success_rate * 100.0);
        println!("Mean latency: {:.2}ms", metrics.mean.as_secs_f64() * 1000.0);
        println!("95th percentile: {:.2}ms", metrics.p95.as_secs_f64() * 1000.0);
        println!("Requests/second: {:.2}", metrics.rate);
    }

    Ok(())
}
```

### Advanced Usage

For more advanced usage, including custom targets with different HTTP methods, headers, and bodies, see the [advanced example](examples/advanced_attack.rs).

### API Reference

#### Main Types

- `Target`: Represents a target for the load test (method, URL, headers, body)
- `Header`: Represents an HTTP header (name, value)
- `AttackResult`: Represents the result of a single request
- `Metrics`: Represents metrics from a load test
- `AttackBuilder`: Builder for configuring and running an attack

#### Helper Functions

- `get(url)`: Create a GET target
- `post(url, body)`: Create a POST target with the specified body
- `target(method, url)`: Create a target with the specified method
- `calculate_metrics(results)`: Calculate metrics from attack results

#### AttackBuilder Methods

The `AttackBuilder` provides a fluent API for configuring load tests. Here are some of the key methods:

- `rate(f64)`: Set the request rate (requests per second)
- `duration(Duration)`: Set the attack duration
- `timeout(Duration)`: Set the general request timeout
- `http_timeout(Duration)`: Set the HTTP request timeout
- `tolerance(f64)`: Set the tolerance for request rate (percentage as decimal, e.g., 0.1 for 10%)
- `workers(u64)`: Set the number of workers
- `max_workers(u64)`: Set the maximum number of workers
- `keepalive(bool)`: Set whether to keep connections alive
- `http2(bool)`: Set whether to use HTTP/2
- `insecure(bool)`: Set whether to ignore invalid TLS certificates
- `redirects(i32)`: Set the number of redirects to follow
- `add_header(name, value)`: Add a header to all requests
- `add_target(target)`: Add a target to the attack
- `targets(targets)`: Set multiple targets for the attack
- `opentelemetry_addr(String)`: Set the OpenTelemetry exporter address for metrics
- `run()`: Run the attack and collect results

For more details, see the [library documentation](src/lib.rs) and the [example files](examples/).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
