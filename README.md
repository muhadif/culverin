# Culverin

Culverin is a powerful HTTP load testing tool inspired by Vegeta, written in Rust. It's designed to help you test the performance and reliability of your HTTP services under various load conditions.

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
        Targets format [http, json] (default "http")
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
  --prometheus-addr string
        Prometheus exporter listen address [empty = disabled]
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
  --unix-socket string
        Connect over a unix socket. This overrides the host address in target URLs
  --workers uint
        Initial number of workers (default 10)
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
