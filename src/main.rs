use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Number of CPUs to use (default = number of cpus)
    #[arg(long, global = true)]
    cpus: Option<usize>,

    /// Enable profiling of [cpu, heap]
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Print version and exit
    #[arg(long, global = true)]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a load test attack
    Attack {
        /// Requests body file
        #[arg(long)]
        body: Option<String>,

        /// TLS client PEM encoded certificate file
        #[arg(long)]
        cert: Option<String>,

        /// Send body with chunked transfer encoding
        #[arg(long)]
        chunked: bool,

        /// A mapping of (ip|host):port to use instead of a target URL's (ip|host):port
        #[arg(long = "connect-to", value_name = "value")]
        connect_to: Vec<String>,

        /// Max open idle connections per target host
        #[arg(long, default_value = "10000")]
        connections: usize,

        /// Cache DNS lookups for the given duration [-1 = disabled, 0 = forever]
        #[arg(long = "dns-ttl", value_name = "value", default_value = "0s")]
        dns_ttl: humantime::Duration,

        /// Duration of the test [0 = forever]
        #[arg(long)]
        duration: Option<humantime::Duration>,

        /// Targets format [http, json]
        #[arg(long, default_value = "http")]
        format: String,

        /// Send HTTP/2 requests without TLS encryption
        #[arg(long)]
        h2c: bool,

        /// Request header
        #[arg(long = "header", value_name = "value")]
        headers: Vec<String>,

        /// Send HTTP/2 requests when supported by the server
        #[arg(long, default_value = "true")]
        http2: bool,

        /// Ignore invalid server TLS certificates
        #[arg(long)]
        insecure: bool,

        /// Use persistent connections
        #[arg(long, default_value = "true")]
        keepalive: bool,

        /// TLS client PEM encoded private key file
        #[arg(long)]
        key: Option<String>,

        /// Local IP address
        #[arg(long = "laddr", value_name = "value", default_value = "0.0.0.0")]
        laddr: String,

        /// Read targets lazily
        #[arg(long)]
        lazy: bool,

        /// Maximum number of bytes to capture from response bodies. [-1 = no limit]
        #[arg(long = "max-body", value_name = "value", default_value = "-1")]
        max_body: i64,

        /// Max connections per target host
        #[arg(long)]
        max_connections: Option<usize>,

        /// Maximum number of workers
        #[arg(long)]
        max_workers: Option<u64>,

        /// Attack name
        #[arg(long)]
        name: Option<String>,

        /// Output file
        #[arg(long, default_value = "stdout")]
        output: String,

        /// Prometheus exporter listen address [empty = disabled]
        #[arg(long)]
        prometheus_addr: Option<String>,

        /// Proxy CONNECT header
        #[arg(long = "proxy-header", value_name = "value")]
        proxy_headers: Vec<String>,

        /// Number of requests per time unit [0 = infinity]
        #[arg(long = "rate", value_name = "value", default_value = "50/1s")]
        rate: String,

        /// Number of redirects to follow. -1 will not follow but marks as success
        #[arg(long, default_value = "10")]
        redirects: i32,

        /// List of addresses (ip:port) to use for DNS resolution
        #[arg(long = "resolvers", value_name = "value")]
        resolvers: Vec<String>,

        /// TLS root certificate files (comma separated list)
        #[arg(long = "root-certs", value_name = "value")]
        root_certs: Vec<String>,

        /// Enable TLS session resumption using session tickets
        #[arg(long)]
        session_tickets: bool,

        /// Targets file
        #[arg(long, default_value = "stdin")]
        targets: String,

        /// Requests timeout
        #[arg(long, default_value = "30s")]
        timeout: humantime::Duration,

        /// Connect over a unix socket. This overrides the host address in target URLs
        #[arg(long)]
        unix_socket: Option<String>,

        /// Initial number of workers
        #[arg(long, default_value = "10")]
        workers: u64,
    },

    /// Encode attack results to different formats
    Encode {
        /// Output file
        #[arg(long, default_value = "stdout")]
        output: String,

        /// Output encoding [csv, gob, json]
        #[arg(long, default_value = "json")]
        to: String,
    },

    /// Generate plots from attack results
    Plot {
        /// Output file
        #[arg(long, default_value = "stdout")]
        output: String,

        /// Threshold of data points above which series are downsampled
        #[arg(long, default_value = "4000")]
        threshold: usize,

        /// Title and header of the resulting HTML page
        #[arg(long, default_value = "Culverin Plot")]
        title: String,
    },

    /// Generate reports from attack results
    Report {
        /// Histogram buckets, e.g.: "[0,1ms,10ms]"
        #[arg(long)]
        buckets: Option<String>,

        /// Report interval
        #[arg(long)]
        every: Option<humantime::Duration>,

        /// Output file
        #[arg(long, default_value = "stdout")]
        output: String,

        /// Report type to generate [text, json, hist[buckets], hdrplot]
        #[arg(long = "type", default_value = "text")]
        report_type: String,
    },
}

mod attack;
mod encode;
mod plot;
mod report;
mod models;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set number of CPUs to use
    let cpu_count = if let Some(cpus) = cli.cpus {
        println!("Using {} CPUs", cpus);
        cpus
    } else {
        // Default to the number of logical cores
        let count = num_cpus::get();
        println!("Using default CPU count: {}", count);
        count
    };

    // Handle profiling
    if let Some(profile_type) = cli.profile {
        match profile_type.as_str() {
            "cpu" => {
                println!("CPU profiling enabled");
                // Implement CPU profiling
                #[cfg(feature = "pprof")]
                {
                    use pprof::ProfilerGuard;
                    let guard = ProfilerGuard::new(100).unwrap();
                    std::thread::spawn(move || {
                        let report = guard.report().build().unwrap();
                        let file = std::fs::File::create("cpu_profile.pb").unwrap();
                        let mut options = pprof::flamegraph::Options::default();
                        options.title = String::from("CPU Flamegraph");
                        let _ = pprof::flamegraph::from_report(&report, file, &mut options);
                    });
                }
                #[cfg(not(feature = "pprof"))]
                {
                    println!("CPU profiling requires the 'pprof' feature to be enabled");
                }
            },
            "heap" => {
                println!("Heap profiling enabled");
                // Implement heap profiling
                #[cfg(feature = "pprof")]
                {
                    use pprof::ProfilerGuard;
                    let guard = ProfilerGuard::new(100).unwrap();
                    std::thread::spawn(move || {
                        let report = guard.report().build().unwrap();
                        let file = std::fs::File::create("heap_profile.pb").unwrap();
                        let mut options = pprof::flamegraph::Options::default();
                        options.title = String::from("Heap Flamegraph");
                        let _ = pprof::flamegraph::from_report(&report, file, &mut options);
                    });
                }
                #[cfg(not(feature = "pprof"))]
                {
                    println!("Heap profiling requires the 'pprof' feature to be enabled");
                }
            },
            _ => println!("Unknown profile type: {}", profile_type),
        }
    }

    // Handle version flag
    if cli.version {
        println!("Culverin version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    match cli.command {
        Some(Commands::Attack {
            body,
            cert,
            chunked,
            connect_to,
            connections,
            dns_ttl,
            duration,
            format,
            h2c,
            headers,
            http2,
            insecure,
            keepalive,
            key,
            laddr,
            lazy,
            max_body,
            max_connections,
            max_workers,
            name,
            output,
            prometheus_addr,
            proxy_headers,
            rate,
            redirects,
            resolvers,
            root_certs,
            session_tickets,
            targets,
            timeout,
            unix_socket,
            workers,
        }) => {
            // Use the CPU count to set the number of workers if not explicitly specified
            let effective_workers = if workers == 10 { // Default value is 10
                cpu_count as u64
            } else {
                workers
            };

            attack::run(
                body, cert, chunked, connections, dns_ttl, duration, format, h2c, 
                headers, http2, insecure, keepalive, key, laddr, lazy, max_body, 
                max_connections, max_workers, name, output, prometheus_addr, 
                proxy_headers, rate, redirects, resolvers, root_certs, 
                session_tickets, targets, timeout, unix_socket, effective_workers
            ).await?;
        }
        Some(Commands::Encode { output, to }) => {
            encode::run(output, to).await?;
        }
        Some(Commands::Plot { output, threshold, title }) => {
            plot::run(output, threshold, title).await?;
        }
        Some(Commands::Report { buckets, every, output, report_type }) => {
            report::run(buckets, every, output, report_type).await?;
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    Ok(())
}
