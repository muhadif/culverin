use culverin::{AttackBuilder, Target, Header, calculate_metrics};
use std::time::Duration;
use anyhow::Result;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    // Create multiple targets with different methods and configurations
    let targets = vec![
        // GET request
        Target {
            method: "GET".to_string(),
            url: Url::parse("https://example.com/api/users")?,
            headers: vec![
                Header {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                },
            ],
            body: None,
        },
        
        // POST request with JSON body
        Target {
            method: "POST".to_string(),
            url: Url::parse("https://example.com/api/users")?,
            headers: vec![
                Header {
                    name: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
                Header {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                },
            ],
            body: Some(r#"{"name": "John Doe", "email": "john@example.com"}"#.as_bytes().to_vec()),
        },
        
        // PUT request
        Target {
            method: "PUT".to_string(),
            url: Url::parse("https://example.com/api/users/123")?,
            headers: vec![
                Header {
                    name: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
            ],
            body: Some(r#"{"name": "Jane Doe", "email": "jane@example.com"}"#.as_bytes().to_vec()),
        },
    ];

    // Configure and run the attack with advanced options
    let results = AttackBuilder::new()
        .rate(20.0)                        // 20 requests per second
        .duration(Duration::from_secs(10)) // Run for 10 seconds
        .timeout(Duration::from_secs(5))   // 5 second timeout
        .workers(8)                        // Use 8 worker threads
        .max_workers(16)                   // Scale up to 16 workers if needed
        .keepalive(true)                   // Keep connections alive
        .http2(true)                       // Use HTTP/2 when supported
        .insecure(false)                   // Verify TLS certificates
        .redirects(5)                      // Follow up to 5 redirects
        .add_header("User-Agent", "culverin-advanced-example")
        .targets(targets)                  // Set multiple targets
        .run()
        .await?;

    // Calculate and display detailed metrics
    if let Some(metrics) = calculate_metrics(&results) {
        println!("=== Attack Results ===");
        println!("Total requests: {}", metrics.requests);
        println!("Successful requests: {} ({:.2}%)", 
            metrics.success, 
            metrics.success_rate * 100.0);
        println!("Duration: {:.2}s", metrics.duration.as_secs_f64());
        println!("Requests/second: {:.2}", metrics.rate);
        
        println!("\n=== Latency Statistics ===");
        println!("Min: {:.2}ms", metrics.min.as_secs_f64() * 1000.0);
        println!("Mean: {:.2}ms", metrics.mean.as_secs_f64() * 1000.0);
        println!("Max: {:.2}ms", metrics.max.as_secs_f64() * 1000.0);
        println!("50th percentile: {:.2}ms", metrics.p50.as_secs_f64() * 1000.0);
        println!("90th percentile: {:.2}ms", metrics.p90.as_secs_f64() * 1000.0);
        println!("95th percentile: {:.2}ms", metrics.p95.as_secs_f64() * 1000.0);
        println!("99th percentile: {:.2}ms", metrics.p99.as_secs_f64() * 1000.0);
        
        println!("\n=== Data Transfer ===");
        println!("Total data received: {} bytes", metrics.bytes_in);
        println!("Total data sent: {} bytes", metrics.bytes_out);
        
        // Print status code distribution
        println!("\n=== Status Code Distribution ===");
        let status_codes = results.iter()
            .fold(std::collections::HashMap::new(), |mut acc, r| {
                *acc.entry(r.status_code).or_insert(0) += 1;
                acc
            });
        
        for (code, count) in status_codes.iter() {
            println!("{}: {} requests", code, count);
        }
        
        // Print error distribution
        let errors = results.iter()
            .filter_map(|r| r.error.as_ref())
            .fold(std::collections::HashMap::new(), |mut acc, e| {
                *acc.entry(e.as_str()).or_insert(0) += 1;
                acc
            });
        
        if !errors.is_empty() {
            println!("\n=== Error Distribution ===");
            for (error, count) in errors.iter() {
                println!("{}: {} occurrences", error, count);
            }
        }
    } else {
        println!("No results collected");
    }

    Ok(())
}