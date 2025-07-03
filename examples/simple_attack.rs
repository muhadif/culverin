use culverin::{AttackBuilder, get, calculate_metrics};
use std::time::Duration;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a target using the helper function
    let target = get("https://example.com")?;

    // Configure and run the attack
    let results = AttackBuilder::new()
        .rate(10.0)  // 10 requests per second
        .duration(Duration::from_secs(5))  // Run for 5 seconds
        .timeout(Duration::from_secs(3))   // 3 second timeout
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
    } else {
        println!("No results collected");
    }

    Ok(())
}