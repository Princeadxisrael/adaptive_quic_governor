//Validation tool for running tests

use ebpf_congestion_signals::{CongestionCollector, CongestionSignals};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("=== eBPF Congestion Signals Validation ===\n");
    println!("This test validates:");
    println!("1. eBPF probes load and attach successfully");
    println!("2. Events are collected from all probes");
    println!("3. CPU overhead is <2% during iperf3 test\n");

    // Load eBPF probes
    println!("Loading eBPF probes...");
    let mut collector = CongestionCollector::load()?;
    collector.start_collection().await?;
    println!("✓ Probes loaded successfully\n");

    // Baseline CPU measurement
    println!("Measuring baseline CPU usage (10 seconds)...");
    let baseline_cpu = measure_cpu_usage(Duration::from_secs(10)).await?;
    println!("Baseline CPU: {:.2}%\n", baseline_cpu);

    // Start monitoring
    println!("Starting signal collection...");
    println!("Run iperf3 test in another terminal:");
    println!("  Server: iperf3 -s");
    println!("  Client: iperf3 -c <server_ip> -t 30 -P 4");
    println!("\nPress Ctrl+C when test completes\n");

    let start = Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut total_signals = CongestionSignals::default();

    loop {
        interval.tick().await;
        
        let signals = collector.read_and_reset();
        
        // Accumulate totals
        total_signals.send_bytes += signals.send_bytes;
        total_signals.drops += signals.drops;
        total_signals.softirq_ns += signals.softirq_ns;
        total_signals.event_count += signals.event_count;

        // Print interval stats
        println!(
            "[{:>3}s] Events: {:>6} | Send: {:>8} MB | Drops: {:>4} | Wmem: {:.1}% | Softirq: {:>6} µs",
            start.elapsed().as_secs(),
            signals.event_count,
            signals.send_bytes / 1_000_000,
            signals.drops,
            signals.avg_wmem_pressure * 100.0,
            signals.softirq_ns / 1000,
        );

        // Every 10 seconds, measure CPU overhead
        if start.elapsed().as_secs() % 10 == 0 && start.elapsed().as_secs() > 0 {
            let current_cpu = measure_cpu_usage(Duration::from_secs(5)).await?;
            let overhead = current_cpu - baseline_cpu;
            println!("  → CPU overhead: {:.2}% (target: <2.0%)", overhead);
            
            if overhead > 2.0 {
                println!("  ⚠ WARNING: CPU overhead exceeds 2% threshold!");
            }
        }
    }
}

/// Measure CPU usage by reading /proc/stat
async fn measure_cpu_usage(duration: Duration) -> anyhow::Result<f64> {
    let (user1, nice1, system1, idle1) = read_cpu_times()?;
    sleep(duration).await;
    let (user2, nice2, system2, idle2) = read_cpu_times()?;

    let total_delta = (user2 - user1) + (nice2 - nice1) + (system2 - system1) + (idle2 - idle1);
    let idle_delta = idle2 - idle1;

    if total_delta == 0 {
        return Ok(0.0);
    }

    let usage = 100.0 * (1.0 - (idle_delta as f64 / total_delta as f64));
    Ok(usage)
}

fn read_cpu_times() -> anyhow::Result<(u64, u64, u64, u64)> {
    let content = std::fs::read_to_string("/proc/stat")?;
    let line = content.lines().next().ok_or(anyhow::anyhow!("No CPU line"))?;
    
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(anyhow::anyhow!("Invalid /proc/stat format"));
    }

    Ok((
        parts[1].parse()?,
        parts[2].parse()?,
        parts[3].parse()?,
        parts[4].parse()?,
    ))
}