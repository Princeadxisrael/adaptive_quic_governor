# eBPF Congestion Signals

Kernel-space network telemetry for congestion-aware QUIC governor.

## Project Structure

```
ebpf-congestion-signals/
├── Cargo.toml                           # Workspace root
├── build.sh                             # Build script
├── README.md                            
├── ebpf-congestion-signals-ebpf/        # eBPF kernel probes
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                      # Probe implementations
│       └── types.rs                     # Shared data structures
└── ebpf-congestion-signals/             # Userspace collector
    ├── Cargo.toml
    └── src/
        ├── lib.rs                       # Collector library
        └── bin/
            └── validate.rs              # Validation tool
```

## What It Does

This crate collects kernel-level network congestion signals:

1. **Send rate** - UDP/TCP bytes sent (sampled)
2. **Packet drops** - Detected via `skb:kfree_skb` tracepoint
3. **Socket buffer pressure** - `sk_wmem_queued` occupancy
4. **Softirq CPU time** - Network interrupt processing cost

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential clang llvm libelf-dev linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install clang llvm elfutils-libelf-devel kernel-devel

# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building

```bash
# Quick build (uses build.sh)
chmod +x build.sh
./build.sh

# Or manually:
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

cd ebpf-congestion-signals-ebpf
cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core
cd ../ebpf-congestion-signals
cargo build --release
```

## Running Validation Test

The validation tool verifies:
- eBPF probes attach successfully
- Events are collected correctly
- CPU overhead is <2%

```bash
# Terminal 1: Run validator (requires root for eBPF)
sudo ./ebpf-congestion-signals/target/release/validate

# Terminal 2: Run iperf3 test
# Server:
iperf3 -s

# Client (on another machine):
iperf3 -c <server_ip> -t 30 -P 4 -u -b 500M
```

### Expected Output

```
=== eBPF Congestion Signals Validation ===

Loading eBPF probes...
✓ Probes loaded successfully

Measuring baseline CPU usage (10 seconds)...
Baseline CPU: 5.23%

Starting signal collection...
Run iperf3 test in another terminal:
  Server: iperf3 -s
  Client: iperf3 -c <server_ip> -t 30 -P 4

[  1s] Events:   1234 | Send:       45 MB | Drops:    0 | Wmem: 32.1% | Softirq:   1234 µs
[  2s] Events:   2456 | Send:       89 MB | Drops:    0 | Wmem: 28.5% | Softirq:   2456 µs
  → CPU overhead: 0.82% (target: <2.0%)
```

## Project Application

### Add as dependency

```toml
[dependencies]
ebpf-congestion-signals = { path = "../ebpf-congestion-signals" }
```

### Basic usage

```rust
use ebpf_congestion_signals::{CongestionCollector, CongestionSignals};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load and start collector
    let mut collector = CongestionCollector::load()?;
    collector.start_collection().await?;

    // Read signals every 200ms
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    loop {
        interval.tick().await;
        let signals = collector.read_and_reset();
        
        // Feed to your governor
        governor.update(signals);
    }
}
```

### Signal structure

```rust
pub struct CongestionSignals {
    pub send_bytes: u64,           // Bytes sent in last interval
    pub drops: u64,                // Packet drops detected
    pub avg_wmem_pressure: f64,    // Socket buffer pressure (0.0-1.0)
    pub softirq_ns: u64,          // Nanoseconds in network softirq
    pub event_count: u64,          // Total events processed
}
```

## Troubleshooting (Tentative)

### Probes fail to attach

```bash
# Check if kprobes are available
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep udp_sendmsg

# Check if tracepoints exist
sudo ls /sys/kernel/debug/tracing/events/skb/
sudo ls /sys/kernel/debug/tracing/events/irq/
```

### High CPU overhead

If overhead exceeds 2%, reduce sampling rate:

Edit `ebpf-congestion-signals-ebpf/src/main.rs`:
```rust
fn should_sample_send() -> bool {
    //  change 100 to 500 for 0.2% sampling
    return count % 500 == 0;
}
```

### Wrong socket buffer offsets

The offsets for `sk_wmem_queued` (0x88) and `sk_sndbuf` (0x8C) are **kernel version dependent**.

Find correct offsets for your kernel:
```bash
# Using pahole (requires dwarves package)
sudo pahole -C sock /usr/lib/debug/boot/vmlinux-$(uname -r) | grep -E 'sk_wmem_queued|sk_sndbuf'
```

Update in `ebpf-congestion-signals-ebpf/src/main.rs`:
```rust
const SK_WMEM_QUEUED_OFFSET: usize = 0x88;  // Your offset here
const SK_SNDBUF_OFFSET: usize = 0x8C;       // Your offset here
```

## Next Steps

1. **Integrate with governor** - Use `CongestionSignals` in our control loop
2. **Add qdisc backlog** - Requires reading qdisc structs (This would be more complex than sk_buff but doable and definitly a step in the right direction)
3. **BTF/CO-RE** - For portable struct offsets across kernels
4. **Tune sampling** - Adjust based on our workload
