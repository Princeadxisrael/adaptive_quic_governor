#!/bin/bash
set -e

echo "=== Building eBPF Congestion Signals ==="

# Check prerequisites
echo "Checking prerequisites..."
command -v cargo >/dev/null 2>&1 || { echo "cargo not found. Install Rust."; exit 1; }

# Install bpf-linker if not present
if ! command -v bpf-linker >/dev/null 2>&1; then
    echo "Installing bpf-linker..."
    cargo install bpf-linker
fi

# Install nightly toolchain
echo "Setting up Rust nightly toolchain..."
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Build eBPF probes
echo ""
echo "Building eBPF probes (kernel code)..."
cd ebpf_congestion_signals_ebpf
cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core
echo "✓ eBPF probes built successfully"
cd ..

# Build userspace collector
echo ""
echo "Building userspace collector..."
cd ebpf_congestion_signals
cargo build --release
echo "✓ Userspace collector built successfully"
cd ..

echo ""
echo "✓ Build complete!"
echo ""
echo "Run validation test with:"
echo "  RUST_LOG=info sudo -E ../ebpf_congestion_signals/target/release/validate"
echo ""
echo "Or run diagnostic:"
echo "  sudo ./ebpf_congestion_signals/target/release/diagnose"