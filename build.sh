#!/bin/bash
set -e

echo "=== Building eBPF Congestion Signals ==="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
check_installed() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $2 found"
        return 0
    else
        echo -e "${RED}✗${NC} $2 not found"
        return 1
    fi
}

check_component() {
    if "$@" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $2"
        return 0
    else
        echo -e "${RED}✗${NC} $2 missing"
        return 1
    fi
}

# Check prerequisites
echo "Checking prerequisites..."

# Check cargo
if ! check_installed cargo "cargo (Rust toolchain)"; then
    echo -e "${YELLOW}Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Check nightly toolchain
if rustup toolchain list | grep -q nightly; then
    echo -e "${GREEN}✓${NC} Rust nightly toolchain installed"
else
    echo -e "${YELLOW}Installing nightly toolchain...${NC}"
    rustup toolchain install nightly
fi

# Check rust-src component
if rustup component list --toolchain nightly | grep -q "rust-src.*installed"; then
    echo -e "${GREEN}✓${NC} rust-src component installed"
else
    echo -e "${YELLOW}Installing rust-src component...${NC}"
    rustup component add rust-src --toolchain nightly
fi

# Check bpf-linker
if ! check_installed bpf-linker "bpf-linker"; then
    echo -e "${YELLOW}Installing bpf-linker...${NC}"
    cargo install bpf-linker
fi

echo ""
echo -e "${GREEN}All prerequisites satisfied!${NC}"
echo ""

# Determine build mode
BUILD_MODE="${1:-release}"
if [[ "$BUILD_MODE" == "debug" ]]; then
    CARGO_BUILD_FLAGS=""
    BUILD_DIR="debug"
    echo "Building in DEBUG mode..."
else
    CARGO_BUILD_FLAGS="--release"
    BUILD_DIR="release"
    echo "Building in RELEASE mode..."
fi

# Build eBPF probes
echo ""
echo "Building eBPF probes (kernel code)..."
cd  ebpf_congestion_signals_ebpf

if cargo +nightly build $CARGO_BUILD_FLAGS --target=bpfel-unknown-none -Z build-std=core; then
    echo -e "${GREEN}✓${NC} eBPF probes built successfully"
else
    echo -e "${RED}✗${NC} eBPF probe build failed"
    exit 1
fi

cd ..

# Build userspace collector
echo ""
echo "Building userspace collector..."
cd ebpf_congestion_signals

if cargo build $CARGO_BUILD_FLAGS; then
    echo -e "${GREEN}✓${NC} Userspace collector built successfully"
else
    echo -e "${RED}✗${NC} Userspace build failed"
    exit 1
fi

cd ..

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Build complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Binaries location:"
echo "  Validator: ./ebpf-congestion-signals/target/$BUILD_DIR/validate"
echo "  Diagnostic: ./ebpf-congestion-signals/target/$BUILD_DIR/diagnose"
echo ""
echo "Run validation test:"
echo "  sudo RUST_LOG=info ./ebpf-congestion-signals/target/$BUILD_DIR/validate"
echo ""
echo "Run diagnostic:"
echo "  sudo ./ebpf-congestion-signals/target/$BUILD_DIR/diagnose"
echo ""
echo "Build options:"
echo "  ./build.sh           # Release build (default)"
echo "  ./build.sh debug     # Debug build"
echo "  ./build.sh clean     # Clean build artifacts"
echo ""

# Handle clean command
if [[ "$1" == "clean" ]]; then
    echo "Cleaning build artifacts..."
    cd ebpf-congestion-signals-ebpf && cargo clean && cd ..
    cd ebpf-congestion-signals && cargo clean && cd ..
    echo -e "${GREEN}✓${NC} Clean complete"
fi