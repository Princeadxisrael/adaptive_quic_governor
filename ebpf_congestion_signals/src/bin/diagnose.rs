/// Diagnostic tool to test eBPF probe attachment
/// This bypasses Aya and uses bpftool to verify kernel support

use std::process::Command;
use std::fs;

fn main() {
    println!("=== eBPF Probe Diagnostic Tool ===\n");
    
    // Check kernel version
    println!("1. Checking kernel version...");
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to run uname");
    let kernel = String::from_utf8_lossy(&output.stdout);
    println!("   Kernel: {}", kernel.trim());
    
    // Check if debugfs is mounted
    println!("\n2. Checking debugfs mount...");
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    if mounts.contains("debugfs") {
        println!("   ✓ debugfs is mounted");
        
        // Find mount point
        for line in mounts.lines() {
            if line.contains("debugfs") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    println!("   Mount point: {}", parts[1]);
                }
            }
        }
    } else {
        println!("   ✗ debugfs is NOT mounted");
        println!("   Run: sudo mount -t debugfs none /sys/kernel/debug");
        return;
    }
    
    //maybe we can read tracing directory
    println!("\n3. Checking tracing access...");
    match fs::read_dir("/sys/kernel/debug/tracing") {
        Ok(_) => println!("   ✓ Can access /sys/kernel/debug/tracing"),
        Err(e) => {
            println!("   ✗ Cannot access /sys/kernel/debug/tracing: {}", e);
            println!("   Run this program with sudo");
            return;
        }
    }
    
    // 4. Check available functions
    println!("\n4. Checking if target functions exist...");
    let funcs = fs::read_to_string("/sys/kernel/debug/tracing/available_filter_functions")
        .unwrap_or_default();
    
    for func in &["udp_sendmsg", "tcp_sendmsg", "tcp_write_xmit"] {
        if funcs.contains(func) {
            println!("   ✓ {} is available", func);
        } else {
            println!("   ✗ {} NOT found", func);
        }
    }
    
    // 5. Check available tracepoints
    println!("\n5. Checking tracepoints...");
    let check_tracepoint = |category: &str, name: &str| {
        let path = format!("/sys/kernel/debug/tracing/events/{}/{}", category, name);
        if fs::metadata(&path).is_ok() {
            println!("   ✓ {}:{} exists", category, name);
            true
        } else {
            println!("   ✗ {}:{} NOT found", category, name);
            false
        }
    };
    
    check_tracepoint("skb", "kfree_skb");
    check_tracepoint("irq", "softirq_entry");
    check_tracepoint("irq", "softirq_exit");
    
    // 6. Check if bpftool is available
    println!("Checking bpftool...");
    match Command::new("bpftool").arg("version").output() {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout);
            println!("   ✓ bpftool found: {}", version.trim());
        }
        Err(_) => {
            println!("   ✗ bpftool not found");
            println!("   Install: sudo apt install linux-tools-generic");
        }
    }
    
    // 7. Try manual kprobe creation
    println!("Testing manual kprobe creation...");
    println!("   Creating test kprobe for udp_sendmsg...");
    
    // Clear any existing probe
    let _ = fs::write("/sys/kernel/debug/tracing/kprobe_events", "-:testprobe_udp\n");
    
    // Try to create a simple kprobe
    match fs::write("/sys/kernel/debug/tracing/kprobe_events", "p:testprobe_udp udp_sendmsg\n") {
        Ok(_) => {
            println!("   ✓ Successfully created test kprobe");
            
            // Check if it appears
            let events = fs::read_to_string("/sys/kernel/debug/tracing/kprobe_events")
                .unwrap_or_default();
            
            if events.contains("testprobe_udp") {
                println!("   Test kprobe visible in kprobe_events");
            } else {
                println!("   Test kprobe NOT visible in kprobe_events");
            }
            
            // Clean up
            let _ = fs::write("/sys/kernel/debug/tracing/kprobe_events", "-:testprobe_udp\n");
            println!("   Cleaned up test kprobe");
        }
        Err(e) => {
            println!("   Failed to create test kprobe: {}", e);
            println!("   This might indicate a permissions or kernel issue");
        }
    }
    
    // 8. Check currently loaded BPF programs
    println!("\n8. Checking loaded BPF programs...");
    match Command::new("bpftool").args(&["prog", "list"]).output() {
        Ok(output) => {
            let progs = String::from_utf8_lossy(&output.stdout);
            if progs.is_empty() {
                println!("   No BPF programs currently loaded");
            } else {
                println!("   Currently loaded BPF programs:");
                for line in progs.lines().take(10) {
                    println!("   {}", line);
                }
            }
        }
        Err(_) => {
            println!("   Could not list BPF programs (bpftool not available)");
        }
    }
    
    
}