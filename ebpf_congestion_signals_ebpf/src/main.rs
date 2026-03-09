#![no_std]
#![no_main]

mod types;

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns},
    macros::{kprobe, map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};

use types::*;

// Maps
#[map]
static EVENTS: PerfEventArray<CongestionEvent> = PerfEventArray::new(0);

#[map]
static SOFTIRQ_START: PerCpuArray<u64> = PerCpuArray::with_max_entries(10, 0);

/// Per-CPU sampling state for send operations
/// Note: Could be made per-socket by hashing socket pointer, but per-CPU is simpler
#[map]
static SEND_SAMPLE_STATE: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);


// Helper Functions
#[inline(always)]
fn should_sample_send() -> bool {
    // Sample every 100th send to reduce overhead
    // Adjust this ratio based on observed CPU overhead
    unsafe {
        if let Some(counter) = SEND_SAMPLE_STATE.get_ptr_mut(0) {
            let count = counter.read();
            counter.write(count.wrapping_add(1));
            return count % 100 == 0;
        }
    }
    false
}

// QUIC-Relevant Probes
/// Probe UDP sends - CRITICAL for QUIC (which runs over UDP)
#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_udp_sendmsg(ctx: ProbeContext) -> Result<(), i64> {
    if !should_sample_send() {
        return Ok(());
    }

    let sk: *const core::ffi::c_void = unsafe { ctx.arg(0).ok_or(1i64)? };
    let len: usize = unsafe { ctx.arg(2).ok_or(1i64)? };

    let event = CongestionEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        event_type: EVENT_UDP_SEND,
        cpu_id: unsafe { bpf_get_smp_processor_id() },
        data: EventData {
            sendmsg: SendMsgData {
                bytes: len as u64,
                is_tcp: 0,
                socket_id: sk as u64,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, (BPF_F_CURRENT_CPU as u64).try_into().unwrap());
    }

    Ok(())
}

/// Tracepoint for packet drops - detects network congestion
#[tracepoint]
pub fn skb_kfree(ctx: TracePointContext) -> u32 {
    match try_skb_kfree(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_skb_kfree(ctx: TracePointContext) -> Result<(), i64> {
    // TODO: Could read drop reason from args->reason to distinguish qdisc drops
    // from other types of drops (e.g., invalid packets, routing failures)
    
    let event = CongestionEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        event_type: EVENT_QDISC_DROP,
        cpu_id: unsafe { bpf_get_smp_processor_id() },
        data: EventData {
            qdisc: QdiscData {
                dropped: 1,
                backlog_bytes: 0,
                backlog_packets: 0,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, (BPF_F_CURRENT_CPU as u64).try_into().unwrap());
    }

    Ok(())
}

/// Tracepoint for qdisc queue events - leading indicator of congestion
/// This replaces the complex tcp_write_xmit approach for qdisc visibility
#[tracepoint]
pub fn net_dev_queue(ctx: TracePointContext) -> u32 {
    match try_net_dev_queue(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_net_dev_queue(ctx: TracePointContext) -> Result<(), i64> {
    // Tracepoint format (from /sys/kernel/debug/tracing/events/net/net_dev_queue/format):
    // field:void * skbaddr;
    // field:unsigned int len;
    // field:__data_loc char[] name;
    
    // Read packet length (offset may vary - typically at offset 16 or 24)
    let len = unsafe { ctx.read_at::<u32>(16).unwrap_or(0) };
    
    // We can sample this too if it generates too many events
    // For now, capture all queue events since they're already relatively infrequent
    
    let event = CongestionEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        event_type: EVENT_NET_DEV_QUEUE,
        cpu_id: unsafe { bpf_get_smp_processor_id() },
        data: EventData {
            qdisc: QdiscData {
                dropped: 0,
                backlog_bytes: len,
                backlog_packets: 1,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, (BPF_F_CURRENT_CPU as u64).try_into().unwrap());
    }

    Ok(())
}

/// Tracepoint for softirq entry - track when network interrupts start
#[tracepoint]
pub fn softirq_entry(ctx: TracePointContext) -> u32 {
    match try_softirq_entry(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_softirq_entry(ctx: TracePointContext) -> Result<(), i64> {
    // `vec` is typically at offset 8 after tracepoint common fields.
    // Keep a fallback at 16 for kernel/layout variance.
    let vec = unsafe {
        ctx.read_at::<u32>(8)
            .or_else(|_| ctx.read_at::<u32>(16))
            .unwrap_or(u32::MAX)
    };
    
    // Only track NET_TX_SOFTIRQ (2) and NET_RX_SOFTIRQ (3)
    if vec != 2 && vec != 3 {
        return Ok(());
    }

    let timestamp = unsafe { bpf_ktime_get_ns() };
    
    unsafe {
        if let Some(start_ptr) = SOFTIRQ_START.get_ptr_mut(vec) {
            start_ptr.write(timestamp);
        }
    }

    Ok(())
}

/// Tracepoint for softirq exit - calculate duration and send event
#[tracepoint]
pub fn softirq_exit(ctx: TracePointContext) -> u32 {
    match try_softirq_exit(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_softirq_exit(ctx: TracePointContext) -> Result<(), i64> {
    // `vec` is typically at offset 8 after tracepoint common fields.
    // Keep a fallback at 16 for kernel/layout variance.
    let vec = unsafe {
        ctx.read_at::<u32>(8)
            .or_else(|_| ctx.read_at::<u32>(16))
            .unwrap_or(u32::MAX)
    };
    
    if vec != 2 && vec != 3 {
        return Ok(());
    }

    let cpu = unsafe { bpf_get_smp_processor_id() };
    let exit_time = unsafe { bpf_ktime_get_ns() };
    
    let duration = unsafe {
        if let Some(start_ptr) = SOFTIRQ_START.get_ptr(vec) {
            let start_time = start_ptr.read();
            if start_time > 0 {
                exit_time - start_time
            } else {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    };

    let event = CongestionEvent {
        timestamp_ns: exit_time,
        event_type: EVENT_SOFTIRQ_EXIT,
        cpu_id: cpu,
        data: EventData {
            softirq: SoftirqData {
                vec_nr: vec,
                duration_ns: duration,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, (BPF_F_CURRENT_CPU as u64).try_into().unwrap());
    }

    Ok(())
}


// tcp_sendmsg - REMOVED: QUIC uses UDP, not TCP
// tcp_write_xmit - REMOVED: TCP-specific socket buffer tracking, not useful for QUIC

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
