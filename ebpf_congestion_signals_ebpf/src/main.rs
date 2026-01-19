#![no_std]
#![no_main]

mod types;

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};

use types::*;

// ============================================================================
// Maps
// ============================================================================

#[map]
static EVENTS: PerfEventArray<CongestionEvent> = PerfEventArray::with_max_entries(1024, 0);

#[map]
static SOFTIRQ_START: PerCpuArray<u64> = PerCpuArray::with_max_entries(10, 0); //per CPU state

#[map]
static SEND_SAMPLE_STATE: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);


// Helper Functions

#[inline(always)]
unsafe fn read_kernel<T>(src: *const T) -> Result<T, i64> {
    bpf_probe_read_kernel(src).map_err(|e| e as i64)
}

#[inline(always)]
fn should_sample_send() -> bool {
    // Sample every 100th send to reduce overhead
    unsafe {
        if let Some(counter) = SEND_SAMPLE_STATE.get_ptr_mut(0) {
            let count = counter.read();
            counter.write(count.wrapping_add(1));
            return count % 100 == 0;
        }
    }
    false
}

// Probes

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
        EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);
    }

    Ok(())
}

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<(), i64> {
    if !should_sample_send() {
        return Ok(());
    }

    let sk: *const core::ffi::c_void = unsafe { ctx.arg(0).ok_or(1i64)? };
    let len: usize = unsafe { ctx.arg(2).ok_or(1i64)? };

    let event = CongestionEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        event_type: EVENT_TCP_SEND,
        cpu_id: unsafe { bpf_get_smp_processor_id() },
        data: EventData {
            sendmsg: SendMsgData {
                bytes: len as u64,
                is_tcp: 1,
                socket_id: sk as u64,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);
    }

    Ok(())
}

//tracepoint for kfree_skb to track drops
#[tracepoint]
pub fn skb_kfree(ctx: TracePointContext) -> u32 {
    match try_skb_kfree(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_skb_kfree(ctx: TracePointContext) -> Result<(), i64> {
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
        EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);
    }

    Ok(())
}

#[kprobe]
pub fn tcp_write_xmit(ctx: ProbeContext) -> u32 {
    match try_tcp_write_xmit(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_write_xmit(ctx: ProbeContext) -> Result<(), i64> {
    if !should_sample_send() {
        return Ok(());
    }

    let sk: *const u8 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // WARNING: These offsets are kernel version dependent!
    // Use BTF/CO-RE in production for portability
    const SK_WMEM_QUEUED_OFFSET: usize = 0x88;
    const SK_SNDBUF_OFFSET: usize = 0x8C;
    
    let wmem_queued = unsafe {
        let wmem_ptr = sk.add(SK_WMEM_QUEUED_OFFSET) as *const i32;
        read_kernel(wmem_ptr).unwrap_or(0)
    };
    
    let sndbuf = unsafe {
        let sndbuf_ptr = sk.add(SK_SNDBUF_OFFSET) as *const i32;
        read_kernel(sndbuf_ptr).unwrap_or(0)
    };

    let event = CongestionEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        event_type: EVENT_SOCKET_STATE,
        cpu_id: unsafe { bpf_get_smp_processor_id() },
        data: EventData {
            socket: SocketData {
                wmem_queued: wmem_queued as u32,
                sndbuf: sndbuf as u32,
                socket_id: sk as u64,
            },
        },
    };

    unsafe {
        EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);
    }

    Ok(())
}

#[tracepoint]
pub fn softirq_entry(ctx: TracePointContext) -> u32 {
    match try_softirq_entry(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_softirq_entry(ctx: TracePointContext) -> Result<(), i64> {
    let vec = unsafe { ctx.read_at::<u32>(16).map_err(|_| 1i64)? };
    
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

#[tracepoint]
pub fn softirq_exit(ctx: TracePointContext) -> u32 {
    match try_softirq_exit(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_softirq_exit(ctx: TracePointContext) -> Result<(), i64> {
    let vec = unsafe { ctx.read_at::<u32>(16).map_err(|_| 1i64)? };
    
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
        EVENTS.output(&ctx, &event, BPF_F_CURRENT_CPU as u64);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}