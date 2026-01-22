//Define the library for collecting congestion signals/events from eBPF and aggregates them

use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{KProbe, TracePoint},
    util::online_cpus,
};
use aya::include_bytes_aligned;
use aya::Bpf;
use bytes::BytesMut;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::task;

// Mirror kernel-side types
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CongestionEvent {
    pub timestamp_ns: u64,
    pub event_type: u32,
    pub cpu_id: u32,
    pub data: EventData,
}

// SAFETY: CongestionEvent is repr(C) and contains only POD types
unsafe impl plain::Plain for CongestionEvent {}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EventData {
    pub sendmsg: SendMsgData,
    pub qdisc: QdiscData,
    pub socket: SocketData,
    pub softirq: SoftirqData,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SendMsgData {
    pub bytes: u64,
    pub is_tcp: u32,
    pub socket_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QdiscData {
    pub dropped: u32,
    pub backlog_bytes: u32,
    pub backlog_packets: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketData {
    pub wmem_queued: u32,
    pub sndbuf: u32,
    pub socket_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SoftirqData {
    pub vec_nr: u32,
    pub duration_ns: u64,
}

impl std::fmt::Debug for EventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventData {{ ... }}")
    }
}

pub const EVENT_UDP_SEND: u32 = 1;
pub const EVENT_TCP_SEND: u32 = 2;
pub const EVENT_QDISC_DROP: u32 = 3;
pub const EVENT_SOCKET_STATE: u32 = 4;
pub const EVENT_SOFTIRQ_EXIT: u32 = 6;

/// Aggregated statistics from eBPF probes
#[derive(Debug, Clone, Default)]
pub struct CongestionSignals {
    pub send_bytes: u64,
    pub drops: u64,
    pub avg_wmem_pressure: f64,
    pub softirq_ns: u64,
    pub event_count: u64,
}

/// Thread-safe atomic storage for signals
struct AtomicSignals {
    send_bytes: AtomicU64,
    drops: AtomicU64,
    wmem_samples: AtomicU64,
    wmem_total: AtomicU64,
    softirq_ns: AtomicU64,
    event_count: AtomicU64,
}

impl Default for AtomicSignals {
    fn default() -> Self {
        Self {
            send_bytes: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            wmem_samples: AtomicU64::new(0),
            wmem_total: AtomicU64::new(0),
            softirq_ns: AtomicU64::new(0),
            event_count: AtomicU64::new(0),
        }
    }
}

pub struct CongestionCollector {
    ebpf: Bpf,
    signals: Arc<AtomicSignals>,
}

impl CongestionCollector {
    /// Load and attach eBPF probes
    pub fn load() -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let mut ebpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/congestion_signals"
        ))?;

        // Attach kprobes
        let prog: &mut KProbe = ebpf.program_mut("udp_sendmsg").unwrap().try_into()?;
        prog.load()?;
        prog.attach("udp_sendmsg", 0)?;

        let prog: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
        prog.load()?;
        prog.attach("tcp_sendmsg", 0)?;

        let prog: &mut KProbe = ebpf.program_mut("tcp_write_xmit").unwrap().try_into()?;
        prog.load()?;
        prog.attach("tcp_write_xmit", 0)?;

        // Attach tracepoints
        let prog: &mut TracePoint = ebpf.program_mut("skb_kfree").unwrap().try_into()?;
        prog.load()?;
        prog.attach("skb", "kfree_skb")?;

        let prog: &mut TracePoint = ebpf.program_mut("softirq_entry").unwrap().try_into()?;
        prog.load()?;
        prog.attach("irq", "softirq_entry")?;

        let prog: &mut TracePoint = ebpf.program_mut("softirq_exit").unwrap().try_into()?;
        prog.load()?;
        prog.attach("irq", "softirq_exit")?;

        log::info!("eBPF probes loaded and attached successfully");

        Ok(Self {
            ebpf,
            signals: Arc::new(AtomicSignals::default()),
        })
    }

    /// Start collecting events in background tasks
    pub async fn start_collection(&mut self) -> anyhow::Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(self.ebpf.take_map("EVENTS").unwrap())?;

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            let signals = self.signals.clone();

            task::spawn(async move {
                let mut buffers = vec![BytesMut::with_capacity(4096); 10];

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let event = unsafe {
                            plain::from_bytes::<CongestionEvent>(buf.as_ref()).unwrap()
                        };

                        Self::process_event(&signals, event);
                    }
                }
            });
        }

        log::info!("Started event collection on {} CPUs", online_cpus()?.len());
        Ok(())
    }

    fn process_event(signals: &AtomicSignals, event: &CongestionEvent) {
        signals.event_count.fetch_add(1, Ordering::Relaxed);

        match event.event_type {
            EVENT_UDP_SEND | EVENT_TCP_SEND => unsafe {
                let bytes = event.data.sendmsg.bytes;
                signals.send_bytes.fetch_add(bytes, Ordering::Relaxed);
            },
            EVENT_QDISC_DROP => {
                signals.drops.fetch_add(1, Ordering::Relaxed);
            }
            EVENT_SOCKET_STATE => unsafe {
                let wmem = event.data.socket.wmem_queued;
                let sndbuf = event.data.socket.sndbuf;
                if sndbuf > 0 {
                    let pressure = (wmem as u64 * 1000) / (sndbuf as u64);
                    signals.wmem_total.fetch_add(pressure, Ordering::Relaxed);
                    signals.wmem_samples.fetch_add(1, Ordering::Relaxed);
                }
            },
            EVENT_SOFTIRQ_EXIT => unsafe {
                let duration = event.data.softirq.duration_ns;
                signals.softirq_ns.fetch_add(duration, Ordering::Relaxed);
            },
            _ => {}
        }
    }

    /// Get current aggregated signals and reset counters
    pub fn read_and_reset(&self) -> CongestionSignals {
        let send_bytes = self.signals.send_bytes.swap(0, Ordering::Relaxed);
        let drops = self.signals.drops.swap(0, Ordering::Relaxed);
        let wmem_total = self.signals.wmem_total.swap(0, Ordering::Relaxed);
        let wmem_samples = self.signals.wmem_samples.swap(0, Ordering::Relaxed);
        let softirq_ns = self.signals.softirq_ns.swap(0, Ordering::Relaxed);
        let event_count = self.signals.event_count.swap(0, Ordering::Relaxed);

        let avg_wmem_pressure = if wmem_samples > 0 {
            (wmem_total as f64) / (wmem_samples as f64) / 1000.0
        } else {
            0.0
        };

        CongestionSignals {
            send_bytes,
            drops,
            avg_wmem_pressure,
            softirq_ns,
            event_count,
        }
    }
}