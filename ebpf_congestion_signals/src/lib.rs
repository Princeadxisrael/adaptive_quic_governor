//Define the library for collecting congestion signals/events from eBPF and aggregates them

use aya::{
    Ebpf, maps::perf::AsyncPerfEventArray, programs::{KProbe, TracePoint}, util::online_cpus
};
use aya::include_bytes_aligned;
use bytes::BytesMut;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::task;

// Mirror kernel-side types. I am defining them here again instead of sharing
// via a common crate because plain::from_bytes requires the types to implement
// the Plain trait in the userspace crate.
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
pub const EVENT_SOFTIRQ_ENTER: u32 = 5;
pub const EVENT_SOFTIRQ_EXIT: u32 = 6;
pub const EVENT_NET_DEV_QUEUE: u32 = 7;

/// Aggregated statistics from eBPF probes
#[derive(Debug, Clone, Default)]
pub struct CongestionSignals {
    pub send_bytes: u64,
    pub drops: u64,
    pub avg_wmem_pressure: f64,
    pub softirq_ns: u64,
    pub event_count: u64,
    pub queue_depth_packets: u64,
    pub queue_depth_bytes: u64,

}

/// Thread-safe atomic storage for signals
struct AtomicSignals {
    send_bytes: AtomicU64,
    drops: AtomicU64,
    wmem_samples: AtomicU64,
    wmem_total: AtomicU64,
    softirq_ns: AtomicU64,
    event_count: AtomicU64,
    queue_depth_packets:AtomicU64,
    queue_depth_bytes: AtomicU64
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
            queue_depth_packets:AtomicU64::new(0),
            queue_depth_bytes: AtomicU64::new(0)
        }
    }
}

pub struct CongestionCollector {
    ebpf: Ebpf,
    signals: Arc<AtomicSignals>,
}

impl CongestionCollector {
    /// Load and attach eBPF probes
    pub fn load() -> anyhow::Result<Self> {
        // Load ebpf bytecode...just ignore the red, loads when the program compiles
        #[cfg(debug_assertions)]
        let mut ebpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/congestion_signals"
        ))?;
        
        #[cfg(not(debug_assertions))]
        let mut ebpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/congestion_signals"
        ))?;

        log::info!("eBPF bytecode loaded successfully");
        // Attach kprobes
        log::info!("eBPF bytecode loaded successfully");
        let prog: &mut KProbe = ebpf.program_mut("udp_sendmsg").unwrap().try_into()?;
        prog.load()?;
        prog.attach("udp_sendmsg", 0)?;
        log::info!("udp_sendmsg attached");


         // Skip tcp_write_xmit for now - focus should be on getting basic probes working
        // let prog: &mut KProbe = ebpf.program_mut("tcp_write_xmit").unwrap().try_into()?;
        // prog.load()?;
        // prog.attach("tcp_write_xmit", 0)?;

        // Attach tracepoints
        log::info!("Attaching tracepoint: skb:kfree_skb");
        let prog: &mut TracePoint = ebpf.program_mut("skb_kfree").unwrap().try_into()?;
        prog.load()?;
        prog.attach("skb", "kfree_skb").map_err(|e| anyhow::anyhow!("Failed to attach skb:kfree_skb tracepoint: {}", e))?;
        log::info!("skb:kfree_skb attached");

        log::info!("Attaching tracepoint: net:net_dev_queue");
        let prog: &mut TracePoint = ebpf.program_mut("net_dev_queue").unwrap().try_into()?;
        prog.load()?;
        prog.attach("net", "net_dev_queue")?;
        log::info!("net:net_dev_queue tracepoint attached");


        log::info!("Attaching tracepoint: irq:softirq_entry");
        let prog: &mut TracePoint = ebpf.program_mut("softirq_entry").unwrap().try_into()?;
        prog.load()?;
        prog.attach("irq", "softirq_entry")?;
        log::info!("Attaching tracepoint: irq:softirq_exit");
        let prog: &mut TracePoint = ebpf.program_mut("softirq_exit").unwrap().try_into()?;
        prog.load()?;
        prog.attach("irq", "softirq_exit")?;
        log::info!("eBPF probes loaded and attached");

        // Verify kprobes are in kernel
        std::thread::sleep(std::time::Duration::from_millis(100));
        Self::verify_kprobes_attached()?;

        Ok(Self {
            ebpf,
            signals: Arc::new(AtomicSignals::default()),
        })
    }

    fn verify_kprobes_attached() -> anyhow::Result<()> {
        use std::fs;
        
        let kprobe_events = fs::read_to_string("/sys/kernel/debug/tracing/kprobe_events")
            .unwrap_or_default();
        
        log::info!("Verifying kprobe attachment...");
        log::info!("kprobe_events content:\n{}", kprobe_events);
        
        if kprobe_events.contains("udp_sendmsg") {
            log::info!("udp_sendmsg found in kprobe_events");
        } else {
            log::warn!("udp_sendmsg NOT found in kprobe_events");
        }
        
        Ok(())
    }
    /// Start collecting events in background tasks
    pub async fn start_collection(&mut self) -> anyhow::Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(self.ebpf.take_map("EVENTS").unwrap())?;

        // fixed online_cpus() should return Vec<32>
        let cpus= online_cpus()
            .map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;
        
        log::info!("Starting event collection on {} CPUs", cpus.len());

        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)?;
            let signals = self.signals.clone();

            task::spawn(async move {
                let mut buffers = vec![BytesMut::with_capacity(4096); 10];

                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for buf in buffers.iter_mut().take(events.read) {
                                let event = unsafe {
                                    plain::from_bytes::<CongestionEvent>(buf.as_ref()).unwrap()
                                };

                                Self::process_event(&signals, event);
                            }
                        }
                        Err(e) => {
                            log::error!("Error reading events from CPU {}: {}", cpu_id, e);
                        }
                    }
                }
            });
        }

        log::info!("Event collection started on all CPUs");
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
            EVENT_NET_DEV_QUEUE => unsafe {
                // NEW: Track queue depth
                let qdata = event.data.qdisc;
                signals.queue_depth_packets.fetch_add(qdata.backlog_packets as u64, Ordering::Relaxed);
                signals.queue_depth_bytes.fetch_add(qdata.backlog_bytes as u64, Ordering::Relaxed);
            },
            EVENT_SOCKET_STATE => unsafe {
                //mind ya: this is deprecated, just here for compactability
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
        let queue_depth_packets = self.signals.queue_depth_packets.swap(0, Ordering::Relaxed);
        let queue_depth_bytes = self.signals.queue_depth_bytes.swap(0, Ordering::Relaxed);

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
            queue_depth_packets,
            queue_depth_bytes,
            

        }
    }
}