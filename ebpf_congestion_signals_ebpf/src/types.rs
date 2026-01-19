//Shared types between kernel and userspace

/// Event sent to userspace via ring buffer
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CongestionEvent {
    pub timestamp_ns: u64,
    pub event_type: u32,
    pub cpu_id: u32,
    pub data: EventData,
}

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

// Event type discriminators
pub const EVENT_UDP_SEND: u32 = 1;
pub const EVENT_TCP_SEND: u32 = 2;
pub const EVENT_QDISC_DROP: u32 = 3;
pub const EVENT_SOCKET_STATE: u32 = 4;
pub const EVENT_SOFTIRQ_ENTER: u32 = 5;
pub const EVENT_SOFTIRQ_EXIT: u32 = 6;