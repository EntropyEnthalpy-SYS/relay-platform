//! Explicit MPTCP socket selection and bounded observations of live sockets.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::net::TcpStream;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Off,
    Prefer,
    Require,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub inbound: Mode,
    #[serde(default)]
    pub outbound: Mode,
}

/// Fallback is allowed only for absence of kernel support, not resource,
/// permission, bind, routing or connection errors.
pub(crate) fn stream_socket(domain: Domain, mode: Mode) -> io::Result<Socket> {
    if mode != Mode::Off {
        #[cfg(target_os = "linux")]
        match Socket::new(domain, Type::STREAM, Some(Protocol::MPTCP)) {
            Ok(socket) => return Ok(socket),
            Err(error)
                if mode == Mode::Prefer
                    && matches!(
                        error.raw_os_error(),
                        Some(
                            nix::libc::EINVAL | nix::libc::EPROTONOSUPPORT | nix::libc::ENOPROTOOPT
                        )
                    ) => {}
            Err(error) => return Err(error),
        }
        #[cfg(not(target_os = "linux"))]
        if mode == Mode::Require {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MPTCP requires a supported Linux kernel",
            ));
        }
    }
    Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketInfo {
    /// None means that the kernel did not provide sufficient evidence.
    pub negotiated: Option<bool>,
    pub additional_subflows: Option<u32>,
    pub total_subflows: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub bytes_retransmitted: Option<u64>,
    pub observation_error: Option<String>,
}

#[cfg(target_os = "linux")]
fn option(socket: &Socket, level: i32, name: i32, bytes: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let mut length = bytes.len() as nix::libc::socklen_t;
    // The buffer is initialized, writable and remains borrowed for the call.
    // getsockopt returns its actual length; every decoded field is bounds checked.
    let result = unsafe {
        nix::libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok((length as usize).min(bytes.len()))
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", test))]
fn decode_info(bytes: &[u8]) -> SocketInfo {
    let u32_at = |at| {
        bytes
            .get(at..at + 4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
    };
    let u64_at = |at| {
        bytes
            .get(at..at + 8)
            .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
    };
    SocketInfo {
        negotiated: u32_at(8).map(|flags| flags & 1 == 0 && flags & 2 != 0),
        additional_subflows: bytes.first().copied().map(u32::from),
        total_subflows: bytes.get(80).copied().map(u32::from),
        bytes_sent: u64_at(56),
        bytes_received: u64_at(64),
        bytes_retransmitted: u64_at(48),
        observation_error: None,
    }
}

fn socket_info(socket: &Socket) -> SocketInfo {
    #[cfg(target_os = "linux")]
    {
        let mut bytes = [0u8; 128];
        let mut info = match option(socket, 284, 1, &mut bytes) {
            Ok(length) => decode_info(&bytes[..length]),
            Err(error) => SocketInfo {
                observation_error: Some(error.to_string()),
                ..Default::default()
            },
        };
        let mut flag = [0u8; 4];
        // TCP_IS_MPTCP is available from Linux 6.10 and distinguishes fallback
        // without interpreting unsupported older MPTCP_INFO as negotiation.
        if option(socket, 6, 43, &mut flag).is_ok() {
            info.negotiated = Some(i32::from_ne_bytes(flag) != 0);
            if info.negotiated == Some(false) {
                info.observation_error = None;
            }
        } else if socket.protocol().ok().flatten() == Some(Protocol::TCP) {
            info.negotiated = Some(false);
            info.observation_error = None;
        }
        info
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        SocketInfo {
            negotiated: Some(false),
            ..Default::default()
        }
    }
}

pub fn inspect(stream: &TcpStream) -> SocketInfo {
    socket_info(&SockRef::from(stream))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub id: u64,
    pub rule_id: String,
    pub direction: String,
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub info: SocketInfo,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub active_sockets: u64,
    pub negotiated_total: u64,
    pub fallback_total: u64,
    pub unknown_total: u64,
    pub required_rejections: u64,
    /// At most 128 live sockets, inspected again on each stats sample.
    pub connections: Vec<Connection>,
}
impl Snapshot {
    pub fn empty(&self) -> bool {
        self.active_sockets == 0
            && self.negotiated_total == 0
            && self.fallback_total == 0
            && self.unknown_total == 0
            && self.required_rejections == 0
    }
}

struct Observed {
    socket: Socket,
    metadata: Connection,
}
#[derive(Default)]
pub(crate) struct Tracker {
    sequence: AtomicU64,
    active: AtomicU64,
    negotiated: AtomicU64,
    fallback: AtomicU64,
    unknown: AtomicU64,
    rejected: AtomicU64,
    observed: Mutex<BTreeMap<u64, Observed>>,
}
impl Tracker {
    pub(crate) fn track(
        self: &Arc<Self>,
        stream: &TcpStream,
        mode: Mode,
        rule: &str,
        direction: &str,
    ) -> Result<Option<Guard>> {
        if mode == Mode::Off {
            return Ok(None);
        }
        let info = inspect(stream);
        if mode == Mode::Require && info.negotiated != Some(true) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!(
                "MPTCP negotiation required; peer fell back or kernel could not confirm it"
            );
        }
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let local = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let mut observed = self.observed.lock().unwrap();
        // Duplicates are solely for live inspection and close with the tunnel.
        // A full observation table never rejects legitimate business traffic.
        if observed.len() < 128
            && let Ok(socket) = SockRef::from(stream).try_clone()
        {
            observed.insert(
                id,
                Observed {
                    socket,
                    metadata: Connection {
                        id,
                        rule_id: rule.to_owned(),
                        direction: direction.to_owned(),
                        local,
                        peer,
                        info: info.clone(),
                    },
                },
            );
        }
        match info.negotiated {
            Some(true) => &self.negotiated,
            Some(false) => &self.fallback,
            None => &self.unknown,
        }
        .fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Ok(Some(Guard {
            id,
            tracker: self.clone(),
        }))
    }
    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        let snapshot = Snapshot {
            active_sockets: self.active.load(Ordering::Relaxed),
            negotiated_total: self.negotiated.load(Ordering::Relaxed),
            fallback_total: self.fallback.load(Ordering::Relaxed),
            unknown_total: self.unknown.load(Ordering::Relaxed),
            required_rejections: self.rejected.load(Ordering::Relaxed),
            connections: self
                .observed
                .lock()
                .unwrap()
                .values()
                .map(|entry| Connection {
                    info: socket_info(&entry.socket),
                    ..entry.metadata.clone()
                })
                .collect(),
        };
        (!snapshot.empty()).then_some(snapshot)
    }
}
pub(crate) struct Guard {
    id: u64,
    tracker: Arc<Tracker>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.tracker.observed.lock().unwrap().remove(&self.id);
        self.tracker.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Config {
    pub fn validate(&self, tcp: bool) -> Result<()> {
        ensure!(tcp, "MPTCP requires a TCP-capable rule");
        ensure!(
            self.inbound != Mode::Off || self.outbound != Mode::Off,
            "MPTCP configuration must enable at least one direction"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_kernel_layout_does_not_invent_missing_subflows_or_bytes() {
        let mut bytes = [0u8; 40];
        bytes[0] = 2;
        bytes[8..12].copy_from_slice(&2u32.to_ne_bytes());
        let info = decode_info(&bytes);
        assert_eq!(info.negotiated, Some(true));
        assert_eq!(info.additional_subflows, Some(2));
        assert_eq!(info.total_subflows, None);
        assert_eq!(info.bytes_sent, None);
        bytes[8..12].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(decode_info(&bytes).negotiated, Some(false));
    }
    #[test]
    fn new_kernel_fields_are_length_checked() {
        let mut bytes = [0u8; 96];
        bytes[80] = 3;
        bytes[56..64].copy_from_slice(&1234u64.to_ne_bytes());
        let info = decode_info(&bytes);
        assert_eq!(info.total_subflows, Some(3));
        assert_eq!(info.bytes_sent, Some(1234));
        assert_eq!(decode_info(&bytes[..80]).total_subflows, None);
    }
}
