//! Preserve the concrete destination and reply source on wildcard UDP listeners.
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod packet_info {
    use super::*;
    use nix::{
        libc,
        sys::socket::{
            self, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, sockopt,
        },
    };
    use std::{
        io::{IoSlice, IoSliceMut},
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
        os::fd::AsRawFd,
    };
    use tokio::io::Interest;

    pub fn configure(socket: &socket2::Socket, address: SocketAddr) -> io::Result<()> {
        if address.is_ipv4() {
            socket::setsockopt(socket, sockopt::Ipv4PacketInfo, &true)?;
        } else {
            socket::setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true)?;
        }
        Ok(())
    }
    pub async fn receive(
        socket: &UdpSocket,
        buffer: &mut [u8],
        bound: SocketAddr,
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        socket
            .async_io(Interest::READABLE, || {
                let mut ancillary = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo);
                let mut slices = [IoSliceMut::new(buffer)];
                let message = socket::recvmsg::<SockaddrStorage>(
                    socket.as_raw_fd(),
                    &mut slices,
                    Some(&mut ancillary),
                    MsgFlags::MSG_DONTWAIT,
                )?;
                if message
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated UDP data or packet information",
                    ));
                }
                let peer = message
                    .address
                    .ok_or_else(|| io::Error::other("UDP source missing"))?;
                let peer = if let Some(v4) = peer.as_sockaddr_in() {
                    SocketAddr::from(*v4)
                } else if let Some(v6) = peer.as_sockaddr_in6() {
                    SocketAddr::from(*v6)
                } else {
                    return Err(io::Error::other("non-IP UDP source"));
                };
                let mut destination = None;
                for item in message.cmsgs()? {
                    match item {
                        ControlMessageOwned::Ipv4PacketInfo(info) => {
                            destination = Some(SocketAddr::new(
                                Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                                bound.port(),
                            ))
                        }
                        ControlMessageOwned::Ipv6PacketInfo(info) => {
                            let ip = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                            destination = Some(SocketAddr::V6(SocketAddrV6::new(
                                ip,
                                bound.port(),
                                0,
                                if ip.is_unicast_link_local() {
                                    info.ipi6_ifindex
                                } else {
                                    0
                                },
                            )));
                        }
                        _ => {}
                    }
                }
                let destination = destination
                    .filter(|a| !a.ip().is_unspecified())
                    .ok_or_else(|| {
                        io::Error::other("UDP destination packet information missing")
                    })?;
                Ok((message.bytes, peer, destination))
            })
            .await
    }
    pub async fn send(
        socket: &UdpSocket,
        data: &[u8],
        peer: SocketAddr,
        local: SocketAddr,
    ) -> io::Result<usize> {
        let peer = SockaddrStorage::from(peer);
        socket
            .async_io(Interest::WRITABLE, || {
                let slices = [IoSlice::new(data)];
                let size = match local {
                    SocketAddr::V4(local) => {
                        let info = libc::in_pktinfo {
                            ipi_ifindex: 0,
                            ipi_spec_dst: libc::in_addr {
                                s_addr: u32::from_ne_bytes(local.ip().octets()),
                            },
                            ipi_addr: libc::in_addr { s_addr: 0 },
                        };
                        socket::sendmsg(
                            socket.as_raw_fd(),
                            &slices,
                            &[ControlMessage::Ipv4PacketInfo(&info)],
                            MsgFlags::MSG_DONTWAIT,
                            Some(&peer),
                        )?
                    }
                    SocketAddr::V6(local) => {
                        let info = libc::in6_pktinfo {
                            ipi6_ifindex: local.scope_id(),
                            ipi6_addr: libc::in6_addr {
                                s6_addr: local.ip().octets(),
                            },
                        };
                        socket::sendmsg(
                            socket.as_raw_fd(),
                            &slices,
                            &[ControlMessage::Ipv6PacketInfo(&info)],
                            MsgFlags::MSG_DONTWAIT,
                            Some(&peer),
                        )?
                    }
                };
                Ok(size)
            })
            .await
    }
}

pub(crate) fn configure(socket: &socket2::Socket, address: SocketAddr) -> io::Result<()> {
    if !address.ip().is_unspecified() {
        return Ok(());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        packet_info::configure(socket, address)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wildcard UDP destination tracking requires Linux or macOS; bind a concrete IP",
        ))
    }
}
pub(crate) async fn receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    bound: SocketAddr,
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    if !bound.ip().is_unspecified() {
        let (size, peer) = socket.recv_from(buffer).await?;
        return Ok((size, peer, bound));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        packet_info::receive(socket, buffer, bound).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wildcard UDP packet information unsupported",
        ))
    }
}
pub(crate) async fn send(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
    local: SocketAddr,
    wildcard: bool,
) -> io::Result<usize> {
    if !wildcard {
        return socket.send_to(data, peer).await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        packet_info::send(socket, data, peer, local).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = local;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wildcard UDP packet information unsupported",
        ))
    }
}
