//! UDP-over-TCP uses the SS session's existing source ACL, connection limit,
//! cancellation and authentication. Datagram payloads use the ordinary meter,
//! destination policy, rate limits and bounded route table.
use super::*;
use crate::shadowsocks_uot as wire;

pub(super) async fn relay(
    mut session: shadowsocks::Session,
    version: u8,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
    inlet: ListenerKey,
) -> Result<()> {
    let activity = Arc::new(StdMutex::new(Instant::now()));
    let relay = async {
        let connected = timeout_at(
            Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms),
            wire::request(&mut session, version),
        )
        .await
        .context("UDP-over-TCP request timed out")??;
        let (mut reader, mut writer) = tokio::io::split(session);
        let server = rule.shadowsocks.as_ref().expect("SS session");
        let inlet = ListenerKey {
            tcp: false,
            ..inlet
        };
        let (mut ipv4, mut ipv6) = (None::<UdpSocket>, None::<UdpSocket>);
        let mut routes = HashMap::<SocketAddr, LoopGuard>::new();
        let mut names = HashMap::<String, (Instant, SocketAddr)>::new();
        let mut buffer = vec![0; wire::MAX_DATAGRAM + 1];
        loop {
            // A reply must not cancel a partly read TCP frame. Reuse this
            // future until it completes, even across many UDP replies.
            let packet = wire::read_packet(&mut reader, connected.as_ref());
            tokio::pin!(packet);
            let message = loop {
                tokio::select! {
                    message = &mut packet => break message?,
                    readable = async {
                        match (&ipv4, &ipv6) {
                            (Some(v4), Some(v6)) => tokio::select! { r=v4.readable()=>r.map(|_|true),r=v6.readable()=>r.map(|_|false) },
                            (Some(v4), None) => v4.readable().await.map(|_|true),
                            (None, Some(v6)) => v6.readable().await.map(|_|false),
                            (None, None) => std::future::pending().await,
                        }
                    } => {
                        let socket = if readable? { ipv4.as_ref() } else { ipv6.as_ref() }.expect("readable socket");
                        let (size, source) = match socket.try_recv_from(&mut buffer) {
                            Ok(packet) => packet,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(error) => return Err(error.into()),
                        };
                        let source = canonical_address(source);
                        if size > wire::MAX_DATAGRAM || !routes.contains_key(&source) {
                            stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue;
                        }
                        rule.throttle(size).await;
                        ensure!(meter.admit(&rule.spec, false, size, true).await? == Some(size), "UDP-over-TCP quota exhausted");
                        wire::write_packet(&mut writer, connected.is_some(), source, &buffer[..size]).await?;
                        stats.forwarded_download_bytes.fetch_add(size as u64, Ordering::Relaxed);
                        *activity.lock().unwrap() = Instant::now();
                    }
                }
            };
            let Some(message) = message else {
                writer.shutdown().await?;
                return Ok(());
            };
            let address = match datagram_address(&rule, server, &message.destination, &mut names)
                .await
            {
                Ok(address) => address,
                Err(error) => {
                    stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(rule_id=%rule.spec.id,%error,"UDP-over-TCP destination rejected");
                    continue;
                }
            };
            if !routes.contains_key(&address) {
                if routes.len() >= MAX_ROUTE_GUARDS {
                    stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let guard = match rule.routes.reserve(inlet, address) {
                    Ok(guard) => guard,
                    Err(_) => {
                        stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                routes.insert(address, guard);
            }
            let slot = if address.is_ipv4() {
                &mut ipv4
            } else {
                &mut ipv6
            };
            if slot.is_none() {
                *slot = Some(network::outbound_udp(
                    rule.spec.outbound_bind.as_ref(),
                    address.is_ipv4(),
                )?);
            }
            let size = message.payload.len();
            rule.throttle(size).await;
            ensure!(
                meter.admit(&rule.spec, true, size, true).await? == Some(size),
                "UDP-over-TCP quota exhausted"
            );
            match slot
                .as_ref()
                .unwrap()
                .send_to(&message.payload, address)
                .await
            {
                Ok(sent) if sent == size => {
                    stats
                        .forwarded_upload_bytes
                        .fetch_add(sent as u64, Ordering::Relaxed);
                }
                _ => {
                    stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                }
            }
            *activity.lock().unwrap() = Instant::now();
        }
    };
    tokio::select! {
        result=relay => result,
        _=rule.cancel.cancelled() => Ok(()),
        _=watch_deadline(&rule.spec, activity.clone()) => Ok(()),
    }
}
