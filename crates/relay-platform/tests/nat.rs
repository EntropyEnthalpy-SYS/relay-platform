use relay_platform::nat;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};

#[tokio::test]
async fn nat_pmp_requests_and_parses_a_mapping() {
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 32];
        let (size, peer) = gateway.recv_from(&mut buffer).await.unwrap();
        assert_eq!(size, 12);
        assert_eq!(&buffer[..4], &[0, 1, 0, 0]);
        assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]), 9000);
        assert_eq!(u16::from_be_bytes([buffer[6], buffer[7]]), 0);
        assert_eq!(
            u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
            3600
        );
        let mut reply = vec![0, 129, 0, 0];
        reply.extend_from_slice(&7u32.to_be_bytes());
        reply.extend_from_slice(&9000u16.to_be_bytes());
        reply.extend_from_slice(&40000u16.to_be_bytes());
        reply.extend_from_slice(&3600u32.to_be_bytes());
        gateway.send_to(&reply, peer).await.unwrap();
        let (size, peer2) = gateway.recv_from(&mut buffer).await.unwrap();
        assert_eq!(
            u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
            0
        );
        let mut deleted = vec![0, 129, 0, 0];
        deleted.extend_from_slice(&8u32.to_be_bytes());
        deleted.extend_from_slice(&9000u16.to_be_bytes());
        deleted.extend_from_slice(&40000u16.to_be_bytes());
        deleted.extend_from_slice(&0u32.to_be_bytes());
        gateway.send_to(&deleted, peer2).await.unwrap();
        assert_eq!(size, 12);
    });
    let mapping = timeout(Duration::from_secs(2), nat::map(address, 9000, 0, 3600))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.gateway, address);
    assert_eq!(mapping.internal_port, 9000);
    assert_eq!(mapping.external_port, 40000);
    assert_eq!(mapping.lifetime_secs, 3600);
    assert_eq!(mapping.epoch, 7);
    let deleted = timeout(Duration::from_secs(2), nat::map(address, 9000, 40000, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.lifetime_secs, 0);
    server.await.unwrap();
}

#[test]
fn nat_pmp_rejects_bad_gateways_and_refusals() {
    assert!(nat::gateway_from("not-an-address").is_err());
    assert!(nat::gateway_from("[::1]:5351").is_err());
    assert_eq!(nat::gateway_from("192.0.2.1").unwrap().port(), 5351);
    let gateway: SocketAddr = "192.0.2.1:5351".parse().unwrap();
    let refused = [0, 129, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(nat::parse_response(&refused, gateway).is_err());
    assert!(nat::parse_response(&[0, 129], gateway).is_err());
}

#[tokio::test]
async fn nat_pmp_renews_until_cancelled() {
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 32];
        for epoch in 1u32..=2 {
            let (size, peer) = gateway.recv_from(&mut buffer).await.unwrap();
            assert_eq!(size, 12);
            let mut reply = vec![0, 129, 0, 0];
            reply.extend_from_slice(&epoch.to_be_bytes());
            reply.extend_from_slice(&9000u16.to_be_bytes());
            reply.extend_from_slice(&40000u16.to_be_bytes());
            reply.extend_from_slice(&120u32.to_be_bytes());
            gateway.send_to(&reply, peer).await.unwrap();
        }
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(nat::maintain(
        address,
        9000,
        0,
        120,
        Duration::from_millis(50),
        None,
        cancel.clone(),
        move |mapping| {
            tx.send(mapping.epoch).unwrap();
        },
    ));
    let first = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first, second), (1, 2));
    cancel.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn nat_pmp_retries_a_refused_request() {
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 32];
        let (_, peer) = gateway.recv_from(&mut buffer).await.unwrap();
        gateway
            .send_to(&[0, 129, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], peer)
            .await
            .unwrap();
        let (size, peer) = gateway.recv_from(&mut buffer).await.unwrap();
        assert_eq!(size, 12);
        let mut reply = vec![0, 129, 0, 0];
        reply.extend_from_slice(&2u32.to_be_bytes());
        reply.extend_from_slice(&9000u16.to_be_bytes());
        reply.extend_from_slice(&40000u16.to_be_bytes());
        reply.extend_from_slice(&120u32.to_be_bytes());
        gateway.send_to(&reply, peer).await.unwrap();
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(nat::maintain(
        address,
        9000,
        0,
        120,
        Duration::from_millis(500),
        Some(nat::RetryPolicy::new(Duration::from_millis(50), Duration::from_millis(200)).unwrap()),
        cancel.clone(),
        move |mapping| tx.send(mapping.epoch).unwrap(),
    ));
    let epoch = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(epoch, 2);
    cancel.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[test]
fn retry_policy_doubles_up_to_its_cap() {
    let policy =
        nat::RetryPolicy::new(Duration::from_millis(50), Duration::from_millis(150)).unwrap();
    let first = policy.next(Duration::from_millis(50));
    assert_eq!(first, Duration::from_millis(100));
    assert_eq!(policy.next(first), Duration::from_millis(150));
    assert!(nat::RetryPolicy::new(Duration::ZERO, Duration::from_secs(1)).is_err());
    assert!(nat::RetryPolicy::new(Duration::from_secs(2), Duration::from_secs(1)).is_err());
}
