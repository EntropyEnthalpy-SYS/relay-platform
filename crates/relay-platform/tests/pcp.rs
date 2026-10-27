use relay_platform::pcp;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};

fn response(request: &[u8], lifetime: u32, epoch: u32, result: u8, external: Ipv4Addr) -> Vec<u8> {
    let mut reply = vec![0u8; 60];
    reply[0] = 2;
    reply[1] = 0x81;
    reply[3] = result;
    reply[4..8].copy_from_slice(&lifetime.to_be_bytes());
    reply[8..12].copy_from_slice(&epoch.to_be_bytes());
    reply[24..36].copy_from_slice(&request[24..36]);
    reply[36] = 17;
    reply[40..42].copy_from_slice(&request[40..42]);
    reply[42..44].copy_from_slice(&40000u16.to_be_bytes());
    reply[44..60].copy_from_slice(&external.to_ipv6_mapped().octets());
    reply
}

#[tokio::test]
async fn pcp_maps_and_deletes_a_mapping() {
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = [0u8; 60];
        let (size, peer) = gateway.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 60);
        assert_eq!(request[0], 2);
        assert_eq!(request[1], 1);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            3600
        );
        assert_eq!(u16::from_be_bytes([request[40], request[41]]), 9000);
        gateway
            .send_to(
                &response(&request, 3600, 7, 0, Ipv4Addr::new(192, 0, 2, 10)),
                peer,
            )
            .await
            .unwrap();
        let mut deleted = [0u8; 60];
        let (size, peer) = gateway.recv_from(&mut deleted).await.unwrap();
        assert_eq!(size, 60);
        assert_eq!(
            u32::from_be_bytes([deleted[4], deleted[5], deleted[6], deleted[7]]),
            0
        );
        gateway
            .send_to(
                &response(&deleted, 0, 8, 0, Ipv4Addr::new(192, 0, 2, 10)),
                peer,
            )
            .await
            .unwrap();
    });
    let mapping = timeout(Duration::from_secs(2), pcp::map(address, 9000, 0, 3600))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.gateway, address);
    assert_eq!(mapping.internal_port, 9000);
    assert_eq!(mapping.external_port, 40000);
    assert_eq!(
        mapping.external_ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(mapping.lifetime_secs, 3600);
    assert_eq!(mapping.epoch, 7);
    let deleted = timeout(Duration::from_secs(2), pcp::map(address, 9000, 40000, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.lifetime_secs, 0);
    server.await.unwrap();
}

#[test]
fn pcp_rejects_bad_versions_and_refusals() {
    let gateway: SocketAddr = "192.0.2.1:5351".parse().unwrap();
    let mut refused = [0u8; 60];
    refused[0] = 2;
    refused[1] = 0x81;
    refused[3] = 3;
    assert!(pcp::parse_response(&refused, gateway, [0; 12]).is_err());
    assert!(pcp::parse_response(&[2, 0x81], gateway, [0; 12]).is_err());
    assert!(pcp::gateway_from("not-an-address").is_err());
}

#[tokio::test]
async fn pcp_renews_until_cancelled() {
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = gateway.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = [0u8; 60];
        for epoch in 1u32..=2 {
            let (size, peer) = gateway.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 60);
            gateway
                .send_to(
                    &response(&request, 120, epoch, 0, Ipv4Addr::new(192, 0, 2, 10)),
                    peer,
                )
                .await
                .unwrap();
        }
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(pcp::maintain(
        address,
        9000,
        0,
        120,
        Duration::from_millis(50),
        None,
        cancel.clone(),
        move |mapping| tx.send(mapping.epoch).unwrap(),
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
