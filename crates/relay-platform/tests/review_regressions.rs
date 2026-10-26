//! Regressions for the 0.19 source-review findings R1-R3.
//!
//! R1: an advertised listener still enforces the owner's cross-node limit.
//! R2: a rejected configuration revision keeps the running revision's limit.
//! R3: a compatible Shadowsocks rule replacement keeps TCP replay state.
mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, shadowsocks, store::Store};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};

fn sync(db: &Store, node: &str, ledger: &str, applied: u64, error: Option<String>) -> SyncResponse {
    db.sync(
        node,
        SyncRequest {
            lease: None,
            budget: None,
            ledger_id: ledger.into(),
            need_config: true,
            applied_revision: applied,
            apply_error: error,
            usage: vec![],
            stats: EngineStats::default(),
        },
    )
    .unwrap()
}

fn ledger(db: &Store, node: &str) -> String {
    db.reconcile(
        node,
        ReconcileRequest {
            lease: None,
            ledger_id: None,
            after: None,
            expected_revision: None,
        },
    )
    .unwrap()
    .ledger_id
}

#[tokio::test]
async fn advertised_listener_enforces_the_owners_limit_for_direct_clients() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = db.create_node(&admin, "default", "edge").unwrap();
    db.enroll(&node.id, &enrollment, &relay_platform::store::secret())
        .unwrap();
    let echo = tcp_echo().await;
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    r.advertise = Some(r.listen.to_string());
    let listen = r.listen;
    let config = db.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    db.set_user_rate(&admin, &admin.id, Some(16 << 10)).unwrap();

    let reply = sync(&db, &node.id, &ledger(&db, &node.id), 1, None);
    let shares = reply.user_rates.unwrap();
    assert_eq!(shares.len(), 1, "advertised rule must hold a share");
    assert_eq!(shares[0].owner_id, admin.id);

    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config).await.unwrap();
    engine.set_user_shares(&shares, Instant::now());
    let payload = vec![7; 1 << 20];
    // At 16 KiB/s the 2 MiB round trip needs about two minutes.
    assert!(
        timeout(Duration::from_secs(1), exchange(listen, &payload))
            .await
            .is_err(),
        "direct access to an advertised listener bypassed the user limit"
    );
    assert_eq!(
        engine.stats().user_rates[0].enforced_bytes_per_sec,
        Some(16 << 10)
    );
    assert_eq!(
        timeout(Duration::from_secs(2), exchange(listen, b"small"))
            .await
            .unwrap(),
        b"small"
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn rejected_revision_renews_the_running_limit_instead_of_removing_it() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let other = db
        .create_user(
            &admin,
            "default",
            "other",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (node, enrollment) = db.create_node(&admin, "default", "edge").unwrap();
    db.enroll(&node.id, &enrollment, &relay_platform::store::secret())
        .unwrap();
    let echo = tcp_echo().await;
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    let initial = db.set_config(&admin, &node.id, 0, vec![r.clone()]).unwrap();
    db.set_user_rate(&admin, &admin.id, Some(16 << 10)).unwrap();
    let ledger = ledger(&db, &node.id);
    let shares = sync(&db, &node.id, &ledger, 1, None).user_rates.unwrap();
    assert_eq!(shares.len(), 1);
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(initial).await.unwrap();
    engine.set_user_shares(&shares, Instant::now());

    // Revision 2 replaces the limited owner's rule with another owner's rule
    // on a port that is already occupied, so the agent must reject it.
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    r.id = "replacement".into();
    r.owner_id = other.id;
    r.listen = blocker.local_addr().unwrap();
    let replacement = db.set_config(&admin, &node.id, 1, vec![r]).unwrap();
    let failed = engine
        .apply(replacement.clone())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(engine.revision().await, 1);

    let reply = sync(&db, &node.id, &ledger, 1, Some(failed));
    let shares = reply.user_rates.unwrap();
    assert_eq!(
        shares.len(),
        1,
        "controller retired the limit while revision 1 was still running"
    );
    assert_eq!(shares[0].owner_id, admin.id);
    // The agent keeps the old revision's limit and renews it; the failed
    // revision's empty share list must not be applied.
    engine.renew_user_shares(Instant::now());
    assert_eq!(
        engine.stats().user_rates[0].enforced_bytes_per_sec,
        Some(16 << 10)
    );
    let payload = vec![8; 1 << 20];
    assert!(
        timeout(Duration::from_secs(1), exchange(listen, &payload))
            .await
            .is_err(),
        "a rejected revision removed the still-running limit"
    );

    // Once the replacement activates, the old owner leaves the share list.
    drop(blocker);
    engine.apply(replacement).await.unwrap();
    let after = sync(&db, &node.id, &ledger, 2, None).user_rates.unwrap();
    assert!(after.is_empty(), "{after:?}");
    engine.set_user_shares(&after, Instant::now());
    assert!(engine.stats().user_rates.is_empty());
    engine.shutdown().await.unwrap();
}

fn ss_request(destination: std::net::SocketAddr, psk: &[u8], salt: [u8; 16]) -> Vec<u8> {
    use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let mut subkey = [0u8; 16];
    let mut hash = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hash.update(psk)
        .update(&salt)
        .finalize_xof()
        .fill(&mut subkey);
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &subkey).unwrap());
    let mut variable = vec![1, 127, 0, 0, 1];
    variable.extend_from_slice(&destination.port().to_be_bytes());
    variable.extend_from_slice(&[0, 0]);
    variable.extend_from_slice(b"review-replay");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut fixed = vec![0];
    fixed.extend_from_slice(&now.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut request = salt.to_vec();
    for (counter, mut block) in [fixed, variable].into_iter().enumerate() {
        let mut nonce = [0; 12];
        nonce[0] = counter as u8;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut block,
        )
        .unwrap();
        request.extend_from_slice(&block);
    }
    request
}

async fn send_ss(address: std::net::SocketAddr, request: &[u8]) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = vec![];
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut reply)).await;
}

#[tokio::test]
async fn shadowsocks_replay_state_survives_compatible_rule_revisions() {
    let temp = tempfile::tempdir().unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = backend.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let accepting = tokio::spawn(async move {
        while let Ok((mut socket, _)) = backend.accept().await {
            let mut payload = vec![];
            socket.read_to_end(&mut payload).await.unwrap();
            tx.send(payload).unwrap();
        }
    });
    let psk: Vec<u8> = (0..16).collect();
    let mut r = rule(address, Protocol::Tcp);
    r.targets.clear();
    r.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: "AAECAwQFBgcICQoLDA0ODw==".into(),
        allow_private_destinations: true,
    });
    let listen = r.listen;
    let mut config = config(r);
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config.clone()).await.unwrap();
    let request = ss_request(address, &psk, [42; 16]);
    send_ss(listen, &request).await;
    assert_eq!(rx.recv().await.unwrap(), b"review-replay");
    send_ss(listen, &request).await;
    assert!(
        timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err(),
        "the same request was accepted twice before any edit"
    );

    // A name-only edit must not hand the replay a fresh salt cache.
    config.revision += 1;
    config.rules[0].name = "Renamed".into();
    engine.apply(config.clone()).await.unwrap();
    send_ss(listen, &request).await;
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "a rename forgot the replayed TCP salt"
    );

    // A rate edit is equally non-cryptographic.
    config.revision += 1;
    config.rules[0].rate_bytes_per_sec = Some(1 << 20);
    engine.apply(config.clone()).await.unwrap();
    send_ss(listen, &request).await;
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "a rate edit forgot the replayed TCP salt"
    );

    // Replay state is scoped by key: a new salt remains acceptable, while the
    // old ciphertext cannot be replayed against the replaced key.
    let fresh = ss_request(address, &psk, [43; 16]);
    send_ss(listen, &fresh).await;
    assert_eq!(rx.recv().await.unwrap(), b"review-replay");

    config.revision += 1;
    config.rules[0].inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: "Dw4NDAsKCQgHBgUEAwIBAA==".into(),
        allow_private_destinations: true,
    });
    engine.apply(config).await.unwrap();
    send_ss(listen, &fresh).await;
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "old key ciphertext was accepted after a key change"
    );
    let new_key: Vec<u8> = (0..16).rev().collect();
    let accepted = ss_request(address, &new_key, [44; 16]);
    send_ss(listen, &accepted).await;
    assert_eq!(rx.recv().await.unwrap(), b"review-replay");
    engine.shutdown().await.unwrap();
    accepting.abort();
}
