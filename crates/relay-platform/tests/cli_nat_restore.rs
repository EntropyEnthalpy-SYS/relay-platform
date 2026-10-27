use std::{
    net::UdpSocket,
    process::Command,
    sync::{Arc, Mutex},
};

#[test]
fn nat_map_restore_state_deletes_the_recorded_mapping_first() {
    let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = gateway.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let server = std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        for _ in 0..2 {
            let (size, peer) = gateway.recv_from(&mut buffer).unwrap();
            assert_eq!(size, 12);
            let external = u16::from_be_bytes([buffer[6], buffer[7]]);
            recorder.lock().unwrap().push(external);
            let mut reply = vec![0, 129, 0, 0];
            reply.extend_from_slice(&1u32.to_be_bytes());
            reply.extend_from_slice(&9000u16.to_be_bytes());
            reply.extend_from_slice(&external.to_be_bytes());
            reply.extend_from_slice(&3600u32.to_be_bytes());
            gateway.send_to(&reply, peer).unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("mapping.json");
    std::fs::write(
        &state,
        serde_json::json!({
            "gateway": address,
            "internal_port": 9000,
            "external_port": 40000,
            "lifetime_secs": 3600,
            "epoch": 1
        })
        .to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "nat-map",
            "--gateway",
            &address.to_string(),
            "--internal-port",
            "9000",
            "--external-port",
            "40001",
            "--state-file",
            &state.display().to_string(),
            "--restore-state",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![40000, 40001]);
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert_eq!(saved["external_port"], 40001);
}
