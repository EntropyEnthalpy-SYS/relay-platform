mod common;
use common::*;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    model::*,
    store::{Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
}
fn options(origin: &str, node: &str, token: Option<PathBuf>) -> AgentOptions {
    AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: token,
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(50),
        controller_addresses: vec![],
        controller_proxy: None,
    }
}
fn question(name: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query
}
/// One UDP query; `None` when nothing answers within half a second.
async fn udp(server: SocketAddr, name: &str, kind: RecordType) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = question(name, kind);
    socket
        .send_to(&query.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buffer = [0u8; 2048];
    let length = timeout(Duration::from_millis(500), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    let reply = Message::from_vec(&buffer[..length]).unwrap();
    assert_eq!(reply.metadata.id, query.metadata.id);
    Some(reply)
}
async fn tcp(server: SocketAddr, name: &str, kind: RecordType) -> Message {
    let mut stream = TcpStream::connect(server).await.unwrap();
    let query = question(name, kind).to_vec().unwrap();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut reply = vec![0; length as usize];
    stream.read_exact(&mut reply).await.unwrap();
    Message::from_vec(&reply).unwrap()
}
fn answers(reply: &Message) -> Vec<String> {
    let mut values: Vec<String> = reply.answers.iter().map(|r| r.data.to_string()).collect();
    values.sort();
    values
}
async fn eventually_answers(server: SocketAddr, name: &str, expected: &[&str]) {
    let until = Instant::now() + Duration::from_secs(10);
    let mut last = None;
    while Instant::now() < until {
        if let Some(reply) = udp(server, name, RecordType::A).await {
            if answers(&reply) == expected {
                assert!(reply.metadata.authoritative);
                return;
            }
            last = Some(answers(&reply));
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("{name} never answered {expected:?}; last answer {last:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_member_serves_health_gated_answers_and_keeps_them_across_an_offline_restart() {
    let temp = tempfile::tempdir().unwrap();
    let mut echo = Some(tcp_echo().await);
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control.create_node(&admin, "default", "ns-a").unwrap();
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let (address, server) = serve(control.clone()).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let call = |method: reqwest::Method, path: &str, body: Value| {
        client
            .request(method, format!("{origin}/api/v1/{path}"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };

    // The entry rule whose health gates one of the answers.
    let mut entry = rule(echo.as_ref().unwrap().address, Protocol::Tcp);
    entry.health_check = Some(
        serde_json::from_value(json!({
            "interval_ms":100, "timeout_ms":60, "healthy_threshold":1,
            "unhealthy_threshold":1, "recovery_delay_ms":0, "max_age_ms":1000,
            "tcp":{"kind":"connect"}
        }))
        .unwrap(),
    );
    let published = call(
        reqwest::Method::PUT,
        &format!("nodes/{}/config", node.id),
        json!({"expected_revision":0,"rules":[entry.clone()]}),
    )
    .await
    .unwrap();
    assert_eq!(
        published.status(),
        200,
        "{}",
        published.text().await.unwrap()
    );

    let zone = json!({"name":"Edge.Example.TEST.","min_keep":1});
    let refused = call(
        reqwest::Method::POST,
        "dns/authoritative/zones",
        zone.clone(),
    )
    .await
    .unwrap();
    assert_eq!(refused.status(), 409, "switched off until turned on");
    call(
        reqwest::Method::PUT,
        "features/dns-authoritative",
        json!({"enabled":true}),
    )
    .await
    .unwrap()
    .error_for_status()
    .unwrap();
    let zone: Value = call(reqwest::Method::POST, "dns/authoritative/zones", zone)
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zone["name"], "edge.example.test");
    let zone_id = zone["id"].as_str().unwrap();
    let dns = free_address();
    let member = call(
        reqwest::Method::POST,
        &format!("dns/authoritative/zones/{zone_id}/members"),
        json!({"node_id":node.id,"listen":[dns.ip()],"port":dns.port()}),
    )
    .await
    .unwrap();
    assert_eq!(member.status(), 200, "{}", member.text().await.unwrap());
    let wildcard = call(
        reqwest::Method::POST,
        &format!("dns/authoritative/zones/{zone_id}/members"),
        json!({"node_id":node.id,"listen":["0.0.0.0"]}),
    )
    .await
    .unwrap();
    assert_eq!(wildcard.status(), 400, "wildcard listeners are refused");
    let record = call(
        reqwest::Method::POST,
        &format!("dns/authoritative/zones/{zone_id}/records"),
        json!({"name":"www","type":"A","values":[
            {"content":"192.0.2.10","health":{"node_id":node.id,"rule_id":entry.id}},
            {"content":"192.0.2.20"}
        ]}),
    )
    .await
    .unwrap();
    assert_eq!(record.status(), 200, "{}", record.text().await.unwrap());
    let clash = call(
        reqwest::Method::POST,
        &format!("dns/authoritative/zones/{zone_id}/records"),
        json!({"name":"www","type":"CNAME","values":[{"content":"elsewhere.example.net"}]}),
    )
    .await
    .unwrap();
    assert_eq!(clash.status(), 409, "a CNAME cannot share its name");

    let secret = temp.path().join("enroll.secret");
    write_secret(&secret, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        agent_db.clone(),
        options(&origin, &node.id, Some(secret.clone())),
        stop.clone(),
    ));
    // Both values once the entry is healthy; the gated one is withheld while
    // it is not, and min_keep never applies while the ungated one remains.
    eventually_answers(dns, "www.edge.example.test.", &["192.0.2.10", "192.0.2.20"]).await;
    let ns = tcp(dns, "edge.example.test.", RecordType::NS).await;
    assert_eq!(answers(&ns), ["ns1.edge.example.test."]);
    assert_eq!(ns.additionals[0].data.to_string(), dns.ip().to_string());
    let missing = udp(dns, "nope.edge.example.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
    let elsewhere = udp(dns, "example.org.", RecordType::A).await.unwrap();
    assert_eq!(elsewhere.metadata.response_code, ResponseCode::Refused);

    let until = Instant::now() + Duration::from_secs(10);
    let view = loop {
        let view: Value = call(reqwest::Method::GET, "dns/authoritative", json!(null))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // The four queries above reach the panel with a later report.
        let member = &view["zones"][0]["members"][0];
        if member["state"] == "serving" && member["report"]["queries"].as_u64() >= Some(4) {
            break view;
        }
        assert!(
            Instant::now() < until,
            "member never reported serving: {view}"
        );
        sleep(Duration::from_millis(50)).await;
    };
    let member = &view["zones"][0]["members"][0];
    assert_eq!(member["nameserver"], "ns1.edge.example.test");
    assert_eq!(member["report"]["listening"][0], dns.to_string());
    assert_eq!(
        view["zones"][0]["records"][0]["healthy"],
        json!([true, null])
    );

    // The entry fails: its address leaves the answer.
    drop(echo.take());
    eventually_answers(dns, "www.edge.example.test.", &["192.0.2.20"]).await;
    let switch_off = call(
        reqwest::Method::PUT,
        "features/dns-authoritative",
        json!({"enabled":false}),
    )
    .await
    .unwrap();
    assert_eq!(switch_off.status(), 409, "the zone still uses the feature");

    // Restarted while the controller is down, the agent answers from its copy.
    stop.cancel();
    timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        udp(dns, "www.edge.example.test.", RecordType::A)
            .await
            .is_none()
    );
    server.cancel();
    let offline = CancellationToken::new();
    let restarted = tokio::spawn(agent::run(
        agent_db.clone(),
        options(&origin, &node.id, None),
        offline.clone(),
    ));
    eventually_answers(dns, "www.edge.example.test.", &["192.0.2.20"]).await;
    offline.cancel();
    let _ = timeout(Duration::from_secs(5), restarted).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_zone_stops_the_listener_and_frees_the_switch() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control.create_node(&admin, "default", "ns-b").unwrap();
    let (address, server) = serve(control.clone()).await;
    let origin = format!("http://{address}");
    control
        .set_feature(&admin, "dns-authoritative", true)
        .unwrap();
    let zone = control
        .create_authoritative_zone(
            &admin,
            serde_json::from_value(json!({"name":"pool.example.test"})).unwrap(),
        )
        .unwrap();
    let dns = free_address();
    control
        .create_authoritative_member(
            &admin,
            &zone.id,
            serde_json::from_value(
                json!({"node_id":node.id,"listen":[dns.ip()],"port":dns.port()}),
            )
            .unwrap(),
        )
        .unwrap();
    control
        .create_authoritative_record(
            &admin,
            &zone.id,
            serde_json::from_value(
                json!({"name":"@","type":"TXT","values":[{"content":"hello pool"}]}),
            )
            .unwrap(),
        )
        .unwrap();
    let secret = temp.path().join("enroll.secret");
    write_secret(&secret, enrollment.as_bytes()).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        options(&origin, &node.id, Some(secret)),
        stop.clone(),
    ));
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(reply) = udp(dns, "pool.example.test.", RecordType::TXT).await
            && answers(&reply) == ["hello pool"]
        {
            break;
        }
        assert!(Instant::now() < until, "TXT never served");
        sleep(Duration::from_millis(50)).await;
    }
    // A node that still answers for a zone cannot be deleted.
    assert!(control.delete_node(&admin, &node.id).is_err());
    control.delete_authoritative_zone(&admin, &zone.id).unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(dns).await.is_ok() {
        assert!(Instant::now() < until, "listener kept running");
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        udp(dns, "pool.example.test.", RecordType::TXT)
            .await
            .is_none()
    );
    control
        .set_feature(&admin, "dns-authoritative", false)
        .unwrap();
    stop.cancel();
    timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.cancel();
}
