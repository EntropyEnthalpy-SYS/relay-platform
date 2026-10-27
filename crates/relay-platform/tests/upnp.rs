use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Method},
    response::{Html, IntoResponse},
    routing::{any, get, post},
};
use relay_platform::upnp;
use std::sync::{Arc, Mutex};

#[test]
fn description_parser_selects_the_wan_service() {
    let xml = r#"<root><device><serviceList><service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
    </service></serviceList></device></root>"#;
    let service = upnp::parse_description(xml).unwrap();
    assert_eq!(
        service.kind,
        "urn:schemas-upnp-org:service:WANIPConnection:1"
    );
    assert_eq!(service.control_url, "/ctl/IPConn");
    assert!(upnp::parse_description("<root/>").is_err());
    assert!(
        upnp::parse_description("<WANIPConnection><controlURL></controlURL></WANIPConnection>")
            .is_err()
    );
}

#[tokio::test]
async fn upnp_add_and_delete_use_the_igd_control_url() {
    type Seen = Arc<Mutex<Vec<String>>>;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    async fn desc() -> Html<&'static str> {
        Html(
            r#"<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/control</controlURL></service></root>"#,
        )
    }
    async fn control(State(seen): State<Seen>, body: String) -> &'static str {
        seen.lock().unwrap().push(body);
        "<Envelope><Body><AddPortMappingResponse/></Body></Envelope>"
    }
    let app = Router::new()
        .route("/desc.xml", get(desc))
        .route("/control", post(control))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://{address}/desc.xml");
    let mapping = upnp::map(&url, "127.0.0.1", 9000, 40000, 600, false)
        .await
        .unwrap();
    assert_eq!(mapping.external_port, 40000);
    assert_eq!(mapping.lifetime_secs, 600);
    let first = seen.lock().unwrap()[0].clone();
    assert!(first.contains("AddPortMapping"));
    assert!(first.contains("<NewExternalPort>40000</NewExternalPort>"));
    assert!(first.contains("<NewInternalPort>9000</NewInternalPort>"));
    assert!(first.contains("<NewInternalClient>127.0.0.1</NewInternalClient>"));
    let deleted = upnp::map(&url, "127.0.0.1", 9000, 40000, 0, true)
        .await
        .unwrap();
    assert_eq!(deleted.lifetime_secs, 0);
    let second = seen.lock().unwrap()[1].clone();
    assert!(second.contains("DeletePortMapping"));
    assert!(second.contains("<NewExternalPort>40000</NewExternalPort>"));
}

#[tokio::test]
async fn upnp_renews_until_cancelled() {
    type Seen = Arc<Mutex<Vec<String>>>;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    async fn desc() -> Html<&'static str> {
        Html(
            r#"<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/control</controlURL></service></root>"#,
        )
    }
    async fn control(State(seen): State<Seen>, body: String) -> &'static str {
        seen.lock().unwrap().push(body);
        "<Envelope><Body><AddPortMappingResponse/></Body></Envelope>"
    }
    let app = Router::new()
        .route("/desc.xml", get(desc))
        .route("/control", post(control))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://{address}/desc.xml");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        upnp::maintain(
            &url,
            "127.0.0.1",
            9000,
            40000,
            600,
            std::time::Duration::from_millis(50),
            task_cancel,
            move |mapping| tx.send(mapping.external_port).unwrap(),
        )
        .await
    });
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first, second), (40000, 40000));
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .take(2)
            .all(|body| body.contains("AddPortMapping"))
    );
}

#[tokio::test]
async fn ssdp_discovery_parses_location_and_deduplicates() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (size, peer) = server.recv_from(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.starts_with("M-SEARCH * HTTP/1.1"));
        assert!(request.contains("ssdp:discover"));
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "LOCATION: http://127.0.0.1:5000/rootDesc.xml\r\n",
            "SERVER: Test/1.0 UPnP/1.1\r\n",
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "USN: uuid:test::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "\r\n"
        );
        server.send_to(response.as_bytes(), peer).await.unwrap();
        server.send_to(response.as_bytes(), peer).await.unwrap();
    });
    let found = upnp::discover_at(target, std::time::Duration::from_millis(400))
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].location, "http://127.0.0.1:5000/rootDesc.xml");
    assert_eq!(found[0].server.as_deref(), Some("Test/1.0 UPnP/1.1"));
    task.await.unwrap();
}

#[tokio::test]
async fn upnp_event_subscription_renews_and_unsubscribes() {
    type Seen = Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    async fn desc() -> Html<&'static str> {
        Html(
            r#"<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/control</controlURL><eventSubURL>/events</eventSubURL></service></root>"#,
        )
    }
    async fn events(
        State(seen): State<Seen>,
        method: Method,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        seen.lock().unwrap().push((
            method.as_str().to_owned(),
            headers
                .get("SID")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            headers
                .get("CALLBACK")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        ));
        ([("SID", "uuid:test"), ("TIMEOUT", "Second-120")], "")
    }
    let app = Router::new()
        .route("/desc.xml", get(desc))
        .route("/events", any(events))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let description = format!("http://{address}/desc.xml");
    let subscription = upnp::subscribe(&description, "http://127.0.0.1:9/callback", 120)
        .await
        .unwrap();
    assert_eq!(subscription.event_url, format!("http://{address}/events"));
    assert_eq!(subscription.sid, "uuid:test");
    assert_eq!(subscription.timeout_secs, 120);
    let renewed = upnp::renew(&subscription.event_url, &subscription.sid, 60)
        .await
        .unwrap();
    assert_eq!(renewed, 120);
    upnp::unsubscribe(&subscription.event_url, &subscription.sid)
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, "SUBSCRIBE");
    assert!(seen[0].2.as_deref().unwrap().contains("/callback"));
    assert_eq!(seen[1].1.as_deref(), Some("uuid:test"));
    assert_eq!(seen[2].0, "UNSUBSCRIBE");
}
