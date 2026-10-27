use axum::{
    Router,
    extract::State,
    response::Html,
    routing::{get, post},
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
