mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    model::*,
    store::{Actor, Store, write_secret},
};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

struct Server {
    address: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lower_limit_applies_during_a_rejected_revision() {
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let other = control
        .create_user(
            &admin,
            "default",
            "other",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (node, enrollment) = control.create_node(&admin, "default", "fenced").unwrap();
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    control
        .set_config(&admin, &node.id, 0, vec![r.clone()])
        .unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let mut opts = options(
        &format!("http://{}", server_instance.address),
        &node.id,
        Some(secret_path),
    );
    opts.poll_interval = Duration::from_millis(50);
    let running = tokio::spawn(agent::run(agent_db.clone(), opts, stop.clone()));
    wait_applied(&control, &admin, 1).await;
    control
        .set_user_rate(&admin, &admin.id, Some(256 << 10))
        .unwrap();
    let seat = || control.user_rate(&admin, &admin.id).unwrap().nodes[0].clone();
    let until = Instant::now() + Duration::from_secs(5);
    while seat().enforced_bytes_per_sec.is_none() {
        assert!(Instant::now() < until, "agent never enforced the share");
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seat().enforced_bytes_per_sec, Some(256 << 10));

    // Revision 2 moves the rule to another owner on an occupied port. The
    // managed agent must keep revision 1 and its share while retrying.
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    r.id = "replacement".into();
    r.owner_id = other.id;
    r.listen = blocker.local_addr().unwrap();
    control.set_config(&admin, &node.id, 1, vec![r]).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let node = control.nodes(&admin).unwrap().remove(0);
        if node.apply_error.is_some() {
            assert_eq!(node.applied_revision, 1);
            break;
        }
        assert!(Instant::now() < until, "agent did not reject revision 2");
        sleep(Duration::from_millis(20)).await;
    }
    // Review probe: a fresh administrative limit is independent of the rejected rule edit.
    control
        .set_user_rate(&admin, &admin.id, Some(1024))
        .unwrap();
    sleep(Duration::from_secs(16)).await;
    let observed = seat();
    let configured = control
        .user_rate(&admin, &admin.id)
        .unwrap()
        .rate_bytes_per_sec;
    let started = Instant::now();
    let forwarded = timeout(Duration::from_secs(2), exchange(listen, &vec![7; 64 << 10])).await;
    println!(
        "RATE configured={configured:?} held={} enforced={:?} 128KiB_roundtrip_completed={} elapsed_ms={}",
        observed.share_bytes_per_sec,
        observed.enforced_bytes_per_sec,
        forwarded.is_ok(),
        started.elapsed().as_millis()
    );
    assert_eq!(control.nodes(&admin).unwrap()[0].applied_revision, 1);
    assert!(TcpStream::connect(listen).await.is_ok());

    // Releasing the port lets the retry activate and retire the old share.
    drop(blocker);
    wait_applied(&control, &admin, 2).await;
    let until = Instant::now() + Duration::from_secs(3);
    while !control
        .user_rate(&admin, &admin.id)
        .unwrap()
        .nodes
        .is_empty()
    {
        assert!(Instant::now() < until, "old share was not retired");
        sleep(Duration::from_millis(20)).await;
    }
    stop.cancel();
    timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(server_instance).await;
    assert_eq!(
        observed.enforced_bytes_per_sec,
        Some(1024),
        "fresh user limit was ignored for more than the 15-second share lease"
    );
}

async fn server(db: Store, bind: SocketAddr) -> Server {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(db).with_shutdown(stop.clone()));
    server_stopped_by(router, bind, stop).await
}
async fn server_stopped_by(
    router: axum::Router,
    bind: SocketAddr,
    stop: CancellationToken,
) -> Server {
    let listener = TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = stop.clone();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    Server {
        address,
        stop,
        task,
    }
}
async fn stop_server(server: Server) {
    server.stop.cancel();
    timeout(Duration::from_secs(3), server.task)
        .await
        .unwrap()
        .unwrap();
}
fn options(origin: &str, node: &str, token: Option<PathBuf>) -> AgentOptions {
    AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: token,
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(50),
    }
}
async fn wait_applied(db: &Store, actor: &Actor, revision: u64) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if db.nodes(actor).unwrap()[0].applied_revision == revision {
            return;
        }
        assert!(
            Instant::now() < until,
            "agent never acknowledged revision {revision}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}
