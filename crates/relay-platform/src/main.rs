use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    engine::Engine,
    model::NodeConfig,
    store::{Store, private_directory, secret, write_secret},
};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "relay",
    version,
    about = "Independent relay controller and TCP/UDP agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Report build target and the deployment state compatibility contract.
    BuildInfo,
    /// Observe MPTCP kernel capability, interfaces, routes and endpoints.
    MptcpInfo,
    /// Request or delete a UPnP IGD UDP port mapping.
    UpnpMap {
        #[arg(long)]
        description_url: String,
        #[arg(long, default_value = "127.0.0.1")]
        internal_client: String,
        #[arg(long)]
        internal_port: u16,
        #[arg(long)]
        external_port: u16,
        #[arg(long, default_value_t = 3600)]
        lifetime_secs: u32,
        #[arg(long)]
        delete: bool,
        /// Keep renewing the mapping until Ctrl-C.
        #[arg(long)]
        renew: bool,
        /// Seconds between renewals (defaults to half the lifetime).
        #[arg(long)]
        renew_after_secs: Option<u64>,
        /// Retry a failed request after this many seconds (omit to fail fast).
        #[arg(long)]
        retry_secs: Option<u64>,
        /// Maximum retry interval after exponential growth (defaults to retry-secs).
        #[arg(long)]
        retry_max_secs: Option<u64>,
        /// Write the last successful mapping as JSON (atomically).
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Delete the mapping recorded in --state-file before creating a new one.
        #[arg(long)]
        restore_state: bool,
    },
    /// Run the public side of a single-session reverse TCP tunnel.
    ReverseServer {
        #[arg(long)]
        control_listen: SocketAddr,
        #[arg(long)]
        public_listen: SocketAddr,
        #[arg(long)]
        token_file: PathBuf,
    },
    /// Connect a private target to a reverse tunnel server.
    ReverseClient {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        target: String,
        #[arg(long)]
        token_file: PathBuf,
        /// Concurrent control sessions (1-64).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=64))]
        sessions: u8,
    },
    /// Serve a multiplexed reverse tunnel on one control connection.
    ReverseMuxServer {
        #[arg(long)]
        control_listen: SocketAddr,
        #[arg(long)]
        public_listen: SocketAddr,
        #[arg(long)]
        token_file: PathBuf,
        /// Concurrent public streams per control connection (1-1024).
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=1024))]
        max_streams: u16,
        /// Close an idle public stream after this many seconds (1-86400).
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=86400))]
        idle_timeout_secs: u32,
    },
    /// Connect a private target to a multiplexed reverse server.
    ReverseMuxClient {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        target: String,
        #[arg(long)]
        token_file: PathBuf,
    },
    /// Subscribe to an IGD event URL; the callback server is external.
    UpnpSubscribe {
        #[arg(long)]
        description_url: String,
        #[arg(long)]
        callback: String,
        #[arg(long, default_value_t = 1800)]
        timeout_secs: u32,
    },
    /// Serve a local UPnP callback, subscribe, print events and renew.
    UpnpEvents {
        #[arg(long)]
        description_url: String,
        #[arg(long)]
        callback: String,
        #[arg(long, default_value_t = 1800)]
        timeout_secs: u32,
    },
    /// Unsubscribe an existing IGD event subscription.
    UpnpUnsubscribe {
        #[arg(long)]
        event_url: String,
        #[arg(long)]
        sid: String,
    },
    /// Discover UPnP IGDs with SSDP and print LOCATION candidates.
    UpnpDiscover {
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=30))]
        timeout_secs: u64,
    },
    /// Request or delete a PCP UDP port mapping.
    PcpMap {
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        internal_port: u16,
        #[arg(long, default_value_t = 0)]
        external_port: u16,
        #[arg(long, default_value_t = 3600)]
        lifetime_secs: u32,
        /// Delete the mapping instead of creating it.
        #[arg(long)]
        delete: bool,
        /// Keep renewing the mapping until Ctrl-C.
        #[arg(long)]
        renew: bool,
        /// Seconds between renewals (defaults to half the lifetime).
        #[arg(long)]
        renew_after_secs: Option<u64>,
        /// Retry a failed request after this many seconds (omit to fail fast).
        #[arg(long)]
        retry_secs: Option<u64>,
        /// Maximum retry interval after exponential growth (defaults to retry-secs).
        #[arg(long)]
        retry_max_secs: Option<u64>,
        /// Write the last successful mapping as JSON (atomically).
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Delete the mapping recorded in --state-file before creating a new one.
        #[arg(long)]
        restore_state: bool,
    },
    /// Request or delete a NAT-PMP UDP port mapping.
    NatMap {
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        internal_port: u16,
        #[arg(long, default_value_t = 0)]
        external_port: u16,
        #[arg(long, default_value_t = 3600)]
        lifetime_secs: u32,
        /// Delete the mapping instead of creating it.
        #[arg(long)]
        delete: bool,
        /// Keep renewing the mapping until Ctrl-C.
        #[arg(long)]
        renew: bool,
        /// Seconds between renewals (defaults to half the lifetime).
        #[arg(long)]
        renew_after_secs: Option<u64>,
        /// Retry a failed request after this many seconds (omit to fail fast).
        #[arg(long)]
        retry_secs: Option<u64>,
        /// Maximum retry interval after exponential growth (defaults to retry-secs).
        #[arg(long)]
        retry_max_secs: Option<u64>,
        /// Write the last successful mapping as JSON (atomically).
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Delete the mapping recorded in --state-file before creating a new one.
        #[arg(long)]
        restore_state: bool,
    },
    /// Run the control API and embedded administration interface.
    Server {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long, default_value = "state/controller")]
        state: PathBuf,
        #[arg(long)]
        admin_password_file: Option<PathBuf>,
        /// Append-only controller recovery log (defaults to STATE/recovery.log).
        #[arg(long)]
        recovery_log: Option<PathBuf>,
        /// Maximum agent sync requests per durable commit; 1 disables coalescing.
        #[arg(long,default_value_t=16,value_parser=clap::value_parser!(u8).range(1..=16))]
        sync_batch_size: u8,
        /// Acknowledge that a TLS reverse proxy protects a non-loopback listener.
        #[arg(long)]
        behind_tls_proxy: bool,
    },
    /// Enroll once, then synchronize configuration and meter real traffic.
    Agent {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        node_id: String,
        #[arg(long, default_value = "state/agent")]
        state: PathBuf,
        #[arg(long)]
        enrollment_token_file: Option<PathBuf>,
        #[arg(long)]
        ca_certificate: Option<PathBuf>,
        /// Directory of local TLS certificate/key profiles (defaults to STATE/tls).
        #[arg(long)]
        tls_directory: Option<PathBuf>,
        #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=300))]
        poll_seconds: u64,
    },
    /// Run the same forwarding engine without a controller.
    Standalone {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "state/standalone/agent.sqlite")]
        database: PathBuf,
        /// Directory of local TLS profiles, required for private certificates.
        #[arg(long)]
        tls_directory: Option<PathBuf>,
        /// Reload versioned JSON every two seconds; invalid updates keep the prior version.
        #[arg(long)]
        watch: bool,
    },
    /// Validate a node configuration without opening listeners.
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a consistent SQLite backup with private file permissions.
    Backup {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a controller backup by replaying its latest log and head manifest.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        recovery_log: PathBuf,
        /// New private state directory; must not already exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print locally admitted payload counters; never prints credentials.
    Usage {
        #[arg(long)]
        database: PathBuf,
    },
}

fn retry_policy(
    initial: Option<u64>,
    max: Option<u64>,
) -> Result<Option<relay_platform::nat::RetryPolicy>> {
    match initial {
        Some(seconds) => {
            let max = max.unwrap_or(seconds);
            Ok(Some(relay_platform::nat::RetryPolicy::new(
                Duration::from_secs(seconds),
                Duration::from_secs(max),
            )?))
        }
        None => {
            if max.is_some() {
                anyhow::bail!("retry-max-secs requires retry-secs");
            }
            Ok(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relay=info,relay_platform=info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let stop = CancellationToken::new();
    let signal = stop.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal.cancel();
    });
    match cli.command {
        Command::UpnpMap {
            description_url,
            internal_client,
            internal_port,
            external_port,
            lifetime_secs,
            delete,
            renew,
            renew_after_secs,
            retry_secs,
            retry_max_secs,
            state_file,
            restore_state,
        } => {
            if restore_state && !delete {
                let path = state_file
                    .as_ref()
                    .context("--restore-state requires --state-file")?;
                if let Some(previous) =
                    relay_platform::state::read_json::<relay_platform::upnp::Mapping>(path)?
                    && (previous.internal_port != internal_port
                        || previous.external_port != external_port)
                {
                    relay_platform::upnp::map(
                        &description_url,
                        &internal_client,
                        previous.internal_port,
                        previous.external_port,
                        0,
                        true,
                    )
                    .await?;
                    relay_platform::state::remove_if_present(path)?;
                }
            }
            if renew && !delete {
                let after = renew_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_secs(u64::from((lifetime_secs / 2).max(1))));
                let cancel = CancellationToken::new();
                let stop = cancel.clone();
                let task = relay_platform::upnp::maintain(
                    &description_url,
                    &internal_client,
                    internal_port,
                    external_port,
                    lifetime_secs,
                    after,
                    retry_policy(retry_secs, retry_max_secs)?,
                    stop,
                    move |mapping| {
                        println!("{}", serde_json::to_string(mapping).unwrap_or_default());
                        if let Some(path) = &state_file {
                            let _ = relay_platform::state::write_json_atomic(path, mapping);
                        }
                    },
                );
                tokio::select! {
                    result = task => result,
                    _ = tokio::signal::ctrl_c() => { cancel.cancel(); Ok(()) }
                }?;
            } else {
                let mapping = relay_platform::upnp::map(
                    &description_url,
                    &internal_client,
                    internal_port,
                    external_port,
                    lifetime_secs,
                    delete,
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&mapping)?);
                if let Some(path) = &state_file {
                    if delete {
                        relay_platform::state::remove_if_present(path)?;
                    } else {
                        relay_platform::state::write_json_atomic(path, &mapping)?;
                    }
                }
            }
        }
        Command::ReverseServer {
            control_listen,
            public_listen,
            token_file,
        } => {
            let token = std::fs::read_to_string(&token_file)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            let control = tokio::net::TcpListener::bind(control_listen).await?;
            let public = tokio::net::TcpListener::bind(public_listen).await?;
            relay_platform::reverse::serve(control, public, token).await?;
        }
        Command::ReverseClient {
            server,
            target,
            token_file,
            sessions,
        } => {
            let token = std::fs::read_to_string(&token_file)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            relay_platform::reverse::client_pool(server, target, token, usize::from(sessions))
                .await?;
        }
        Command::ReverseMuxServer {
            control_listen,
            public_listen,
            token_file,
            max_streams,
            idle_timeout_secs,
        } => {
            let token = std::fs::read_to_string(&token_file)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            let control = tokio::net::TcpListener::bind(control_listen).await?;
            let public = tokio::net::TcpListener::bind(public_listen).await?;
            relay_platform::reverse_mux::serve_mux_with_options(
                control,
                public,
                token,
                usize::from(max_streams),
                u64::from(idle_timeout_secs),
            )
            .await?;
        }
        Command::ReverseMuxClient {
            server,
            target,
            token_file,
        } => {
            let token = std::fs::read_to_string(&token_file)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            loop {
                if let Err(error) =
                    relay_platform::reverse_mux::client_mux(server, target.clone(), token.clone())
                        .await
                {
                    tracing::warn!(%error, "reverse mux client ended; reconnecting");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        Command::UpnpSubscribe {
            description_url,
            callback,
            timeout_secs,
        } => {
            let subscription =
                relay_platform::upnp::subscribe(&description_url, &callback, timeout_secs).await?;
            println!("{}", serde_json::to_string_pretty(&subscription)?);
        }
        Command::UpnpEvents {
            description_url,
            callback,
            timeout_secs,
        } => {
            let cancel = CancellationToken::new();
            let stop = cancel.clone();
            let task = relay_platform::upnp::run_events(
                &description_url,
                &callback,
                timeout_secs,
                stop,
                |event| println!("{}", serde_json::to_string(event).unwrap_or_default()),
            );
            let signal_cancel = cancel.clone();
            let signal = tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal_cancel.cancel();
            });
            let subscription = task.await?;
            signal.abort();
            println!("{}", serde_json::to_string_pretty(&subscription)?);
        }
        Command::UpnpUnsubscribe { event_url, sid } => {
            relay_platform::upnp::unsubscribe(&event_url, &sid).await?;
            println!("{}", serde_json::json!({"ok": true}));
        }
        Command::UpnpDiscover { timeout_secs } => {
            let found = relay_platform::upnp::discover(Duration::from_secs(timeout_secs)).await?;
            println!("{}", serde_json::to_string_pretty(&found)?);
        }
        Command::PcpMap {
            gateway,
            internal_port,
            external_port,
            lifetime_secs,
            delete,
            renew,
            renew_after_secs,
            retry_secs,
            retry_max_secs,
            state_file,
            restore_state,
        } => {
            let gateway = relay_platform::pcp::gateway_from(&gateway)?;
            let lifetime = if delete { 0 } else { lifetime_secs };
            if restore_state && !delete {
                let path = state_file
                    .as_ref()
                    .context("--restore-state requires --state-file")?;
                if let Some(previous) =
                    relay_platform::state::read_json::<relay_platform::pcp::Mapping>(path)?
                    && (previous.internal_port != internal_port
                        || previous.external_port != external_port)
                {
                    relay_platform::pcp::map(
                        gateway,
                        previous.internal_port,
                        previous.external_port,
                        0,
                    )
                    .await?;
                    relay_platform::state::remove_if_present(path)?;
                }
            }
            if renew && !delete {
                let after = renew_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_secs(u64::from((lifetime_secs / 2).max(1))));
                let cancel = CancellationToken::new();
                let stop = cancel.clone();
                let task = relay_platform::pcp::maintain(
                    gateway,
                    internal_port,
                    external_port,
                    lifetime,
                    after,
                    retry_policy(retry_secs, retry_max_secs)?,
                    stop,
                    move |mapping| {
                        println!("{}", serde_json::to_string(mapping).unwrap_or_default());
                        if let Some(path) = &state_file {
                            let _ = relay_platform::state::write_json_atomic(path, mapping);
                        }
                    },
                );
                tokio::select! {
                    result = task => result,
                    _ = tokio::signal::ctrl_c() => { cancel.cancel(); Ok(()) }
                }?;
            } else {
                let mapping =
                    relay_platform::pcp::map(gateway, internal_port, external_port, lifetime)
                        .await?;
                println!("{}", serde_json::to_string_pretty(&mapping)?);
                if let Some(path) = &state_file {
                    if delete {
                        relay_platform::state::remove_if_present(path)?;
                    } else {
                        relay_platform::state::write_json_atomic(path, &mapping)?;
                    }
                }
            }
        }
        Command::NatMap {
            gateway,
            internal_port,
            external_port,
            lifetime_secs,
            delete,
            renew,
            renew_after_secs,
            retry_secs,
            retry_max_secs,
            state_file,
            restore_state,
        } => {
            let gateway = relay_platform::nat::gateway_from(&gateway)?;
            relay_platform::nat::validate_ports(internal_port, external_port)?;
            relay_platform::nat::validate_lifetime(lifetime_secs)?;
            let lifetime = if delete { 0 } else { lifetime_secs };
            if restore_state && !delete {
                let path = state_file
                    .as_ref()
                    .context("--restore-state requires --state-file")?;
                if let Some(previous) =
                    relay_platform::state::read_json::<relay_platform::nat::Mapping>(path)?
                    && (previous.internal_port != internal_port
                        || previous.external_port != external_port)
                {
                    relay_platform::nat::map(
                        gateway,
                        previous.internal_port,
                        previous.external_port,
                        0,
                    )
                    .await?;
                    relay_platform::state::remove_if_present(path)?;
                }
            }
            if renew && !delete {
                let after = renew_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_secs(u64::from((lifetime_secs / 2).max(1))));
                let cancel = CancellationToken::new();
                let stop = cancel.clone();
                let task = relay_platform::nat::maintain(
                    gateway,
                    internal_port,
                    external_port,
                    lifetime,
                    after,
                    retry_policy(retry_secs, retry_max_secs)?,
                    stop,
                    move |mapping| {
                        println!("{}", serde_json::to_string(mapping).unwrap_or_default());
                        if let Some(path) = &state_file {
                            let _ = relay_platform::state::write_json_atomic(path, mapping);
                        }
                    },
                );
                tokio::select! {
                    result = task => result,
                    _ = tokio::signal::ctrl_c() => {
                        cancel.cancel();
                        Ok(())
                    }
                }?;
            } else {
                let mapping =
                    relay_platform::nat::map(gateway, internal_port, external_port, lifetime)
                        .await?;
                println!("{}", serde_json::to_string_pretty(&mapping)?);
                if let Some(path) = &state_file {
                    if delete {
                        relay_platform::state::remove_if_present(path)?;
                    } else {
                        relay_platform::state::write_json_atomic(path, &mapping)?;
                    }
                }
            }
        }
        Command::MptcpInfo => {
            println!(
                "{}",
                serde_json::to_string_pretty(&relay_platform::mptcp::detect())?
            );
        }
        Command::BuildInfo => {
            // Bump the relevant contract before an incompatible persisted-state
            // change. Deployment rollback requires exact contract equality and
            // never restores older state or recovery logs.
            println!(
                "{}",
                serde_json::json!({
                    "product": "relay-platform",
                    "version": env!("CARGO_PKG_VERSION"),
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "deployment_format": 1,
                    "state_contract": {"controller": 2, "agent": 2},
                    "controller_schema": 5
                })
            );
        }
        Command::Server {
            listen,
            state,
            admin_password_file,
            recovery_log,
            sync_batch_size,
            behind_tls_proxy,
        } => {
            ensure!(
                listen.ip().is_loopback() || behind_tls_proxy,
                "a non-loopback control listener requires --behind-tls-proxy and an HTTPS reverse proxy"
            );
            private_directory(&state)?;
            let store = Store::open(&state.join("controller.sqlite"))?;
            let _instance = store.lock_instance()?;
            store
                .enable_recovery_log(&recovery_log.unwrap_or_else(|| state.join("recovery.log")))?;
            store.set_kind("controller")?;
            if store.needs_bootstrap()? {
                let password_path =
                    admin_password_file.unwrap_or_else(|| state.join("admin-password.secret"));
                if !password_path.exists() {
                    write_secret(&password_path, secret().as_bytes())?;
                }
                let password = std::fs::read_to_string(&password_path)?;
                store.bootstrap(password.trim())?;
                tracing::info!(username="admin",password_file=%password_path.display(),"administrator initialized; password is stored in the private file");
            }
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(address=%listener.local_addr()?,"controller listening");
            tokio::spawn(relay_platform::alerts::run(
                store.clone(),
                Duration::from_secs(2),
                stop.clone(),
            ));
            axum::serve(
                listener,
                api::router(
                    AppState::new(store)
                        .with_sync_batch_size(sync_batch_size as usize)?
                        .with_shutdown(stop.clone()),
                )
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(stop.cancelled_owned())
            .await?;
        }
        Command::Restore {
            backup,
            recovery_log,
            output,
        } => {
            let report =
                relay_platform::journal::restore_controller(&backup, &recovery_log, &output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Agent {
            controller,
            node_id,
            state,
            enrollment_token_file,
            ca_certificate,
            tls_directory,
            poll_seconds,
        } => {
            private_directory(&state)?;
            let store = Store::open(&state.join("agent.sqlite"))?;
            agent::run(
                store,
                AgentOptions {
                    controller,
                    node_id,
                    enrollment_token_file,
                    ca_certificate,
                    tls_directory: Some(tls_directory.unwrap_or_else(|| state.join("tls"))),
                    poll_interval: Duration::from_secs(poll_seconds),
                },
                stop,
            )
            .await?;
        }
        Command::Standalone {
            config,
            database,
            tls_directory,
            watch,
        } => {
            let store = Store::open(&database)?;
            let _instance = store.lock_instance()?;
            store.set_kind("agent")?;
            let engine = Engine::with_tls_directory(store, tls_directory);
            let initial = read_config(&config).await?;
            engine.apply(initial).await?;
            tracing::info!(
                revision = engine.revision().await,
                "standalone configuration active"
            );
            loop {
                tokio::select! {biased;_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2)),if watch=>{
                    match read_config(&config).await {Ok(update)=>if let Err(error)=engine.apply(update).await{tracing::warn!(%error,"reload rejected; previous revision remains active");},Err(error)=>tracing::warn!(%error,"cannot read configuration; previous revision remains active")}
                }}
            }
            engine.shutdown().await?;
        }
        Command::Validate { config } => {
            read_config(&config).await?.validate()?;
            println!("configuration valid");
        }
        Command::Backup { database, output } => {
            ensure!(database.exists(), "source database does not exist");
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                private_directory(parent)?;
            }
            Store::open(&database)?.backup(&output)?;
            println!("backup created: {}", output.display());
        }
        Command::Usage { database } => {
            ensure!(database.exists(), "database does not exist");
            println!(
                "{}",
                serde_json::to_string_pretty(&Store::open(&database)?.agent_usage(false)?)?
            );
        }
    }
    Ok(())
}
async fn read_config(path: &PathBuf) -> Result<NodeConfig> {
    serde_json::from_slice(&tokio::fs::read(path).await?).context("invalid configuration JSON")
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
