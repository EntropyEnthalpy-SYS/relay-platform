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
        Command::Server {
            listen,
            state,
            admin_password_file,
            recovery_log,
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
            axum::serve(
                listener,
                api::router(AppState::new(store))
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
