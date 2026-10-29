//! CLI fixtures keep the kernel-selected ports bound until the server exits.
use std::{
    io::ErrorKind,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

pub struct Process {
    pub child: Child,
    log: PathBuf,
}
impl Process {
    pub fn spawn(root: &Path, name: &str, args: &[String]) -> Self {
        let log = root.join(format!("{name}.log"));
        let file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_relay"))
            .args(args)
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        Self { child, log }
    }
    pub fn diagnostic(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    pub fn assert_alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "CLI process exited: {}",
            self.diagnostic()
        );
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Server {
    pub process: Process,
    pub control: SocketAddr,
    pub public: SocketAddr,
    pub ready: serde_json::Value,
    token: PathBuf,
}
impl Server {
    pub fn start(root: &Path, token: &str, extra: &[&str]) -> Self {
        let token_file = root.join("token");
        std::fs::write(&token_file, token).unwrap();
        let ready_file = root.join("ready.json");
        let mut args: Vec<String> = [
            "reverse-mux-server",
            "--control-listen",
            "127.0.0.1:0",
            "--public-listen",
            "127.0.0.1:0",
            "--token-file",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.extend([
            token_file.display().to_string(),
            "--ready-file".into(),
            ready_file.display().to_string(),
        ]);
        args.extend(extra.iter().map(|v| v.to_string()));
        let mut process = Process::spawn(root, "server", &args);
        let deadline = Instant::now() + Duration::from_secs(15);
        let ready = loop {
            process.assert_alive();
            if let Ok(bytes) = std::fs::read(&ready_file)
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            {
                assert_eq!(value["pid"], process.child.id());
                assert_eq!(value["state"], "listeners_bound");
                break value;
            }
            assert!(
                Instant::now() < deadline,
                "listener readiness deadline: {}",
                process.diagnostic()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        Self {
            control: ready["control_listen"].as_str().unwrap().parse().unwrap(),
            public: ready["public_listen"].as_str().unwrap().parse().unwrap(),
            ready,
            process,
            token: token_file,
        }
    }
    pub fn client(&self, root: &Path, target: SocketAddr) -> Process {
        Process::spawn(
            root,
            "client",
            &[
                "reverse-mux-client".into(),
                "--server".into(),
                self.control.to_string(),
                "--target".into(),
                target.to_string(),
                "--token-file".into(),
                self.token.display().to_string(),
            ],
        )
    }
    pub fn accept_target(&mut self, client: &mut Process, target: &TcpListener) -> TcpStream {
        target.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.process.assert_alive();
            client.assert_alive();
            match target.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept target: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "target not reached; server: {}; client: {}",
                self.process.diagnostic(),
                client.diagnostic()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
