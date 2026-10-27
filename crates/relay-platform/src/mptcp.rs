//! MPTCP capability observation. This module deliberately does not claim a
//! working multipath data path: it probes the kernel, reports the configured
//! interfaces/routes and exposes whether MPTCP sockets can be created.
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Interface {
    pub name: String,
    pub state: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Route {
    pub interface: String,
    pub destination: String,
    pub gateway: String,
    pub mask: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Capability {
    pub platform: &'static str,
    pub kernel: Option<String>,
    pub supported: bool,
    pub enabled: Option<bool>,
    pub probe_error: Option<String>,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub endpoints: Vec<String>,
    pub active_connections: Option<u64>,
    pub note: &'static str,
}

pub fn detect() -> Capability {
    let mut capability = Capability {
        platform: std::env::consts::OS,
        kernel: None,
        supported: false,
        enabled: None,
        probe_error: None,
        interfaces: Vec::new(),
        routes: Vec::new(),
        endpoints: Vec::new(),
        active_connections: None,
        note: "Capability and configuration observation only; no MPTCP data path is enabled by this report.",
    };
    #[cfg(target_os = "linux")]
    {
        capability.kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_owned());
        capability.enabled = std::fs::read_to_string("/proc/sys/net/mptcp/enabled")
            .ok()
            .and_then(|value| value.trim().parse::<u8>().ok())
            .map(|value| value != 0);
        match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::MPTCP),
        ) {
            Ok(socket) => {
                drop(socket);
                capability.supported = true;
            }
            Err(error) => capability.probe_error = Some(error.to_string()),
        }
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut interfaces: Vec<_> = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .map(|name| {
                    let state = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
                        .map(|value| value.trim().to_owned())
                        .unwrap_or_else(|_| "unknown".into());
                    Interface { name, state }
                })
                .collect();
            interfaces.sort_by(|a, b| a.name.cmp(&b.name));
            capability.interfaces = interfaces;
        }
        if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
            capability.routes = routes
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    (fields.len() >= 8).then(|| Route {
                        interface: fields[0].into(),
                        destination: fields[1].into(),
                        gateway: fields[2].into(),
                        mask: fields[7].into(),
                    })
                })
                .take(128)
                .collect();
        }
        if let Ok(endpoints) = std::fs::read_to_string("/proc/net/mptcp") {
            capability.endpoints = endpoints.lines().take(128).map(str::to_owned).collect();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        capability.probe_error = Some("MPTCP socket capability is probed on Linux only".into());
    }
    capability
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detection_is_explicit_about_the_platform() {
        let capability = detect();
        assert_eq!(capability.platform, std::env::consts::OS);
        assert!(!capability.note.is_empty());
        if !cfg!(target_os = "linux") {
            assert!(!capability.supported);
            assert!(capability.probe_error.is_some());
        }
        assert!(capability.routes.len() <= 128);
        assert!(capability.endpoints.len() <= 128);
    }
}
