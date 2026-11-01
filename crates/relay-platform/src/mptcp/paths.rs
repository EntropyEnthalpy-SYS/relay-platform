//! Extra local addresses for Linux MPTCP subflows ("endpoints"), applied by an
//! agent whose server opted in with `RELAY_MPTCP_PATHS=1` and CAP_NET_ADMIN.
//! The agent touches only endpoints with ids in its own range, so endpoints a
//! server operator configured by hand stay as they are. Kernel limits are
//! changed only when the panel sets them.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// The first endpoint id the agent owns; the kernel accepts 1..=255.
pub const FIRST_ID: u8 = 200;
pub const MAX_ENDPOINTS: usize = 8;
const KERNEL_LIMIT: u8 = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    pub endpoints: Vec<Endpoint>,
    /// Server-wide kernel limits; `None` leaves the server's own value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflows: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_addr_accepted: Option<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Announce this address to the peer (the server side of a connection).
    #[serde(default)]
    pub signal: bool,
    /// Open subflows from this address (the client side of a connection).
    #[serde(default)]
    pub subflow: bool,
    /// Use this path only when the others fail.
    #[serde(default)]
    pub backup: bool,
}
/// What the agent last found on its server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Report {
    /// The server allows the agent to change MPTCP endpoints.
    pub host_enabled: bool,
    /// Agent-owned endpoint addresses now in place.
    pub applied: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflows: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_addr_accepted: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn interface_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
impl Paths {
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty() && self.subflows.is_none() && self.add_addr_accepted.is_none()
    }
    pub fn validate(&self) -> Result<()> {
        let mut seen = Vec::with_capacity(self.endpoints.len());
        for endpoint in &self.endpoints {
            let address = crate::model::canonical_ip(endpoint.address);
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address == IpAddr::V4(Ipv4Addr::BROADCAST)
                || seen.contains(&address)
                || endpoint
                    .interface
                    .as_deref()
                    .is_some_and(|name| !interface_name(name))
                || !(endpoint.signal || endpoint.subflow)
            {
                return crate::store::reject(
                    400,
                    "each MPTCP path needs a distinct unicast address, a valid interface name if given, and signal or subflow",
                );
            }
            seen.push(address);
        }
        if self.endpoints.len() > MAX_ENDPOINTS
            || self.subflows.is_some_and(|n| n > KERNEL_LIMIT)
            || self.add_addr_accepted.is_some_and(|n| n > KERNEL_LIMIT)
        {
            return crate::store::reject(400, "at most 8 MPTCP paths, and kernel limits of 0..8");
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Observed {
    id: u8,
    address: IpAddr,
    interface: Option<String>,
    signal: bool,
    subflow: bool,
    backup: bool,
}
/// `ip -j mptcp endpoint show`. iproute2 6.1 prints each flag as a boolean;
/// later versions may list them in `flags`.
fn parse_endpoints(json: &str) -> Result<Vec<Observed>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(json).context("unreadable ip mptcp output")?;
    rows.iter()
        .map(|row| {
            let flags: Vec<&str> = row["flags"]
                .as_array()
                .map(|list| list.iter().filter_map(|f| f.as_str()).collect())
                .unwrap_or_default();
            let flag = |name: &str| row[name].as_bool().unwrap_or(false) || flags.contains(&name);
            Ok(Observed {
                id: u8::try_from(row["id"].as_u64().context("endpoint without id")?)?,
                address: row["address"]
                    .as_str()
                    .context("endpoint without address")?
                    .parse()?,
                interface: row["dev"].as_str().map(str::to_owned),
                signal: flag("signal"),
                subflow: flag("subflow"),
                backup: flag("backup"),
            })
        })
        .collect()
}
/// `ip mptcp limits show` prints `add_addr_accepted N subflows M`.
fn parse_limits(text: &str) -> (Option<u8>, Option<u8>) {
    let words: Vec<&str> = text.split_whitespace().collect();
    let value = |name: &str| {
        words
            .windows(2)
            .find(|pair| pair[0] == name)
            .and_then(|pair| pair[1].parse().ok())
    };
    (value("subflows"), value("add_addr_accepted"))
}
fn owned(id: u8) -> bool {
    (FIRST_ID..FIRST_ID + MAX_ENDPOINTS as u8).contains(&id)
}
fn matches(observed: &Observed, wanted: &Endpoint) -> bool {
    observed.address == crate::model::canonical_ip(wanted.address)
        && (wanted.interface.is_none() || observed.interface == wanted.interface)
        && (observed.signal, observed.subflow, observed.backup)
            == (wanted.signal, wanted.subflow, wanted.backup)
}
/// The `ip` commands that move owned endpoints to `desired`, deletions first,
/// and the addresses that an operator's own endpoint already uses.
fn plan(observed: &[Observed], desired: &Paths) -> (Vec<Vec<String>>, Vec<IpAddr>) {
    let wanted = |id: u8| {
        desired
            .endpoints
            .get(usize::from(id.wrapping_sub(FIRST_ID)))
    };
    let mut commands = Vec::new();
    for endpoint in observed.iter().filter(|e| owned(e.id)) {
        if !wanted(endpoint.id).is_some_and(|w| matches(endpoint, w)) {
            commands.push(vec![
                "mptcp".into(),
                "endpoint".into(),
                "delete".into(),
                "id".into(),
                endpoint.id.to_string(),
            ]);
        }
    }
    let mut conflicts = Vec::new();
    for (index, endpoint) in desired.endpoints.iter().enumerate() {
        let id = FIRST_ID + index as u8;
        let address = crate::model::canonical_ip(endpoint.address);
        if observed.iter().any(|e| e.id == id && matches(e, endpoint)) {
            continue;
        }
        if observed
            .iter()
            .any(|e| !owned(e.id) && e.address == address)
        {
            conflicts.push(address);
            continue;
        }
        let mut command: Vec<String> = vec![
            "mptcp".into(),
            "endpoint".into(),
            "add".into(),
            address.to_string(),
        ];
        if let Some(interface) = &endpoint.interface {
            command.extend(["dev".into(), interface.clone()]);
        }
        command.extend(["id".into(), id.to_string()]);
        for (on, name) in [
            (endpoint.signal, "signal"),
            (endpoint.subflow, "subflow"),
            (endpoint.backup, "backup"),
        ] {
            if on {
                command.push(name.into());
            }
        }
        commands.push(command);
    }
    (commands, conflicts)
}

/// Applies the controller's desired paths on this server, rechecking once a
/// minute so hand edits and failed attempts converge.
pub struct Applier {
    opted_in: bool,
    last: Option<(Paths, Report, tokio::time::Instant)>,
}
impl Applier {
    pub fn from_env() -> Self {
        Self {
            opted_in: std::env::var("RELAY_MPTCP_PATHS").as_deref() == Ok("1"),
            last: None,
        }
    }
    pub async fn reconcile(&mut self, desired: &Paths) -> Report {
        if !self.opted_in || !cfg!(target_os = "linux") {
            return Report {
                error: (!desired.is_empty()).then(|| {
                    "this server has not allowed the agent to manage MPTCP paths (RELAY_MPTCP_PATHS=1 and CAP_NET_ADMIN on Linux)".into()
                }),
                ..Report::default()
            };
        }
        if let Some((paths, report, at)) = &self.last
            && paths == desired
            && at.elapsed() < std::time::Duration::from_secs(60)
        {
            return report.clone();
        }
        let report = match apply(desired).await {
            Ok(report) => report,
            Err(error) => Report {
                host_enabled: true,
                error: Some(error.to_string().chars().take(512).collect()),
                ..Report::default()
            },
        };
        if let Some(error) = &report.error {
            tracing::warn!(%error, "MPTCP paths not fully applied");
        }
        self.last = Some((desired.clone(), report.clone(), tokio::time::Instant::now()));
        report
    }
}
async fn ip(args: &[String]) -> Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("ip")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("ip command timed out")?
    .context("cannot run the ip command")?;
    anyhow::ensure!(
        output.status.success(),
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
async fn apply(desired: &Paths) -> Result<Report> {
    let show = ["-j", "mptcp", "endpoint", "show"].map(String::from);
    let (commands, conflicts) = plan(&parse_endpoints(&ip(&show).await?)?, desired);
    let mut errors: Vec<String> = conflicts
        .iter()
        .map(|address| {
            format!("{address} is already an MPTCP endpoint configured outside the panel")
        })
        .collect();
    for command in commands {
        if let Err(error) = ip(&command).await {
            errors.push(error.to_string());
        }
    }
    let limits = ["mptcp", "limits", "show"].map(String::from);
    let (subflows, add_addr_accepted) = parse_limits(&ip(&limits).await?);
    let mut set: Vec<String> = ["mptcp", "limits", "set"].map(String::from).to_vec();
    if let Some(n) = desired.subflows.filter(|n| Some(*n) != subflows) {
        set.extend(["subflows".into(), n.to_string()]);
    }
    if let Some(n) = desired
        .add_addr_accepted
        .filter(|n| Some(*n) != add_addr_accepted)
    {
        set.extend(["add_addr_accepted".into(), n.to_string()]);
    }
    if set.len() > 3
        && let Err(error) = ip(&set).await
    {
        errors.push(error.to_string());
    }
    let after = parse_endpoints(&ip(&show).await?)?;
    let (subflows, add_addr_accepted) = parse_limits(&ip(&limits).await?);
    Ok(Report {
        host_enabled: true,
        applied: after
            .iter()
            .filter(|e| owned(e.id))
            .map(|e| e.address)
            .collect(),
        subflows,
        add_addr_accepted,
        error: (!errors.is_empty()).then(|| errors.join("; ").chars().take(512).collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, signal: bool, subflow: bool) -> Endpoint {
        Endpoint {
            address: address.parse().unwrap(),
            interface: Some("eth1".into()),
            signal,
            subflow,
            backup: false,
        }
    }

    #[test]
    fn reads_both_iproute2_flag_formats_and_limits() {
        let old = r#"[{"address":"10.9.0.2","id":200,"signal":true,"subflow":true,"backup":true,"dev":"dummy0"}]"#;
        let new = r#"[{"address":"10.9.0.2","id":200,"flags":["signal","subflow","backup"],"dev":"dummy0"}]"#;
        assert_eq!(parse_endpoints(old).unwrap(), parse_endpoints(new).unwrap());
        assert!(parse_endpoints(old).unwrap()[0].backup);
        assert!(parse_endpoints("").unwrap().is_empty());
        assert_eq!(
            parse_limits("add_addr_accepted 0 subflows 2 \n"),
            (Some(2), Some(0))
        );
    }

    #[test]
    fn plan_keeps_hand_made_endpoints_and_replaces_only_changed_owned_ones() {
        let observed = vec![
            // An operator's endpoint outside the agent's id range.
            Observed {
                id: 1,
                address: "192.0.2.9".parse().unwrap(),
                interface: Some("eth0".into()),
                signal: true,
                subflow: false,
                backup: false,
            },
            // Owned and still wanted.
            Observed {
                id: 200,
                address: "192.0.2.10".parse().unwrap(),
                interface: Some("eth1".into()),
                signal: true,
                subflow: false,
                backup: false,
            },
            // Owned with different flags than wanted at id 201.
            Observed {
                id: 201,
                address: "192.0.2.11".parse().unwrap(),
                interface: Some("eth1".into()),
                signal: true,
                subflow: false,
                backup: false,
            },
            // Owned and no longer wanted.
            Observed {
                id: 205,
                address: "192.0.2.15".parse().unwrap(),
                interface: None,
                signal: false,
                subflow: true,
                backup: false,
            },
        ];
        let desired = Paths {
            endpoints: vec![
                endpoint("192.0.2.10", true, false),
                endpoint("192.0.2.11", false, true),
                endpoint("192.0.2.9", true, false),
            ],
            ..Paths::default()
        };
        let (commands, conflicts) = plan(&observed, &desired);
        let text: Vec<String> = commands.iter().map(|c| c.join(" ")).collect();
        assert_eq!(
            text,
            [
                "mptcp endpoint delete id 201",
                "mptcp endpoint delete id 205",
                "mptcp endpoint add 192.0.2.11 dev eth1 id 201 subflow",
            ]
        );
        assert_eq!(conflicts, ["192.0.2.9".parse::<IpAddr>().unwrap()]);
        assert!(
            !text
                .iter()
                .any(|c| c.contains("id 1 ") || c.ends_with("id 1"))
        );
    }

    #[test]
    fn validation_rejects_ambiguous_or_unsafe_paths() {
        let ok = Paths {
            endpoints: vec![endpoint("192.0.2.10", true, false)],
            subflows: Some(4),
            add_addr_accepted: Some(4),
        };
        ok.validate().unwrap();
        for bad in [
            Paths {
                endpoints: vec![endpoint("0.0.0.0", true, false)],
                ..ok.clone()
            },
            Paths {
                endpoints: vec![endpoint("127.0.0.1", true, false)],
                ..ok.clone()
            },
            Paths {
                endpoints: vec![endpoint("192.0.2.10", false, false)],
                ..ok.clone()
            },
            Paths {
                endpoints: vec![
                    endpoint("192.0.2.10", true, false),
                    endpoint("::ffff:192.0.2.10", false, true),
                ],
                ..ok.clone()
            },
            Paths {
                endpoints: vec![Endpoint {
                    interface: Some("eth0; reboot".into()),
                    ..endpoint("192.0.2.10", true, false)
                }],
                ..ok.clone()
            },
            Paths {
                subflows: Some(9),
                ..ok.clone()
            },
            Paths {
                endpoints: (1..=9)
                    .map(|n| endpoint(&format!("192.0.2.{n}"), true, false))
                    .collect(),
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
