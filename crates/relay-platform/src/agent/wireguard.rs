//! Applies the controller's WireGuard interfaces on this server. The agent
//! acts only when the server allows it (`RELAY_WIREGUARD=1`, CAP_NET_ADMIN and
//! wireguard-tools) and only on WireGuard links named `rwg-*`, so links an
//! operator made stay as they are. It never adds default routes, policy
//! rules, firewall rules or server-wide settings; forwarding is switched on
//! for the relay's or hub's own link only. Stopping the agent leaves the
//! links up, so an upgrade does not interrupt the network.
use crate::{
    store::Store,
    wireguard::{self as wg, Desired, Interface, InterfaceReport, PeerReport, Report},
};
use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use std::{collections::HashMap, net::Ipv4Addr, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, time::Instant};

/// Agent metadata key of this node's private key.
const KEY: &str = "agent_wireguard_key";
/// Hand edits and failed attempts converge within this time.
const RECHECK: Duration = Duration::from_secs(60);
const STATUS_EVERY: Duration = Duration::from_secs(10);

pub struct Applier {
    opted_in: bool,
    /// The controller's host: an interface must never capture its route.
    controller: String,
    key: Option<String>,
    last: Option<(String, Instant)>,
    status_at: Option<Instant>,
    report: Report,
}

impl Applier {
    pub fn new(store: &Store, controller: &str) -> Result<Self> {
        Ok(Self {
            opted_in: std::env::var("RELAY_WIREGUARD").as_deref() == Ok("1"),
            controller: controller.to_string(),
            key: store.metadata(KEY)?,
            last: None,
            status_at: None,
            report: Report::default(),
        })
    }

    pub async fn reconcile(&mut self, store: &Store, desired: &Desired) -> Report {
        let due = self
            .last
            .as_ref()
            .is_none_or(|(digest, at)| *digest != desired.digest || at.elapsed() >= RECHECK);
        if due {
            self.last = Some((desired.digest.clone(), Instant::now()));
            self.report = self.apply(store, desired).await;
            self.status_at = Some(Instant::now());
        } else if !self.report.interfaces.is_empty()
            && self.status_at.is_none_or(|at| at.elapsed() >= STATUS_EVERY)
        {
            for interface in &mut self.report.interfaces {
                if let Ok(peers) = status(&interface.name).await {
                    interface.peers = peers;
                }
            }
            self.status_at = Some(Instant::now());
        }
        self.report.clone()
    }

    async fn apply(&mut self, store: &Store, desired: &Desired) -> Report {
        if let Err(problem) = self.preflight().await {
            return Report {
                problem: (desired.enabled || !desired.interfaces.is_empty())
                    .then(|| format!("{problem:#}")),
                ..Report::default()
            };
        }
        if desired.enabled && self.key.is_none() {
            let key = wg::private_key();
            if let Err(error) = store.set_metadata(KEY, &key) {
                return Report {
                    ready: true,
                    problem: Some(format!("cannot save the WireGuard key: {error:#}")),
                    ..Report::default()
                };
            }
            self.key = Some(key);
        }
        let mut report = Report {
            ready: true,
            probes: true,
            preshared_keys: true,
            public_key: self
                .key
                .as_deref()
                .filter(|_| desired.enabled)
                .and_then(|key| wg::public_key(key).ok()),
            ..Report::default()
        };
        match converge(desired, self.key.as_deref(), &self.controller).await {
            Ok(interfaces) => report.interfaces = interfaces,
            Err(error) => report.problem = Some(format!("{error:#}")),
        }
        // Failures are reported per interface, so one refused network does
        // not hide that the node's other networks are current.
        report.applied = desired.digest.clone();
        if let Some(problem) = &report.problem {
            tracing::warn!(%problem, "WireGuard interfaces not applied");
        }
        for interface in report.interfaces.iter().filter(|i| i.error.is_some()) {
            tracing::warn!(interface = %interface.name, error = interface.error.as_deref().unwrap_or_default(), "WireGuard interface refused");
        }
        report
    }

    /// Removes every agent-owned link, for a node the controller revoked.
    /// A server that never allowed WireGuard keeps its links untouched.
    pub async fn remove_all(&self) {
        if !self.opted_in {
            return;
        }
        if let Ok(links) = owned_links().await {
            for name in links {
                let _ = ip(&["link", "del", "dev", &name]).await;
            }
        }
    }

    async fn preflight(&self) -> Result<()> {
        ensure!(
            self.opted_in && cfg!(target_os = "linux"),
            "this server has not allowed the agent to manage WireGuard (RELAY_WIREGUARD=1 with CAP_NET_ADMIN on Linux; see deploy/relay-agent-wireguard.conf)"
        );
        let status = tokio::fs::read_to_string("/proc/self/status").await?;
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .unwrap_or(0);
        ensure!(
            effective & (1 << 12) != 0,
            "the agent lacks CAP_NET_ADMIN; install deploy/relay-agent-wireguard.conf"
        );
        command("wg", &["--version"], None)
            .await
            .context("wireguard-tools is not installed (apt install wireguard-tools)")?;
        Ok(())
    }
}

async fn command(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot run {program}"))?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(input.as_bytes()).await?;
    }
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .with_context(|| format!("{program} timed out"))??;
    ensure!(
        output.status.success(),
        "{program} {} failed: {}",
        args.first().copied().unwrap_or_default(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
async fn ip(args: &[&str]) -> Result<String> {
    command("ip", args, None).await
}
fn json(text: &str) -> Result<Vec<serde_json::Value>> {
    if text.trim().is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str(text).context("unreadable ip output")
}
fn owned(name: &str) -> bool {
    name.starts_with(wg::PREFIX)
}

async fn owned_links() -> Result<Vec<String>> {
    Ok(
        json(&ip(&["-j", "link", "show", "type", "wireguard"]).await?)?
            .iter()
            .filter_map(|link| link["ifname"].as_str())
            .filter(|name| owned(name))
            .map(str::to_string)
            .collect(),
    )
}

/// Prefixes that other links use: an address's subnet or a route, except
/// default routes.
fn taken(addresses: &str, routes: &str) -> Result<Vec<(Ipv4Net, String)>> {
    let mut taken = vec![];
    for link in json(addresses)? {
        let name = link["ifname"].as_str().unwrap_or_default();
        if owned(name) {
            continue;
        }
        for address in link["addr_info"].as_array().into_iter().flatten() {
            if let (Some(local), Some(len)) =
                (address["local"].as_str(), address["prefixlen"].as_u64())
                && let Ok(net) = Ipv4Net::new(local.parse()?, len as u8)
            {
                taken.push((net.trunc(), format!("address {local}/{len} on {name}")));
            }
        }
    }
    for route in json(routes)? {
        let dst = route["dst"].as_str().unwrap_or("default");
        let dev = route["dev"].as_str().unwrap_or_default();
        if dst == "default" || owned(dev) {
            continue;
        }
        let net = dst
            .parse::<Ipv4Net>()
            .or_else(|_| dst.parse::<Ipv4Addr>().map(Ipv4Net::from));
        if let Ok(net) = net {
            taken.push((
                net,
                format!("route {dst} via {}", if dev.is_empty() { "-" } else { dev }),
            ));
        }
    }
    Ok(taken)
}

/// Refuses a network that would capture traffic it must not carry.
fn guard(
    interface: &Interface,
    taken: &[(Ipv4Net, String)],
    protected: &[(Ipv4Addr, String)],
) -> Result<()> {
    let net = Ipv4Net::new(interface.address, interface.prefix)?.trunc();
    if let Some((_, what)) = taken
        .iter()
        .find(|(other, _)| net.contains(other) || other.contains(&net))
    {
        anyhow::bail!("{net} overlaps the {what} on this server; choose another range");
    }
    if let Some((_, what)) = protected.iter().find(|(ip, _)| net.contains(ip)) {
        anyhow::bail!("{net} contains {what}; choose another range");
    }
    Ok(())
}

async fn resolve(host: &str) -> Vec<Ipv4Addr> {
    let lookup = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(host));
    match lookup.await {
        Ok(Ok(addresses)) => addresses
            .filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
            })
            .collect(),
        _ => vec![],
    }
}

async fn converge(
    desired: &Desired,
    key: Option<&str>,
    controller: &str,
) -> Result<Vec<InterfaceReport>> {
    let links = owned_links().await?;
    for name in links
        .iter()
        .filter(|name| !desired.interfaces.iter().any(|i| &i.name == *name))
    {
        ip(&["link", "del", "dev", name]).await?;
    }
    if desired.interfaces.is_empty() {
        return Ok(vec![]);
    }
    let key = key.context("no WireGuard key yet")?;
    let taken = taken(
        &ip(&["-j", "-4", "address", "show"]).await?,
        &ip(&["-j", "-4", "route", "show", "table", "all"]).await?,
    )?;
    // Looked up together, so slow DNS holds the sync loop for one timeout.
    let endpoints: Vec<&str> = desired
        .interfaces
        .iter()
        .flat_map(|i| i.peers.iter().filter_map(|p| p.endpoint.as_deref()))
        .collect();
    let (controller_ips, resolved) = tokio::join!(
        resolve(controller),
        futures_util::future::join_all(endpoints.iter().map(|e| resolve(e)))
    );
    let resolved: HashMap<&str, Vec<Ipv4Addr>> = endpoints.into_iter().zip(resolved).collect();
    let mut reports = vec![];
    for interface in &desired.interfaces {
        let mut protected: Vec<(Ipv4Addr, String)> = controller_ips
            .iter()
            .map(|ip| (*ip, format!("the controller address {ip}")))
            .collect();
        for endpoint in interface.peers.iter().filter_map(|p| p.endpoint.as_deref()) {
            protected.extend(
                resolved[endpoint]
                    .iter()
                    .map(|ip| (*ip, format!("the peer endpoint {endpoint}"))),
            );
        }
        let exists = links.contains(&interface.name);
        // A link that may capture the wrong traffic, or one only half made,
        // does not stay. A link that worked before keeps running when an
        // update fails, for example while an endpoint does not resolve.
        let failure = match guard(interface, &taken, &protected) {
            Ok(()) => setup(interface, key, exists, &controller_ips)
                .await
                .err()
                .map(|error| (error, !exists)),
            Err(error) => Some((error, exists)),
        };
        if let Some((_, true)) = &failure {
            let _ = ip(&["link", "del", "dev", &interface.name]).await;
        }
        let error: Option<String> =
            failure.map(|(error, _)| format!("{error:#}").chars().take(512).collect());
        reports.push(InterfaceReport {
            network_id: interface.network_id.clone(),
            name: interface.name.clone(),
            peers: if error.is_none() {
                status(&interface.name).await.unwrap_or_default()
            } else {
                vec![]
            },
            error,
        });
    }
    Ok(reports)
}

async fn setup(
    interface: &Interface,
    key: &str,
    exists: bool,
    controller_ips: &[Ipv4Addr],
) -> Result<()> {
    let name = interface.name.as_str();
    if !exists {
        ip(&["link", "add", "dev", name, "type", "wireguard"])
            .await
            .context("the kernel cannot create a WireGuard link")?;
    }
    command(
        "wg",
        &["syncconf", name, "/dev/stdin"],
        Some(&wg::wg_config(interface, key)),
    )
    .await?;
    ip(&[
        "link",
        "set",
        "dev",
        name,
        "mtu",
        &interface.mtu.to_string(),
    ])
    .await?;
    let wanted = format!("{}/{}", interface.address, interface.prefix);
    ip(&["-4", "address", "replace", &wanted, "dev", name]).await?;
    for link in json(&ip(&["-j", "-4", "address", "show", "dev", name]).await?)? {
        for address in link["addr_info"].as_array().into_iter().flatten() {
            if let (Some(local), Some(len)) =
                (address["local"].as_str(), address["prefixlen"].as_u64())
                && format!("{local}/{len}") != wanted
            {
                ip(&[
                    "-4",
                    "address",
                    "del",
                    &format!("{local}/{len}"),
                    "dev",
                    name,
                ])
                .await?;
            }
        }
    }
    tokio::fs::write(
        format!("/proc/sys/net/ipv4/conf/{name}/forwarding"),
        if interface.forwarding { "1" } else { "0" },
    )
    .await
    .context("cannot set forwarding on the WireGuard link")?;
    ip(&["link", "set", "dev", name, "up"]).await?;
    for controller in controller_ips {
        let route = json(&ip(&["-j", "route", "get", &controller.to_string()]).await?)?;
        if route.iter().any(|r| r["dev"].as_str().is_some_and(owned)) {
            let _ = ip(&["link", "del", "dev", name]).await;
            anyhow::bail!(
                "the link would carry the traffic to the controller {controller}; removed it"
            );
        }
    }
    Ok(())
}

/// `wg show NAME dump`. The first line holds the private key and is dropped
/// before anything is read.
async fn status(name: &str) -> Result<Vec<PeerReport>> {
    Ok(parse_dump(
        &command("wg", &["show", name, "dump"], None).await?,
    ))
}
fn parse_dump(dump: &str) -> Vec<PeerReport> {
    dump.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            (fields.len() >= 8).then(|| PeerReport {
                public_key: fields[0].to_string(),
                endpoint: Some(fields[2].to_string()).filter(|e| e != "(none)"),
                handshake: fields[4].parse().unwrap_or(0),
                rx_bytes: fields[5].parse().unwrap_or(0),
                tx_bytes: fields[6].parse().unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(address: &str, prefix: u8) -> Interface {
        Interface {
            network_id: "n".into(),
            name: "rwg-0f1e2d3c".into(),
            address: address.parse().unwrap(),
            prefix,
            mtu: 1420,
            listen_port: 51820,
            forwarding: false,
            peers: vec![],
        }
    }

    #[test]
    fn guard_refuses_ranges_used_by_other_links_but_not_by_own_ones() {
        let addresses = r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
            {"ifname":"eth0","addr_info":[{"local":"10.210.1.2","prefixlen":24}]},
            {"ifname":"rwg-aaaaaaaa","addr_info":[{"local":"10.88.0.2","prefixlen":24}]}]"#;
        let routes = r#"[{"dst":"default","gateway":"10.210.1.1","dev":"eth0"},
            {"dst":"10.210.1.0/24","dev":"eth0"},{"dst":"172.20.5.9","dev":"eth0"},
            {"dst":"10.88.0.0/24","dev":"rwg-aaaaaaaa"},{"type":"blackhole","dst":"192.168.50.0/24"}]"#;
        let taken = taken(addresses, routes).unwrap();
        let protected = vec![(
            "100.64.3.3".parse().unwrap(),
            "the controller address 100.64.3.3".to_string(),
        )];
        guard(&interface("10.88.0.2", 24), &taken, &protected).unwrap();
        guard(&interface("10.89.0.1", 16), &taken, &protected).unwrap();
        for (bad, why) in [
            (interface("10.210.0.1", 16), "address 10.210.1.2/24 on eth0"),
            (
                interface("10.210.1.200", 29),
                "address 10.210.1.2/24 on eth0",
            ),
            (interface("172.20.5.1", 24), "route 172.20.5.9 via eth0"),
            (interface("192.168.50.1", 24), "route 192.168.50.0/24 via -"),
            (interface("100.64.3.1", 24), "the controller address"),
        ] {
            let error = guard(&bad, &taken, &protected).unwrap_err().to_string();
            assert!(error.contains(why), "{error}");
        }
    }

    #[test]
    fn dump_drops_the_private_key_line() {
        let dump = "cHJpdmF0ZQ==\tcHVibGlj\t51820\toff\n\
            UEVFUjE=\t(none)\t203.0.113.1:51820\t10.88.0.1/32\t1793530000\t1200\t3400\t25\n\
            UEVFUjI=\t(none)\t(none)\t10.88.0.3/32\t0\t0\t0\toff\n";
        let peers = parse_dump(dump);
        assert_eq!(peers.len(), 2);
        assert_eq!(
            (
                peers[0].public_key.as_str(),
                peers[0].endpoint.as_deref(),
                peers[0].handshake,
                peers[0].rx_bytes,
                peers[0].tx_bytes
            ),
            (
                "UEVFUjE=",
                Some("203.0.113.1:51820"),
                1_793_530_000,
                1200,
                3400
            )
        );
        assert_eq!(peers[1].endpoint, None);
        assert!(!peers.iter().any(|p| p.public_key.contains("cHJpdmF0ZQ")));
    }
}
