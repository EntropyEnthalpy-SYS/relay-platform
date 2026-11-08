//! Destination allow/deny policy for fixed targets and proxy destinations.
//! Deny wins; an empty allow list allows everything not denied. Patterns are
//! IP, CIDR, exact domain, `*.example.com`/`.example.com` suffix, or `*`.
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DestinationPolicy {
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
    ports: PortPolicy,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PortPolicy {
    allow: Vec<PortPattern>,
    deny: Vec<PortPattern>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortPattern {
    Any,
    Single(u16),
    Range(u16, u16),
}
impl PortPolicy {
    fn parse(allow: &[String], deny: &[String]) -> Result<Self> {
        Ok(Self {
            allow: allow
                .iter()
                .map(|value| parse_port(value))
                .collect::<Result<_>>()?,
            deny: deny
                .iter()
                .map(|value| parse_port(value))
                .collect::<Result<_>>()?,
        })
    }
    fn permits(&self, port: u16) -> bool {
        !self.deny.iter().any(|pattern| pattern.matches(port))
            && (self.allow.is_empty() || self.allow.iter().any(|pattern| pattern.matches(port)))
    }
}
impl PortPattern {
    pub(crate) fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(value) => *value == port,
            Self::Range(start, end) => (*start..=*end).contains(&port),
        }
    }
}
pub(crate) fn parse_port(value: &str) -> Result<PortPattern> {
    let value = value.trim();
    if value.is_empty() {
        bail!("destination port must not be empty");
    }
    if value == "*" {
        return Ok(PortPattern::Any);
    }
    if let Some((start, end)) = value.split_once('-') {
        let start: u16 = start
            .parse()
            .context("invalid destination port range start")?;
        let end: u16 = end.parse().context("invalid destination port range end")?;
        ensure!(start <= end, "destination port range is reversed");
        return Ok(PortPattern::Range(start, end));
    }
    Ok(PortPattern::Single(
        value.parse().context("invalid destination port")?,
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pattern {
    Any,
    Domain(String),
    Suffix(String),
    Ip(IpAddr),
    Cidr(IpNet),
}
impl DestinationPolicy {
    pub fn parse(allow: &[String], deny: &[String]) -> Result<Self> {
        Self::parse_with_ports(allow, deny, &[], &[])
    }
    pub fn parse_with_ports(
        allow: &[String],
        deny: &[String],
        allow_ports: &[String],
        deny_ports: &[String],
    ) -> Result<Self> {
        ensure!(
            allow_ports.len() <= 256 && deny_ports.len() <= 256,
            "too many destination port patterns"
        );
        Ok(Self {
            allow: parse_list(allow)?,
            deny: parse_list(deny)?,
            ports: PortPolicy::parse(allow_ports, deny_ports)?,
        })
    }
    /// Returns only the resolved addresses that the policy authorizes.
    /// A domain/allow entry authorizes the hostname (and therefore its
    /// undeined addresses), while an IP/CIDR allow entry authorizes only
    /// matching addresses. Deny entries remove matching addresses; a denied
    /// hostname removes every address.
    pub fn filter(&self, host: &str, ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
        let host = normalize_host(host);
        if self.deny.iter().any(|pattern| pattern.matches_host(&host)) {
            return Vec::new();
        }
        let host_allowed =
            self.allow.is_empty() || self.allow.iter().any(|pattern| pattern.matches_host(&host));
        ips.into_iter()
            .filter(|ip| {
                !self.deny.iter().any(|pattern| pattern.matches_ip(*ip))
                    && (host_allowed || self.allow.iter().any(|pattern| pattern.matches_ip(*ip)))
            })
            .collect()
    }
    /// Compatibility predicate used by fixed-IP checks. It is true when the
    /// host is authorized or at least one supplied address survives filtering.
    pub fn permits(&self, host: &str, ips: impl IntoIterator<Item = IpAddr>) -> bool {
        let host_value = normalize_host(host);
        if self
            .deny
            .iter()
            .any(|pattern| pattern.matches_host(&host_value))
        {
            return false;
        }
        if self.allow.is_empty()
            || self
                .allow
                .iter()
                .any(|pattern| pattern.matches_host(&host_value))
        {
            return true;
        }
        self.filter(&host_value, ips).into_iter().next().is_some()
    }
    pub fn permits_address(&self, address: std::net::SocketAddr) -> bool {
        self.permits_socket(address)
    }
    pub fn filter_sockets(
        &self,
        host: &str,
        addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    ) -> Vec<std::net::SocketAddr> {
        let addresses: Vec<_> = addresses.into_iter().collect();
        let allowed = self.filter(host, addresses.iter().map(|address| address.ip()));
        addresses
            .into_iter()
            .filter(|address| allowed.contains(&address.ip()) && self.ports.permits(address.port()))
            .collect()
    }
    pub fn permits_socket(&self, address: std::net::SocketAddr) -> bool {
        self.permits(&address.ip().to_string(), [address.ip()])
            && self.ports.permits(address.port())
    }
    /// Whether `host:port` is permitted by its name alone, for a name sent
    /// on unresolved: `Some(false)` when a name or port entry denies it,
    /// `Some(true)` when a name entry or an empty allow list permits it and
    /// no address entry could deny one of its addresses, and `None` when
    /// only its addresses can tell, as for a name that is not a valid
    /// hostname ([`valid_hostname`]).
    pub fn decide_name(&self, host: &str, port: u16) -> Option<bool> {
        let host = normalize_host(host);
        if !self.ports.permits(port) || self.deny.iter().any(|p| p.matches_host(&host)) {
            return Some(false);
        }
        if !valid_hostname(&host)
            || self
                .deny
                .iter()
                .any(|p| matches!(p, Pattern::Ip(_) | Pattern::Cidr(_)))
        {
            return None;
        }
        (self.allow.is_empty() || self.allow.iter().any(|p| p.matches_host(&host))).then_some(true)
    }
}
impl Pattern {
    pub(crate) fn matches_host(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Domain(domain) => host == domain,
            // A subdomain: `api.example.com`, not `badexample.com`.
            Self::Suffix(suffix) => host
                .strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
            Self::Ip(_) | Self::Cidr(_) => {
                host.parse::<IpAddr>().is_ok_and(|ip| self.matches_ip(ip))
            }
        }
    }
    pub(crate) fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ip(expected) => *expected == ip,
            Self::Cidr(net) => net.contains(&ip),
            Self::Domain(_) | Self::Suffix(_) => false,
        }
    }
}
fn parse_list(values: &[String]) -> Result<Vec<Pattern>> {
    values.iter().map(|value| parse(value)).collect()
}
pub(crate) fn parse(value: &str) -> Result<Pattern> {
    let value = value.trim();
    if value.is_empty() {
        bail!("destination pattern must not be empty");
    }
    if value == "*" {
        return Ok(Pattern::Any);
    }
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(Pattern::Cidr(net));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(Pattern::Ip(ip));
    }
    if value.starts_with("*.") || value.starts_with('.') {
        let suffix = value
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() || suffix.contains(['*', '/', ':', ' ']) || !suffix.contains('.') {
            bail!("invalid destination domain suffix: {value}");
        }
        return Ok(Pattern::Suffix(suffix));
    }
    if value.contains(['*', '/', ':', ' '])
        || value.starts_with('.')
        || value.ends_with('.')
        || value.len() > 253
    {
        bail!("invalid destination domain: {value}");
    }
    let domain = value.to_ascii_lowercase();
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        bail!("invalid destination domain: {value}");
    }
    Ok(Pattern::Domain(domain))
}
pub(crate) fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}
/// Whether `host`, as [`normalize_host`] leaves it, is a hostname: labels
/// of 1 to 63 ASCII letters, digits, hyphens or underscores, at most 253
/// characters. Only such a name is judged by name alone and sent on
/// unresolved; another (with a NUL byte or raw UTF-8, say) could reach a
/// resolver as a different name than the one the rules matched.
pub(crate) fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
pub fn host_from_endpoint(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(endpoint);
    }
    endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_wins_and_allow_is_a_whitelist() {
        let policy = DestinationPolicy::parse(
            &[
                "*.example.com".into(),
                "10.0.0.0/8".into(),
                "203.0.113.7".into(),
            ],
            &["secret.example.com".into(), "10.9.0.0/16".into()],
        )
        .unwrap();
        assert!(policy.permits("api.example.com", []));
        assert!(!policy.permits("secret.example.com", []));
        // A suffix matches subdomains only, not the bare domain or a lookalike.
        assert!(!policy.permits("example.com", []));
        assert!(!policy.permits("badexample.com", []));
        assert!(policy.permits("other.test", ["10.2.3.4".parse().unwrap()]));
        assert!(!policy.permits("other.test", ["10.9.1.1".parse().unwrap()]));
        assert!(!policy.permits("other.test", ["203.0.113.8".parse().unwrap()]));
        assert!(policy.permits("other.test", ["203.0.113.7".parse().unwrap()]));
    }

    #[test]
    fn names_are_decided_without_addresses_only_when_no_address_entry_could_matter() {
        let names = DestinationPolicy::parse_with_ports(
            &["*.example.com".into()],
            &["secret.example.com".into()],
            &[],
            &["25".into()],
        )
        .unwrap();
        assert_eq!(names.decide_name("API.Example.com.", 443), Some(true));
        assert_eq!(names.decide_name("secret.example.com", 443), Some(false));
        assert_eq!(names.decide_name("api.example.com", 25), Some(false));
        // Outside the name entries only an address entry could allow it.
        assert_eq!(names.decide_name("other.test", 443), None);
        assert_eq!(
            DestinationPolicy::default().decide_name("other.test", 443),
            Some(true)
        );
        // A name that is not a hostname is never let through by name: the
        // deny entry did not match it, yet a resolver may read it as
        // db.internal.corp.
        let suffix = DestinationPolicy::parse(&[], &["*.internal.corp".into()]).unwrap();
        assert_eq!(suffix.decide_name("db.internal.corp", 443), Some(false));
        assert_eq!(suffix.decide_name("db.internal.corp\0", 443), None);
        assert_eq!(suffix.decide_name("db.internal.corp\0.example", 443), None);
        assert_eq!(suffix.decide_name("db internal.corp", 443), None);
        assert_eq!(suffix.decide_name("other.test", 443), Some(true));
        assert!(!valid_hostname("db.internal.corp\0"));
        assert!(!valid_hostname("a..b") && !valid_hostname(""));
        assert!(!valid_hostname(&format!("{}.test", "a".repeat(64))));
        assert!(valid_hostname("db-1.internal.corp") && valid_hostname("192.0.2.1"));
        // Underscores are common in internal names and mean nothing else to a
        // resolver; raw UTF-8 may be mapped to another name by the upstream.
        assert_eq!(suffix.decide_name("my_host.corp.local", 443), Some(true));
        assert_eq!(suffix.decide_name("db.internal\u{ff0e}corp", 443), None);
        // An address entry in the deny list may match any name's address.
        let addresses = DestinationPolicy::parse(&[], &["10.0.0.0/8".into()]).unwrap();
        assert_eq!(addresses.decide_name("api.example.com", 443), None);
        assert_eq!(
            DestinationPolicy::parse(&["10.0.0.0/8".into()], &[])
                .unwrap()
                .decide_name("api.example.com", 443),
            None
        );
    }

    #[test]
    fn ip_allowlist_filters_mixed_answers() {
        let policy = DestinationPolicy::parse(&["127.0.0.1/32".into()], &[]).unwrap();
        let filtered = policy.filter(
            "localhost",
            ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        );
        assert_eq!(filtered, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert!(
            DestinationPolicy::parse(&["*.example.com".into()], &[])
                .unwrap()
                .filter(
                    "api.example.com",
                    [
                        "203.0.113.8".parse().unwrap(),
                        "203.0.113.9".parse().unwrap()
                    ]
                )
                .len()
                == 2
        );
        assert!(
            DestinationPolicy::parse(&[], &["203.0.113.9".into()])
                .unwrap()
                .filter(
                    "api.example.com",
                    [
                        "203.0.113.8".parse().unwrap(),
                        "203.0.113.9".parse().unwrap()
                    ]
                )
                .len()
                == 1
        );
    }

    #[test]
    fn destination_ports_are_filtered_with_ranges() {
        let policy = DestinationPolicy::parse_with_ports(
            &[],
            &[],
            &["443".into(), "8000-8080".into()],
            &["8443".into(), "9000-9001".into()],
        )
        .unwrap();
        assert!(policy.permits_socket("203.0.113.7:443".parse().unwrap()));
        assert!(policy.permits_socket("203.0.113.7:8080".parse().unwrap()));
        assert!(!policy.permits_socket("203.0.113.7:80".parse().unwrap()));
        assert!(!policy.permits_socket("203.0.113.7:8443".parse().unwrap()));
        assert!(!policy.permits_socket("203.0.113.7:9001".parse().unwrap()));
        assert!(DestinationPolicy::parse_with_ports(&[], &[], &["8000-1".into()], &[]).is_err());
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(DestinationPolicy::parse(&["http://example.com".into()], &[]).is_err());
        assert!(DestinationPolicy::parse(&["example.com:443".into()], &[]).is_err());
        assert!(DestinationPolicy::parse(&["*.".into()], &[]).is_err());
    }
}
