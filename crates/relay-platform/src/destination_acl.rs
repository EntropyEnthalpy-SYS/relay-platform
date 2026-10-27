//! Destination allow/deny policy for fixed targets and proxy destinations.
//! Deny wins; an empty allow list allows everything not denied. Patterns are
//! IP, CIDR, exact domain, `*.example.com`/`.example.com` suffix, or `*`.
use anyhow::{Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DestinationPolicy {
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    Any,
    Domain(String),
    Suffix(String),
    Ip(IpAddr),
    Cidr(IpNet),
}
impl DestinationPolicy {
    pub fn parse(allow: &[String], deny: &[String]) -> Result<Self> {
        Ok(Self {
            allow: parse_list(allow)?,
            deny: parse_list(deny)?,
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
        self.permits(&address.ip().to_string(), [address.ip()])
    }
}
impl Pattern {
    fn matches_host(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Domain(domain) => host == domain,
            Self::Suffix(suffix) => host.len() > suffix.len() && host.ends_with(suffix),
            Self::Ip(_) | Self::Cidr(_) => {
                host.parse::<IpAddr>().is_ok_and(|ip| self.matches_ip(ip))
            }
        }
    }
    fn matches_ip(&self, ip: IpAddr) -> bool {
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
fn parse(value: &str) -> Result<Pattern> {
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
fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
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
        assert!(policy.permits("other.test", ["10.2.3.4".parse().unwrap()]));
        assert!(!policy.permits("other.test", ["10.9.1.1".parse().unwrap()]));
        assert!(!policy.permits("other.test", ["203.0.113.8".parse().unwrap()]));
        assert!(policy.permits("other.test", ["203.0.113.7".parse().unwrap()]));
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
    fn invalid_patterns_are_rejected() {
        assert!(DestinationPolicy::parse(&["http://example.com".into()], &[]).is_err());
        assert!(DestinationPolicy::parse(&["example.com:443".into()], &[]).is_err());
        assert!(DestinationPolicy::parse(&["*.".into()], &[]).is_err());
    }
}
