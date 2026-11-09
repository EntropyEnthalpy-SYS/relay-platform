//! Firewall rule sets: named, ordered allow/deny rules with a default
//! action, bound to a server's inbound or outbound side or to one rule's
//! inbound side. The first rule in list order that matches decides; when
//! none does, the set's default action does. Every bound layer must allow a
//! connection, so a later layer can only tighten what an earlier one let
//! through.
//!
//! The controller and the agents evaluate with the same code: the agent
//! enforces [`Layers`] built from the [`Desired`] policy it was sent, and
//! the panel's tester builds the same [`Layers`] from the same policy.
use crate::destination_acl::{self, Pattern, PortPattern};
use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Rules in one set.
pub const MAX_RULES: usize = 256;
/// Sources, destinations or ports in one rule.
pub const MAX_ENTRIES: usize = 256;
/// Characters in a set's name.
pub const MAX_NAME_CHARS: usize = 120;
/// The serialized policy of one server, and of one set. Agents take at most
/// 4 MiB per sync reply, which also carries the configuration.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
/// Sets one tenant keeps; system sets count as one more tenant.
pub const MAX_SETS: usize = 64;
/// Characters of an error the agent reports. At most 4 bytes each, so a
/// report always fits the controller's [`MAX_ERROR_BYTES`].
pub const MAX_ERROR_CHARS: usize = 512;
/// Bytes of an error the controller takes in a report.
pub const MAX_ERROR_BYTES: usize = 2048;

/// `message` cut to what a [`Report`] carries.
pub fn report_error(message: &str) -> String {
    message.chars().take(MAX_ERROR_CHARS).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Matches the client's source address.
    Inbound,
    /// Matches the destination the server connects to.
    Outbound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
    fn verb(self) -> &'static str {
        match self {
            Self::Allow => "allows",
            Self::Deny => "denies",
        }
    }
}

/// What a rule matches. Inbound rules match `sources`; outbound rules
/// match `destinations` and/or `ports`, every list that is set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// Source IPv4/IPv6 networks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<IpNet>,
    /// Destination IP, CIDR, exact domain or `*.suffix` domain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
    /// Destination ports (`443`) or ranges (`8000-8080`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRule {
    pub action: Action,
    #[serde(rename = "match")]
    pub matches: Match,
}

/// A rule set as agents receive it and the tester evaluates it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub id: String,
    pub name: String,
    pub direction: Direction,
    pub default_action: Action,
    pub rules: Vec<SetRule>,
}

pub fn validate_name(name: &str) -> Result<()> {
    let count = name.chars().count();
    ensure!(
        (1..=MAX_NAME_CHARS).contains(&count)
            && name.trim() == name
            && !name.chars().any(char::is_control),
        "a rule set name has 1 to {MAX_NAME_CHARS} characters without surrounding spaces or control characters"
    );
    Ok(())
}

/// Checks `rules` for a set of `direction`: their count, and that each
/// matches only what its direction can see.
pub fn validate_rules(direction: Direction, rules: &[SetRule]) -> Result<()> {
    ensure!(
        rules.len() <= MAX_RULES,
        "a rule set has at most {MAX_RULES} rules"
    );
    for (index, rule) in rules.iter().enumerate() {
        let number = index + 1;
        let m = &rule.matches;
        match direction {
            Direction::Inbound => {
                ensure!(
                    m.destinations.is_empty() && m.ports.is_empty(),
                    "rule {number}: an inbound set matches source addresses only, not destinations or ports"
                );
                ensure!(
                    (1..=MAX_ENTRIES).contains(&m.sources.len()),
                    "rule {number}: an inbound rule has 1 to {MAX_ENTRIES} source networks"
                );
            }
            Direction::Outbound => {
                ensure!(
                    m.sources.is_empty(),
                    "rule {number}: an outbound set matches destinations and ports only, not source addresses"
                );
                ensure!(
                    !(m.destinations.is_empty() && m.ports.is_empty()),
                    "rule {number}: an outbound rule needs destinations, ports or both"
                );
                ensure!(
                    m.destinations.len() <= MAX_ENTRIES && m.ports.len() <= MAX_ENTRIES,
                    "rule {number}: an outbound rule has at most {MAX_ENTRIES} destinations and {MAX_ENTRIES} ports"
                );
                for destination in &m.destinations {
                    match destination_acl::parse(destination) {
                        Ok(Pattern::Any) | Err(_) => bail!(
                            "rule {number}: invalid destination {destination:?}; use an IP, a CIDR, a domain or *.domain"
                        ),
                        Ok(_) => {}
                    }
                }
                for port in &m.ports {
                    match destination_acl::parse_port(port) {
                        Ok(PortPattern::Any) | Err(_) => bail!(
                            "rule {number}: invalid port {port:?}; use a port such as 443 or a range such as 8000-8080"
                        ),
                        Ok(_) => {}
                    }
                }
            }
        }
    }
    Ok(())
}

impl Spec {
    pub fn validate(&self) -> Result<()> {
        ensure!(crate::model::identifier(&self.id), "invalid rule set id");
        validate_name(&self.name)?;
        validate_rules(self.direction, &self.rules)
    }
}

/// What decided for one set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The rule at this index (0-based) matched first.
    Rule(usize, Action),
    /// No rule matched.
    Default(Action),
    /// A destination name whose addresses decide: some rule up to the
    /// deciding one matches addresses. Resolve and ask per address.
    NeedsAddress,
}
impl Verdict {
    pub fn action(self) -> Option<Action> {
        match self {
            Self::Rule(_, action) | Self::Default(action) => Some(action),
            Self::NeedsAddress => None,
        }
    }
}

struct CompiledRule {
    action: Action,
    sources: Vec<IpNet>,
    destinations: Vec<Pattern>,
    ports: Vec<PortPattern>,
}
/// A set ready to evaluate.
pub struct Compiled {
    pub id: String,
    pub name: String,
    pub direction: Direction,
    default_action: Action,
    rules: Vec<CompiledRule>,
}

/// `ip` and, for an IPv4 address, its IPv4-mapped IPv6 form, so that
/// `::ffff:192.0.2.1` and `192.0.2.1` match the same networks.
fn forms(ip: IpAddr) -> [IpAddr; 2] {
    let ip = crate::model::canonical_ip(ip);
    match ip {
        IpAddr::V4(v4) => [ip, IpAddr::V6(v4.to_ipv6_mapped())],
        IpAddr::V6(_) => [ip, ip],
    }
}

impl Compiled {
    pub fn new(spec: &Spec) -> Result<Self> {
        spec.validate()?;
        Ok(Self {
            id: spec.id.clone(),
            name: spec.name.clone(),
            direction: spec.direction,
            default_action: spec.default_action,
            rules: spec
                .rules
                .iter()
                .map(|rule| {
                    Ok(CompiledRule {
                        action: rule.action,
                        sources: rule.matches.sources.clone(),
                        destinations: rule
                            .matches
                            .destinations
                            .iter()
                            .map(|d| destination_acl::parse(d))
                            .collect::<Result<_>>()?,
                        ports: rule
                            .matches
                            .ports
                            .iter()
                            .map(|p| destination_acl::parse_port(p))
                            .collect::<Result<_>>()?,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
    fn first(&self, matches: impl Fn(&CompiledRule) -> bool) -> Verdict {
        self.rules
            .iter()
            .position(matches)
            .map_or(Verdict::Default(self.default_action), |index| {
                Verdict::Rule(index, self.rules[index].action)
            })
    }
    /// An inbound set's verdict for a client at `source`.
    pub fn source(&self, source: IpAddr) -> Verdict {
        let forms = forms(source);
        self.first(|rule| {
            rule.sources
                .iter()
                .any(|net| forms.iter().any(|ip| net.contains(ip)))
        })
    }
    /// An outbound set's verdict for one address of `host` (a name, or the
    /// address itself) on `port`. A name entry matches every address of the
    /// name; an address entry only the addresses inside it.
    pub fn destination(&self, host: &str, address: IpAddr, port: u16) -> Verdict {
        let host = destination_acl::normalize_host(host);
        let forms = forms(address);
        self.first(|rule| {
            (rule.ports.is_empty() || rule.ports.iter().any(|p| p.matches(port)))
                && (rule.destinations.is_empty()
                    || rule.destinations.iter().any(|pattern| {
                        pattern.matches_host(&host)
                            || forms.iter().any(|ip| pattern.matches_ip(*ip))
                    }))
        })
    }
    /// An outbound set's verdict for `host:port` by the name alone:
    /// [`Verdict::NeedsAddress`] when a rule that could match first has
    /// address entries that the name does not settle.
    pub fn destination_name(&self, host: &str, port: u16) -> Verdict {
        let host = destination_acl::normalize_host(host);
        for (index, rule) in self.rules.iter().enumerate() {
            if !(rule.ports.is_empty() || rule.ports.iter().any(|p| p.matches(port))) {
                continue;
            }
            if rule.destinations.is_empty()
                || rule.destinations.iter().any(|p| p.matches_host(&host))
            {
                return Verdict::Rule(index, rule.action);
            }
            if rule
                .destinations
                .iter()
                .any(|p| matches!(p, Pattern::Ip(_) | Pattern::Cidr(_)))
            {
                return Verdict::NeedsAddress;
            }
        }
        Verdict::Default(self.default_action)
    }
}

/// Where a set is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    ServerInbound,
    RuleInbound,
    ServerOutbound,
}
impl Layer {
    fn text(self) -> &'static str {
        match self {
            Self::ServerInbound => "server inbound",
            Self::RuleInbound => "rule inbound",
            Self::ServerOutbound => "server outbound",
        }
    }
}

/// One layer's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub layer: Layer,
    pub set_id: String,
    /// `None` when the set did not reach this server, or is bound with the
    /// wrong direction: such a layer refuses everything.
    pub set_name: Option<String>,
    pub verdict: Option<Verdict>,
}
/// Whether a layer's verdict refuses; `None` is a set that is not usable.
fn refuses(verdict: Option<Verdict>) -> bool {
    matches!(
        verdict,
        None | Some(Verdict::Rule(_, Action::Deny) | Verdict::Default(Action::Deny))
    )
}
impl Outcome {
    fn new(layer: Layer, set_id: &str, set: Option<&Compiled>, verdict: Option<Verdict>) -> Self {
        Self {
            layer,
            set_id: set_id.to_owned(),
            set_name: set.map(|set| set.name.clone()),
            verdict,
        }
    }
    pub fn denies(&self) -> bool {
        refuses(self.verdict)
    }
    /// For a block record: the layer, the rule (1-based, as the panel
    /// numbers them) or the default action, then the set's name. Names no
    /// address and nothing secret.
    pub fn detail(&self) -> String {
        let layer = self.layer.text();
        match (&self.set_name, self.verdict) {
            (Some(name), Some(Verdict::Rule(index, action))) => format!(
                "{layer} rule set: rule {} {} ({name})",
                index + 1,
                action.verb()
            ),
            (Some(name), Some(Verdict::Default(action))) => {
                format!(
                    "{layer} rule set: default action {} ({name})",
                    action.verb()
                )
            }
            (Some(name), Some(Verdict::NeedsAddress)) => {
                format!("{layer} rule set: needs the address ({name})")
            }
            (_, _) => format!(
                "{layer} rule set {} is not available here: refused",
                self.set_id
            ),
        }
    }
}

enum Bound {
    Set(Arc<Compiled>),
    /// Bound but not usable here: refuses everything.
    Missing(String),
}
impl Bound {
    fn set(&self) -> Option<&Compiled> {
        match self {
            Self::Set(set) => Some(&**set),
            Self::Missing(_) => None,
        }
    }
    /// The answer with the set's id and name, built only when it is shown
    /// or recorded.
    fn outcome(&self, layer: Layer, verdict: Option<Verdict>) -> Outcome {
        match self {
            Self::Set(set) => Outcome::new(layer, &set.id, Some(&**set), verdict),
            Self::Missing(id) => Outcome::new(layer, id, None, None),
        }
    }
}

/// One server's firewall: its server bindings and every set that its rules
/// are bound to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_outbound: Option<String>,
    /// By id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sets: Vec<Spec>,
}
impl Policy {
    /// SHA-256 of the canonical form: sets ordered by id.
    pub fn hash(&self) -> String {
        let mut canonical = self.clone();
        canonical.sets.sort_by(|a, b| a.id.cmp(&b.id));
        let bytes = serde_json::to_vec(&canonical).expect("a policy serializes");
        format!("{:x}", Sha256::digest(bytes))
    }
}

/// What the controller sends with every sync. `policy` is left out when
/// the agent reported that it applied `hash` already.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Desired {
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

/// [`Report::covers`]: protocol gateways judge each client's own address
/// by the server's and the rule's inbound sets before the protocol engine
/// sees anything of it.
pub const COVERS_GATEWAY_INBOUND: &str = "gateway_inbound";
/// [`Report::covers`]: the private end of a reverse tunnel checks the
/// server's outbound set before it connects to the tunnel's target.
pub const COVERS_REVERSE_PRIVATE_OUTBOUND: &str = "reverse_private_outbound";
/// [`NodeStatus::uncovered`]: the server's protocol gateways take clients
/// that its inbound sets do not judge.
pub const UNCOVERED_GATEWAYS: &str = "gateways";
/// [`NodeStatus::uncovered`]: the server dials reverse tunnel targets that
/// its outbound set does not judge.
pub const UNCOVERED_REVERSE_TUNNELS: &str = "reverse_tunnels";
/// What this agent's [`Report::covers`] names.
pub const COVERS: [&str; 2] = [COVERS_GATEWAY_INBOUND, COVERS_REVERSE_PRIVATE_OUTBOUND];

/// What the agent reports to a controller that sent [`Desired`]. Its
/// presence tells the controller the agent enforces rule sets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// The policy in force, as the controller hashed it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_hash: Option<String>,
    /// Why the last policy sent was not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Paths beyond the agent's own rules that it holds to rule sets
    /// ([`COVERS`]); agents of 0.150.0 send none. Unknown names are kept
    /// and ignored.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub covers: Vec<String>,
}
impl Report {
    pub fn within_limits(&self) -> bool {
        self.applied_hash.as_ref().is_none_or(|h| h.len() <= 64)
            && self
                .error
                .as_ref()
                .is_none_or(|e| e.len() <= MAX_ERROR_BYTES)
            && self.covers.len() <= 16
            && self.covers.iter().all(|c| c.len() <= 64)
    }
    /// Whether the agent reported that it covers `path`.
    pub fn covers(&self, path: &str) -> bool {
        self.covers.iter().any(|c| c == path)
    }
}

/// A policy ready to evaluate. A set that is bound but missing, or bound
/// with the wrong direction, refuses everything at its layer.
#[derive(Default)]
pub struct Layers {
    server_inbound: Option<Bound>,
    server_outbound: Option<Bound>,
    sets: HashMap<String, Arc<Compiled>>,
    /// Why sets were left out, for the agent's report.
    refused: Vec<String>,
}
impl Layers {
    /// Sets that do not compile are left out, so whatever binds them
    /// refuses; [`Self::error`] says which and why.
    pub fn new(policy: &Policy) -> Self {
        let mut sets = HashMap::new();
        let mut refused = vec![];
        for spec in &policy.sets {
            match Compiled::new(spec) {
                Ok(set) => {
                    sets.insert(spec.id.clone(), Arc::new(set));
                }
                Err(error) => {
                    tracing::warn!(set = %spec.id, %error, "firewall rule set refused");
                    refused.push(format!(
                        "rule set {:?} ({}) cannot be used here and refuses everything: {error}",
                        spec.name, spec.id
                    ));
                }
            }
        }
        let bound = |id: &Option<String>, direction| {
            id.as_ref().map(|id| match sets.get(id) {
                Some(set) if set.direction == direction => Bound::Set(set.clone()),
                _ => Bound::Missing(id.clone()),
            })
        };
        Self {
            server_inbound: bound(&policy.server_inbound, Direction::Inbound),
            server_outbound: bound(&policy.server_outbound, Direction::Outbound),
            sets,
            refused,
        }
    }
    /// Why sets of this policy refuse everything, for the agent's report.
    pub fn error(&self) -> Option<String> {
        (!self.refused.is_empty()).then(|| report_error(&self.refused.join("; ")))
    }
    /// The inbound set with this id; `None` when it is missing here or is
    /// an outbound set, which refuses everything.
    fn inbound_set(&self, id: &str) -> Option<&Compiled> {
        self.sets
            .get(id)
            .map(|set| &**set)
            .filter(|set| set.direction == Direction::Inbound)
    }
    /// The inbound layers' answers for a client at `source`, in order: the
    /// server's set, then the rule's (`rule_set`), for the tester.
    pub fn inbound<'a>(
        &'a self,
        rule_set: Option<&'a str>,
        source: IpAddr,
    ) -> impl Iterator<Item = Outcome> + 'a {
        let server = self.server_inbound.iter().map(move |bound| {
            bound.outcome(
                Layer::ServerInbound,
                bound.set().map(|set| set.source(source)),
            )
        });
        let rule = rule_set.into_iter().map(move |id| {
            let set = self.inbound_set(id);
            Outcome::new(
                Layer::RuleInbound,
                id,
                set,
                set.map(|set| set.source(source)),
            )
        });
        server.chain(rule)
    }
    /// The first inbound layer that refuses `source`, as [`Self::inbound`]
    /// would answer, stopping there. Only a refusal builds an [`Outcome`].
    pub fn inbound_refusal(&self, rule_set: Option<&str>, source: IpAddr) -> Option<Outcome> {
        if let Some(bound) = &self.server_inbound {
            let verdict = bound.set().map(|set| set.source(source));
            if refuses(verdict) {
                return Some(bound.outcome(Layer::ServerInbound, verdict));
            }
        }
        let id = rule_set?;
        let set = self.inbound_set(id);
        let verdict = set.map(|set| set.source(source));
        refuses(verdict).then(|| Outcome::new(Layer::RuleInbound, id, set, verdict))
    }
    /// The server's outbound set's answer for one address of `host` on
    /// `port`, or, without an address, for the name alone.
    pub fn outbound(&self, host: &str, address: Option<IpAddr>, port: u16) -> Option<Outcome> {
        self.server_outbound.as_ref().map(|bound| {
            let verdict = bound.set().map(|set| match address {
                Some(address) => set.destination(host, address, port),
                None => set.destination_name(host, port),
            });
            bound.outcome(Layer::ServerOutbound, verdict)
        })
    }
    /// [`Self::outbound`] for `host:port` by the name alone, for the agent:
    /// the refusal, or whether only the name's addresses can tell.
    pub fn outbound_name(&self, host: &str, port: u16) -> Result<bool, Outcome> {
        let Some(bound) = &self.server_outbound else {
            return Ok(false);
        };
        let verdict = bound.set().map(|set| set.destination_name(host, port));
        if refuses(verdict) {
            return Err(bound.outcome(Layer::ServerOutbound, verdict));
        }
        Ok(verdict == Some(Verdict::NeedsAddress))
    }
    /// Splits the addresses of `host` into those the server's outbound set
    /// lets the server connect to and the first refusal.
    pub fn filter_outbound(
        &self,
        host: &str,
        addresses: Vec<SocketAddr>,
    ) -> (Vec<SocketAddr>, Option<Outcome>) {
        let Some(bound) = &self.server_outbound else {
            return (addresses, None);
        };
        let mut refused = None;
        let allowed = addresses
            .into_iter()
            .filter(|address| {
                let verdict = bound
                    .set()
                    .map(|set| set.destination(host, address.ip(), address.port()));
                if !refuses(verdict) {
                    return true;
                }
                if refused.is_none() {
                    refused = Some(bound.outcome(Layer::ServerOutbound, verdict));
                }
                false
            })
            .collect();
        (allowed, refused)
    }
}

/// The policy an agent enforces, replaced as the controller sends new ones.
#[derive(Default)]
pub struct Runtime {
    current: RwLock<Arc<Layers>>,
    /// Whether the policy in force binds the server's inbound or outbound
    /// set, read without the lock: a rule with no set of its own on a
    /// server without them takes no lock per connection or datagram.
    server_inbound: AtomicBool,
    server_outbound: AtomicBool,
    /// The policy as received, and the rule set ids the running
    /// configuration's rules use.
    state: Mutex<RuntimeState>,
}
#[derive(Default)]
struct RuntimeState {
    policy: Option<Desired>,
    referenced: HashSet<String>,
    /// Sets the running rules still use that the newest policy dropped:
    /// kept until a configuration without them runs, so a rule never loses
    /// its set while its new revision is on the way.
    kept: BTreeMap<String, Spec>,
}
impl Runtime {
    pub fn load(&self) -> Arc<Layers> {
        self.current.read().unwrap().clone()
    }
    /// Whether the policy in force binds the server's inbound set.
    pub fn server_inbound(&self) -> bool {
        self.server_inbound.load(Ordering::Acquire)
    }
    /// Whether the policy in force binds the server's outbound set.
    pub fn server_outbound(&self) -> bool {
        self.server_outbound.load(Ordering::Acquire)
    }
    /// Why sets of the policy in force refuse everything.
    pub fn error(&self) -> Option<String> {
        self.load().error()
    }
    /// The hash of the policy in force.
    pub fn applied_hash(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .map(|d| d.hash.clone())
    }
    /// Enforces `desired` (a policy, not only its hash) from now on; `None`
    /// clears the policy, for a controller older than rule sets.
    pub fn apply(&self, desired: Option<Desired>) {
        let mut state = self.state.lock().unwrap();
        let mut kept = std::mem::take(&mut state.kept);
        if let Some(old) = state.policy.as_ref().and_then(|d| d.policy.as_ref()) {
            for set in &old.sets {
                kept.insert(set.id.clone(), set.clone());
            }
        }
        let new = desired.as_ref().and_then(|d| d.policy.as_ref());
        let present: HashSet<&str> = new
            .map(|p| p.sets.iter().map(|s| s.id.as_str()).collect())
            .unwrap_or_default();
        kept.retain(|id, _| state.referenced.contains(id) && !present.contains(id.as_str()));
        state.kept = kept;
        state.policy = desired;
        self.publish(&state);
    }
    /// The running configuration's rules use these sets now.
    pub fn retain(&self, referenced: HashSet<String>) {
        let mut state = self.state.lock().unwrap();
        state.kept.retain(|id, _| referenced.contains(id));
        state.referenced = referenced;
        self.publish(&state);
    }
    fn publish(&self, state: &RuntimeState) {
        let mut policy = state
            .policy
            .as_ref()
            .and_then(|d| d.policy.clone())
            .unwrap_or_default();
        policy.sets.extend(state.kept.values().cloned());
        let layers = Layers::new(&policy);
        let (inbound, outbound) = (
            layers.server_inbound.is_some(),
            layers.server_outbound.is_some(),
        );
        *self.current.write().unwrap() = Arc::new(layers);
        self.server_inbound.store(inbound, Ordering::Release);
        self.server_outbound.store(outbound, Ordering::Release);
    }
}

/// Who may use a set. System sets are kept by system administrators and
/// are the only ones a server binds; a tenant's sets bind to that tenant's
/// rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    System,
    Tenant,
}

/// A set as the controller keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub id: String,
    pub scope: Scope,
    /// The owning tenant; `None` for a system set.
    pub tenant_id: Option<String>,
    pub name: String,
    pub direction: Direction,
    pub default_action: Action,
    pub rules: Vec<SetRule>,
    pub revision: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
impl Stored {
    pub fn spec(&self) -> Spec {
        Spec {
            id: self.id.clone(),
            name: self.name.clone(),
            direction: self.direction,
            default_action: self.default_action,
            rules: self.rules.clone(),
        }
    }
}

/// A set to create, or a set's new contents. The direction cannot change;
/// the scope and tenant are chosen once, at creation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetInput {
    pub name: String,
    pub direction: Direction,
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<SetRule>,
    /// Creation only; `tenant` by default.
    #[serde(default)]
    pub scope: Option<Scope>,
    /// Creation of a tenant set by a system administrator; the actor's
    /// tenant by default.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Updates: refused with 409 when the set changed since.
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// Where a set is in use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRef {
    pub layer: Layer,
    pub node_id: String,
    pub node_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SetView {
    #[serde(flatten)]
    pub set: Stored,
    pub bindings: Vec<BindingRef>,
}

/// A server's inbound and outbound sets; `null` unbinds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerBinding {
    #[serde(default)]
    pub inbound_set_id: Option<String>,
    #[serde(default)]
    pub outbound_set_id: Option<String>,
}

/// Whether a server's agent enforces the policy the panel wants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    /// The agent confirmed the desired policy.
    Applied,
    /// Online and able, but it has not confirmed the newest policy yet.
    Waiting,
    /// Not heard from recently; it confirms when it is back.
    Offline,
    /// The agent never reported support for rule sets.
    TooOld,
    /// The agent never connected.
    NotConnected,
    /// No set is bound here and the agent does not enforce sets: nothing
    /// to confirm.
    #[default]
    Unused,
}

/// A server's bindings, the policy hash the panel wants and the one its
/// agent confirmed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Paths of this server that its bindings do not hold, because its
    /// agent does not cover them ([`UNCOVERED_GATEWAYS`],
    /// [`UNCOVERED_REVERSE_TUNNELS`]): bound before the controller knew.
    pub uncovered: Vec<String>,
    pub inbound_set_id: Option<String>,
    pub inbound_set_name: Option<String>,
    pub outbound_set_id: Option<String>,
    pub outbound_set_name: Option<String>,
    /// Rules on this server bound to an inbound set.
    pub rule_bindings: usize,
    pub desired_hash: String,
    pub applied_hash: Option<String>,
    /// Why the agent did not apply the last policy, as it reported.
    pub error: Option<String>,
    pub state: PolicyState,
}

/// A question for the tester: a set (`set_id`) or a server's bindings
/// (`node_id`, and `rule_id` for a rule's own layers too), with a client
/// source for inbound or a destination for outbound.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestInput {
    #[serde(default)]
    pub set_id: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub source: Option<IpAddr>,
    /// A domain or an IP.
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// One address the destination name resolves to; without it a name is
    /// judged by the name alone where it can be.
    #[serde(default)]
    pub address: Option<IpAddr>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestAnswer {
    Allow,
    Deny,
    /// Only the destination's addresses can tell; give one.
    NeedsAddress,
    /// The set is bound but not usable: it refuses everything.
    Missing,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLayer {
    /// `server_inbound`, `rule_inbound`, `server_outbound`, `set` or
    /// `rule_lists` (the rule's own source or destination lists).
    pub layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_name: Option<String>,
    /// The rule that matched first, 0-based.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    /// No rule matched: the set's default action answered.
    pub default_action: bool,
    pub result: TestAnswer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
impl TestLayer {
    pub fn of(outcome: &Outcome) -> Self {
        let (rule_index, default_action, result) = match outcome.verdict {
            Some(Verdict::Rule(index, action)) => (Some(index), false, answer(action)),
            Some(Verdict::Default(action)) => (None, true, answer(action)),
            Some(Verdict::NeedsAddress) => (None, false, TestAnswer::NeedsAddress),
            None => (None, false, TestAnswer::Missing),
        };
        Self {
            layer: serde_json::to_value(outcome.layer)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            set_id: Some(outcome.set_id.clone()),
            set_name: outcome.set_name.clone(),
            rule_index,
            default_action,
            result,
            detail: None,
        }
    }
}
fn answer(action: Action) -> TestAnswer {
    match action {
        Action::Allow => TestAnswer::Allow,
        Action::Deny => TestAnswer::Deny,
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    pub direction: Direction,
    /// `deny` when any layer refuses, `needs_address` when one cannot tell
    /// by the name, else `allow`.
    pub decision: TestAnswer,
    pub layers: Vec<TestLayer>,
    /// The server's desired policy the answer is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}
impl TestResult {
    pub fn new(direction: Direction, layers: Vec<TestLayer>, policy_hash: Option<String>) -> Self {
        let decision = if layers
            .iter()
            .any(|l| matches!(l.result, TestAnswer::Deny | TestAnswer::Missing))
        {
            TestAnswer::Deny
        } else if layers.iter().any(|l| l.result == TestAnswer::NeedsAddress) {
            TestAnswer::NeedsAddress
        } else {
            TestAnswer::Allow
        };
        Self {
            direction,
            decision,
            layers,
            policy_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(default_action: Action, rules: &[(Action, &[&str])]) -> Compiled {
        Compiled::new(&Spec {
            id: "in".into(),
            name: "In".into(),
            direction: Direction::Inbound,
            default_action,
            rules: rules
                .iter()
                .map(|(action, sources)| SetRule {
                    action: *action,
                    matches: Match {
                        sources: sources.iter().map(|s| s.parse().unwrap()).collect(),
                        ..Default::default()
                    },
                })
                .collect(),
        })
        .unwrap()
    }
    fn outbound(default_action: Action, rules: &[(Action, &[&str], &[&str])]) -> Compiled {
        Compiled::new(&Spec {
            id: "out".into(),
            name: "Out".into(),
            direction: Direction::Outbound,
            default_action,
            rules: rules
                .iter()
                .map(|(action, destinations, ports)| SetRule {
                    action: *action,
                    matches: Match {
                        destinations: destinations.iter().map(|s| s.to_string()).collect(),
                        ports: ports.iter().map(|s| s.to_string()).collect(),
                        ..Default::default()
                    },
                })
                .collect(),
        })
        .unwrap()
    }
    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_first_matching_rule_wins_over_a_later_broader_one() {
        use Action::*;
        let set = inbound(
            Deny,
            &[(Allow, &["203.0.113.7/32"]), (Deny, &["203.0.113.0/24"])],
        );
        assert_eq!(set.source(ip("203.0.113.7")), Verdict::Rule(0, Allow));
        assert_eq!(set.source(ip("203.0.113.8")), Verdict::Rule(1, Deny));
        assert_eq!(set.source(ip("198.51.100.1")), Verdict::Default(Deny));
        // The same rules the other way round: the broader deny is first.
        let set = inbound(
            Allow,
            &[(Deny, &["203.0.113.0/24"]), (Allow, &["203.0.113.7/32"])],
        );
        assert_eq!(set.source(ip("203.0.113.7")), Verdict::Rule(0, Deny));
        assert_eq!(set.source(ip("198.51.100.1")), Verdict::Default(Allow));
    }

    #[test]
    fn an_empty_set_answers_with_its_default_action() {
        assert_eq!(
            inbound(Action::Deny, &[]).source(ip("192.0.2.1")),
            Verdict::Default(Action::Deny)
        );
        assert_eq!(
            inbound(Action::Allow, &[]).source(ip("2001:db8::1")),
            Verdict::Default(Action::Allow)
        );
        let out = outbound(Action::Deny, &[]);
        assert_eq!(
            out.destination("example.com", ip("192.0.2.1"), 443),
            Verdict::Default(Action::Deny)
        );
        assert_eq!(
            out.destination_name("example.com", 443),
            Verdict::Default(Action::Deny)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_sources_match_ipv4_networks_and_the_reverse() {
        let set = inbound(Action::Allow, &[(Action::Deny, &["192.0.2.0/24"])]);
        assert_eq!(
            set.source(ip("::ffff:192.0.2.9")),
            Verdict::Rule(0, Action::Deny)
        );
        assert_eq!(
            set.source(ip("::ffff:192.0.3.9")),
            Verdict::Default(Action::Allow)
        );
        let mapped = inbound(Action::Allow, &[(Action::Deny, &["::ffff:192.0.2.0/120"])]);
        assert_eq!(
            mapped.source(ip("192.0.2.9")),
            Verdict::Rule(0, Action::Deny)
        );
        assert_eq!(
            mapped.source(ip("192.0.3.9")),
            Verdict::Default(Action::Allow)
        );
        // A plain IPv6 address in an IPv4 network's place does not match.
        assert_eq!(
            set.source(ip("2001:db8::c000:209")),
            Verdict::Default(Action::Allow)
        );
    }

    #[test]
    fn port_ranges_match_at_both_edges_only() {
        use Action::*;
        let set = outbound(Allow, &[(Deny, &[], &["8000-8080"])]);
        let at = |port| set.destination("192.0.2.1", ip("192.0.2.1"), port);
        assert_eq!(at(7999), Verdict::Default(Allow));
        assert_eq!(at(8000), Verdict::Rule(0, Deny));
        assert_eq!(at(8080), Verdict::Rule(0, Deny));
        assert_eq!(at(8081), Verdict::Default(Allow));
        // Ports narrow a destination entry: both must match.
        let set = outbound(Allow, &[(Deny, &["192.0.2.0/24"], &["25"])]);
        assert_eq!(
            set.destination("192.0.2.1", ip("192.0.2.1"), 25),
            Verdict::Rule(0, Deny)
        );
        assert_eq!(
            set.destination("192.0.2.1", ip("192.0.2.1"), 26),
            Verdict::Default(Allow)
        );
        assert_eq!(
            set.destination("198.51.100.1", ip("198.51.100.1"), 25),
            Verdict::Default(Allow)
        );
    }

    #[test]
    fn a_suffix_matches_subdomains_but_not_the_bare_domain_or_a_lookalike() {
        use Action::*;
        let set = outbound(Allow, &[(Deny, &["*.example.com"], &[])]);
        let name = |host| set.destination_name(host, 443);
        assert_eq!(name("api.example.com"), Verdict::Rule(0, Deny));
        assert_eq!(name("API.Example.COM."), Verdict::Rule(0, Deny));
        assert_eq!(name("a.b.example.com"), Verdict::Rule(0, Deny));
        assert_eq!(name("example.com"), Verdict::Default(Allow));
        assert_eq!(name("badexample.com"), Verdict::Default(Allow));
        assert_eq!(name("example.com.evil.test"), Verdict::Default(Allow));
        // The bare domain needs its own entry.
        let set = outbound(Allow, &[(Deny, &["example.com", "*.example.com"], &[])]);
        assert_eq!(
            set.destination_name("example.com", 443),
            Verdict::Rule(0, Deny)
        );
    }

    #[test]
    fn names_wait_for_addresses_only_when_an_address_entry_comes_first() {
        use Action::*;
        let set = outbound(
            Allow,
            &[
                (Deny, &["10.0.0.0/8"], &[]),
                (Allow, &["*.example.com"], &[]),
            ],
        );
        assert_eq!(
            set.destination_name("api.example.com", 443),
            Verdict::NeedsAddress
        );
        // Per address: the name's private address is refused by rule 1, its
        // public one allowed by rule 2.
        assert_eq!(
            set.destination("api.example.com", ip("10.1.2.3"), 443),
            Verdict::Rule(0, Deny)
        );
        assert_eq!(
            set.destination("api.example.com", ip("203.0.113.5"), 443),
            Verdict::Rule(1, Allow)
        );
        // A name entry first decides without addresses.
        let set = outbound(
            Allow,
            &[
                (Allow, &["*.example.com"], &[]),
                (Deny, &["10.0.0.0/8"], &[]),
            ],
        );
        assert_eq!(
            set.destination_name("api.example.com", 443),
            Verdict::Rule(0, Allow)
        );
        assert_eq!(
            set.destination_name("other.test", 443),
            Verdict::NeedsAddress
        );
        // A rule whose ports exclude this one is skipped, address entry or not.
        let set = outbound(Deny, &[(Allow, &["10.0.0.0/8"], &["22"])]);
        assert_eq!(
            set.destination_name("host.test", 443),
            Verdict::Default(Deny)
        );
    }

    #[test]
    fn several_addresses_are_kept_or_refused_one_by_one() {
        let policy = Policy {
            server_outbound: Some("out".into()),
            sets: vec![Spec {
                id: "out".into(),
                name: "Out".into(),
                direction: Direction::Outbound,
                default_action: Action::Allow,
                rules: vec![SetRule {
                    action: Action::Deny,
                    matches: Match {
                        destinations: vec!["10.0.0.0/8".into()],
                        ..Default::default()
                    },
                }],
            }],
            ..Default::default()
        };
        let layers = Layers::new(&policy);
        let (allowed, refused) = layers.filter_outbound(
            "mixed.test",
            vec![
                "10.0.0.1:443".parse().unwrap(),
                "203.0.113.1:443".parse().unwrap(),
            ],
        );
        assert_eq!(allowed, vec!["203.0.113.1:443".parse().unwrap()]);
        let refused = refused.unwrap();
        assert_eq!(refused.verdict, Some(Verdict::Rule(0, Action::Deny)));
        assert_eq!(
            refused.detail(),
            "server outbound rule set: rule 1 denies (Out)"
        );
    }

    #[test]
    fn layers_refuse_in_order_and_a_missing_or_misdirected_set_refuses_everything() {
        let set = |id: &str, direction, default_action| Spec {
            id: id.into(),
            name: id.to_uppercase(),
            direction,
            default_action,
            rules: vec![],
        };
        let policy = Policy {
            server_inbound: Some("open".into()),
            server_outbound: Some("closed-in".into()),
            sets: vec![
                set("open", Direction::Inbound, Action::Allow),
                set("closed-in", Direction::Inbound, Action::Deny),
            ],
        };
        let layers = Layers::new(&policy);
        let source = ip("192.0.2.1");
        assert_eq!(layers.inbound_refusal(None, source), None);
        let refusal = layers.inbound_refusal(Some("closed-in"), source).unwrap();
        assert_eq!(refusal.layer, Layer::RuleInbound);
        assert_eq!(
            refusal.detail(),
            "rule inbound rule set: default action denies (CLOSED-IN)"
        );
        let missing = layers.inbound_refusal(Some("gone"), source).unwrap();
        assert_eq!(missing.verdict, None);
        // An inbound set bound as the server's outbound one refuses.
        let outbound = layers.outbound("example.com", Some(source), 443).unwrap();
        assert!(outbound.denies() && outbound.set_name.is_none());
        // Every layer is reported for the tester.
        assert_eq!(layers.inbound(Some("closed-in"), source).count(), 2);
    }

    #[test]
    fn a_rule_keeps_a_dropped_set_until_its_new_revision_runs() {
        let spec = |id: &str| Spec {
            id: id.into(),
            name: id.into(),
            direction: Direction::Inbound,
            default_action: Action::Deny,
            rules: vec![],
        };
        let desired = |sets: Vec<Spec>| {
            let policy = Policy {
                sets,
                ..Default::default()
            };
            Desired {
                hash: policy.hash(),
                policy: Some(policy),
            }
        };
        let runtime = Runtime::default();
        runtime.retain(["a".to_string()].into());
        runtime.apply(Some(desired(vec![spec("a")])));
        // The new policy has only b; the running rule still uses a.
        runtime.apply(Some(desired(vec![spec("b")])));
        let source = ip("192.0.2.1");
        assert!(
            runtime
                .load()
                .inbound_refusal(Some("a"), source)
                .unwrap()
                .set_name
                .is_some()
        );
        runtime.retain(["b".to_string()].into());
        assert!(
            runtime
                .load()
                .inbound_refusal(Some("a"), source)
                .unwrap()
                .set_name
                .is_none()
        );
        runtime.apply(None);
        assert_eq!(runtime.applied_hash(), None);
    }

    #[test]
    fn rules_of_the_wrong_direction_and_bad_entries_are_refused() {
        let rule = |matches| SetRule {
            action: Action::Deny,
            matches,
        };
        assert!(
            validate_rules(
                Direction::Inbound,
                &[rule(Match {
                    destinations: vec!["example.com".into()],
                    sources: vec!["192.0.2.0/24".parse().unwrap()],
                    ..Default::default()
                })]
            )
            .is_err()
        );
        assert!(validate_rules(Direction::Inbound, &[rule(Match::default())]).is_err());
        assert!(
            validate_rules(
                Direction::Outbound,
                &[rule(Match {
                    sources: vec!["192.0.2.0/24".parse().unwrap()],
                    ports: vec!["443".into()],
                    ..Default::default()
                })]
            )
            .is_err()
        );
        for bad in ["*", "http://example.com", "example.com:443", "*."] {
            assert!(
                validate_rules(
                    Direction::Outbound,
                    &[rule(Match {
                        destinations: vec![bad.into()],
                        ..Default::default()
                    })]
                )
                .is_err(),
                "{bad}"
            );
        }
        for bad in ["*", "0-", "9-1", "70000"] {
            assert!(
                validate_rules(
                    Direction::Outbound,
                    &[rule(Match {
                        ports: vec![bad.into()],
                        ..Default::default()
                    })]
                )
                .is_err(),
                "{bad}"
            );
        }
        assert!(validate_name(" padded").is_err());
        assert!(validate_name(&"名".repeat(120)).is_ok());
        assert!(validate_name(&"名".repeat(121)).is_err());
    }

    #[test]
    fn an_agent_names_a_few_short_paths_and_unknown_ones_cover_nothing() {
        let report = |covers: Vec<String>| Report {
            covers,
            ..Default::default()
        };
        assert!(report(vec!["x".repeat(64); 16]).within_limits());
        assert!(!report(vec!["x".into(); 17]).within_limits());
        assert!(!report(vec!["x".repeat(65)]).within_limits());
        // A later agent may name paths this one does not know.
        let later: Report = serde_json::from_value(serde_json::json!({
            "applied_hash": "h",
            "covers": ["future_path", COVERS_GATEWAY_INBOUND]
        }))
        .unwrap();
        assert!(later.covers(COVERS_GATEWAY_INBOUND));
        assert!(!later.covers(COVERS_REVERSE_PRIVATE_OUTBOUND));
        assert!(!later.covers("future"));
        // 0.150.0 names none, and this one's are left out when empty.
        let old: Report = serde_json::from_value(serde_json::json!({"applied_hash": "h"})).unwrap();
        assert!(old.covers.is_empty());
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::json!({"applied_hash": "h"})
        );
    }

    #[test]
    fn an_error_the_agent_reports_always_fits_what_the_controller_takes() {
        let report = |error: String| Report {
            error: Some(error),
            ..Default::default()
        };
        // Cut by characters: 512 three-byte characters are 1536 bytes.
        let chinese = report_error(&"规".repeat(600));
        assert_eq!(chinese.chars().count(), MAX_ERROR_CHARS);
        assert_eq!(chinese.len(), 1536);
        assert!(report(chinese).within_limits());
        let widest = report_error(&"😀".repeat(600));
        assert_eq!(widest.len(), MAX_ERROR_BYTES);
        assert!(report(widest).within_limits());
        assert!(!report("x".repeat(MAX_ERROR_BYTES + 1)).within_limits());
    }

    #[test]
    fn a_set_that_does_not_compile_refuses_and_the_agent_says_why() {
        let bad = Spec {
            id: "bad".into(),
            name: "Bad".into(),
            direction: Direction::Outbound,
            default_action: Action::Allow,
            rules: vec![SetRule {
                action: Action::Deny,
                matches: Match {
                    destinations: vec!["*".into()],
                    ..Default::default()
                },
            }],
        };
        let policy = Policy {
            server_outbound: Some("bad".into()),
            sets: vec![bad],
            ..Default::default()
        };
        let runtime = Runtime::default();
        assert!(!runtime.server_outbound() && runtime.error().is_none());
        runtime.apply(Some(Desired {
            hash: policy.hash(),
            policy: Some(policy),
        }));
        assert!(runtime.server_outbound() && !runtime.server_inbound());
        let refused = runtime
            .load()
            .outbound("example.com", Some(ip("192.0.2.1")), 443)
            .unwrap();
        assert!(refused.denies() && refused.set_name.is_none());
        let error = runtime.error().unwrap();
        assert!(
            error.starts_with("rule set \"Bad\" (bad) cannot be used here and refuses everything: rule 1: invalid destination"),
            "{error}"
        );
        runtime.apply(None);
        assert!(!runtime.server_outbound() && runtime.error().is_none());
    }

    #[test]
    fn the_agents_name_check_answers_as_the_tester_does() {
        let spec = Spec {
            id: "out".into(),
            name: "Out".into(),
            direction: Direction::Outbound,
            default_action: Action::Allow,
            rules: vec![
                SetRule {
                    action: Action::Deny,
                    matches: Match {
                        destinations: vec!["*.internal.test".into()],
                        ..Default::default()
                    },
                },
                SetRule {
                    action: Action::Deny,
                    matches: Match {
                        destinations: vec!["10.0.0.0/8".into()],
                        ..Default::default()
                    },
                },
            ],
        };
        let layers = Layers::new(&Policy {
            server_outbound: Some("out".into()),
            sets: vec![spec],
            ..Default::default()
        });
        let refused = layers.outbound_name("db.internal.test", 443).unwrap_err();
        assert_eq!(
            refused.detail(),
            "server outbound rule set: rule 1 denies (Out)"
        );
        assert_eq!(layers.outbound_name("example.com", 443), Ok(true));
        assert_eq!(
            Layers::default().outbound_name("db.internal.test", 443),
            Ok(false)
        );
        // The same answers as the tester's.
        assert_eq!(
            layers.outbound("db.internal.test", None, 443).unwrap(),
            refused
        );
        assert_eq!(
            layers.outbound("example.com", None, 443).unwrap().verdict,
            Some(Verdict::NeedsAddress)
        );
    }
}
