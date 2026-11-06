//! Endpoint groups and saved forwarding chains. A group is one layer of
//! alternative servers; a chain is an ordered list of groups. Building a
//! forwarding from a chain creates ordinary rules, one per server, so agents
//! and the rule format are unchanged: every server of a layer targets every
//! server of the next layer through `via`, chosen by that layer's balance.
use crate::model::{Balance, Protocol};
use crate::topology::{BatchResult, ConfigBatch};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// Most servers in one endpoint group.
pub const MAX_MEMBERS: usize = 32;
/// Most layers in one chain.
pub const MAX_LAYERS: usize = 6;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointGroup {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    /// Node ids in the order the operator chose.
    pub members: Vec<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub members: Vec<String>,
}
/// One layer: its servers are the candidates the previous hop chooses from
/// with `balance`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub group_id: String,
    #[serde(default)]
    pub balance: Balance,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub layers: Vec<Layer>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainInput {
    pub name: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub layers: Vec<Layer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub node_id: String,
    pub rule_id: String,
}
/// What a forwarding built from a chain created, stored under
/// `chain_use:<entry rule id>`: the rules of each layer, in group order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainUse {
    pub chain_id: String,
    pub entry_node_id: String,
    pub layers: Vec<Vec<Hop>>,
}
/// Plan and apply input. `owner_id` defaults to the caller. Apply refuses
/// with 409 when `expected_revisions` (from a plan) no longer matches a
/// server, so what is published is what was planned.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInput {
    pub entry_node_id: String,
    pub name: String,
    pub protocol: Protocol,
    pub target: String,
    #[serde(default)]
    pub entry_port: Option<u16>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub expected_revisions: Option<BTreeMap<String, u64>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub node_id: String,
    pub node_name: Option<String>,
    /// The node no longer exists.
    pub missing: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainRef {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub members: Vec<MemberView>,
    /// Chains with a layer on this group; it cannot be deleted while any is.
    pub used_by: Vec<ChainRef>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct LayerView {
    pub group_id: String,
    pub group_name: Option<String>,
    pub balance: Balance,
    pub members: Vec<MemberView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct HopView {
    pub node_id: String,
    pub rule_id: String,
    pub node_name: Option<String>,
    /// The node or its rule no longer exists.
    pub missing: bool,
}
/// Members of a layer's group now compared with when the forwarding was
/// built; `layer` counts from 1.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LayerChange {
    pub layer: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct UseView {
    pub entry_rule_id: String,
    pub entry_node_id: String,
    pub entry_node_name: Option<String>,
    /// The entry rule's name, while it exists.
    pub name: Option<String>,
    /// The entry rule or its node no longer exists.
    pub missing: bool,
    pub layers: Vec<Vec<HopView>>,
    /// Some layer's group gained or lost members since the forwarding was
    /// built. Nothing re-syncs the forwarding automatically.
    pub out_of_date: bool,
    pub changes: Vec<LayerChange>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub layers: Vec<LayerView>,
    pub uses: Vec<UseView>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
/// One planned rule: `layer` 0 is the entry, then the chain's layers from 1.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedHop {
    pub layer: usize,
    pub node_id: String,
    pub node_name: String,
    pub rule_id: String,
    pub listen: SocketAddr,
    pub advertise: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainPlan {
    pub entry_rule_id: String,
    pub hops: Vec<PlannedHop>,
    /// The batch apply would publish; rule ids are generated again by apply.
    pub batch: ConfigBatch,
    pub preview: BatchResult,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainApplied {
    pub entry_rule_id: String,
    pub hops: Vec<PlannedHop>,
    pub published: BatchResult,
}
