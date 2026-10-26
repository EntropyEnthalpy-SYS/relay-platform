//! Node execution leases. The controller fences its own writes; compliant
//! agents stop business traffic before their conservative local deadline.
use crate::model::EngineStats;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeasePolicy {
    #[serde(default = "default_ttl")]
    pub ttl_ms: u64,
}
fn default_ttl() -> u64 {
    30_000
}
impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            ttl_ms: default_ttl(),
        }
    }
}
impl LeasePolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(5_000..=120_000).contains(&self.ttl_ms) {
            return crate::store::reject(400, "node lease TTL must be 5000..120000 ms");
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseProof {
    pub run_id: String,
    pub generation: u64,
    pub token: String,
}
impl std::fmt::Debug for LeaseProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseProof")
            .field("run_id", &self.run_id)
            .field("generation", &self.generation)
            .field("token", &"[redacted]")
            .finish()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub run_id: String,
    pub token: String,
    /// None acquires (or recovers a lost acquisition response); Some renews.
    pub generation: Option<u64>,
    /// Resume only an uninterrupted durable budget run from this prior owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_generation: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseReply {
    pub required: bool,
    pub generation: Option<u64>,
    pub valid_for_ms: u64,
    pub ttl_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRelease {
    pub proof: LeaseProof,
    pub stats: EngineStats,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseStatus {
    pub policy: Option<LeasePolicy>,
    pub generation: u64,
    pub holder_run_id: Option<String>,
    pub active: bool,
    pub remaining_ms: u64,
    pub recovery_wait_ms: u64,
}
