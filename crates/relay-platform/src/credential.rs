use crate::lease::LeaseProof;
use serde::{Deserialize, Serialize};

/// Public status contains no credential or credential hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatus {
    #[serde(default)]
    pub phase: CredentialPhase,
    pub revision: u64,
    pub pending: Option<RotationRequest>,
    pub last_rotation: Option<RotationReceipt>,
    #[serde(default)]
    pub revocation: Option<RevocationReceipt>,
    #[serde(default)]
    pub replacement: Option<ReplacementStatus>,
    #[serde(default)]
    pub blocked_quota_periods: Vec<QuotaHold>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPhase {
    NotEnrolled,
    #[default]
    Active,
    Revoked,
    ReplacementPending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub id: String,
    pub revision: u64,
    pub at_ms: i64,
    pub actor_id: String,
    pub reason: String,
    pub strict_execution: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementStatus {
    pub id: String,
    pub revision: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub enrolled_at_ms: Option<i64>,
    pub offline_stop_attested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaHold {
    pub rule_id: String,
    pub meter_epoch: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCredential {
    pub operation_id: String,
    pub expected_revision: u64,
    pub reason: String,
}

// Contains the caller-generated one-time enrollment secret; never Debug/log it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceCredential {
    pub operation_id: String,
    pub expected_revision: u64,
    pub enrollment_token: String,
    pub valid_for_seconds: u64,
    #[serde(default)]
    pub offline_stop_attested: bool,
    #[serde(default)]
    pub lease_policy: Option<crate::lease::LeasePolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRequest {
    pub id: String,
    pub expected_revision: u64,
    pub requested_at_ms: i64,
    pub requested_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationReceipt {
    pub id: String,
    pub revision: u64,
    pub completed_at_ms: i64,
}

// Deliberately not Debug: this message contains the proposed secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateCredential {
    pub request_id: String,
    pub expected_revision: u64,
    pub credential: String,
    #[serde(default)]
    pub lease: Option<LeaseProof>,
}
