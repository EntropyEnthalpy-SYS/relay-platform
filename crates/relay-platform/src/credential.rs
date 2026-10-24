use crate::lease::LeaseProof;
use serde::{Deserialize, Serialize};

/// Public status contains no credential or credential hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatus {
    pub revision: u64,
    pub pending: Option<RotationRequest>,
    pub last_rotation: Option<RotationReceipt>,
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
