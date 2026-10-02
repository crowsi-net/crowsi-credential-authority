use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::HostError;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MarkerV1 {
    schema: String,
    deployment_id: String,
    authority_epoch: u64,
}

pub(super) fn initialize(
    root: &Path,
    name: &str,
    deployment: &str,
    epoch: u64,
) -> Result<(), HostError> {
    let path = path(root, name)?;
    let value = MarkerV1 {
        schema: schema(name)?,
        deployment_id: deployment.into(),
        authority_epoch: epoch,
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path, &wire)
}

pub(super) fn verify(
    root: &Path,
    name: &str,
    deployment: &str,
    epoch: u64,
) -> Result<(), HostError> {
    let wire = crate::host_files::owner_file(&path(root, name)?, 16_384)?;
    let value: MarkerV1 = serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    let valid = value.schema == schema(name)?
        && value.deployment_id == deployment
        && value.authority_epoch == epoch
        && epoch > 0;
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

pub(super) fn filename(name: &str) -> Result<String, HostError> {
    valid(name)
        .then(|| format!("gateway-{name}-initialized.json"))
        .ok_or(HostError::StateInvalid)
}

pub(super) fn present(root: &Path, name: &str) -> Result<bool, HostError> {
    crate::management_v2_atomic::present(&path(root, name)?)
}

fn path(root: &Path, name: &str) -> Result<PathBuf, HostError> {
    Ok(root.join(filename(name)?))
}

fn schema(name: &str) -> Result<String, HostError> {
    valid(name)
        .then(|| format!("crowsi://credential-authority/gateway-{name}-initialized/v1"))
        .ok_or(HostError::StateInvalid)
}

fn valid(value: &str) -> bool {
    matches!(
        value,
        "peer-state" | "peer-anchor" | "replay-state" | "replay-anchor"
    )
}
