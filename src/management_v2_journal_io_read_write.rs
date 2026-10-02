pub(crate) fn read(
    root: &Path,
    anchor_root: &Path,
    owner: &str,
) -> Result<ManagementLedgerV2, HostError> {
    crate::management_v2_commit::read(root, anchor_root, owner)
}

pub(crate) fn write(
    root: &Path,
    anchor_root: &Path,
    owner: &str,
    value: &ManagementLedgerV2,
) -> Result<(), HostError> {
    validate(value, owner, value.revision)?;
    if serde_json::to_vec(value)
        .map_err(|_| HostError::StateInvalid)?
        .len()
        > 16_777_216
    {
        return Err(HostError::StateInvalid);
    }
    crate::management_v2_commit::write(root, anchor_root, owner, value)
}
