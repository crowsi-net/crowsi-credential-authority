fn command(value: &ManagementCommandV2) -> Result<(&str, u64), HostError> {
    let ManagementCommandV2::TargetApprove {
        operation_id,
        expected_state_revision,
        ..
    } = value
    else {
        return Err(HostError::RequestInvalid);
    };
    Ok((operation_id, *expected_state_revision))
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}
