fn command(value: &ManagementCommandV2) -> Result<(&str, u64), HostError> {
    let ManagementCommandV2::SourceApprove {
        operation_id,
        expected_state_revision,
        ..
    } = value
    else {
        return Err(HostError::RequestInvalid);
    };
    Ok((operation_id, *expected_state_revision))
}
