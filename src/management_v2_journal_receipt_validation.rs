fn mutation_response(
    value: &Receipt,
    record: &ManagementRecordV2,
    revision: u64,
) -> Result<(), HostError> {
    if value.read_only || value.operation_id.as_deref() != Some(&record.operation.operation_id) {
        return Err(HostError::ResponseInvalid);
    }
    let Response::Projection(response) = &value.response else {
        return Err(HostError::ResponseInvalid);
    };
    match &response.body {
        crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation {
            operation,
        } if operation == &record.operation && response.snapshot_revision == revision => Ok(()),
        _ => Err(HostError::ResponseInvalid),
    }
}

fn response_revision(value: &Receipt, revision: u64) -> Result<(), HostError> {
    if let Response::Projection(response) = &value.response
        && response.snapshot_revision != revision
    {
        return Err(HostError::ResponseInvalid);
    }
    Ok(())
}
