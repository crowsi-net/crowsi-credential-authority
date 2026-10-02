fn initialize(values: &[String]) -> bool {
    config_command(values, "initialize-once")
}

fn initialize_once(values: &[String], now: u64) -> Result<(), HostError> {
    let config = crate::host_config::load_pinned(Path::new(&values[3]), &values[5], now)?;
    let initial_clock_ms = config
        .document
        .issued_at_epoch_s
        .checked_mul(1_000)
        .ok_or(HostError::ConfigInvalid)?;
    crate::FileAuthorityStore::initialize_anchored(
        &config.document.authority_store_directory,
        &config.document.authority_anchor_directory,
        initial_clock_ms,
    )?;
    crate::management_v2_journal::ManagementJournalV2::initialize(
        Path::new(&config.document.management_state_directory),
        Path::new(&config.document.management_anchor_directory),
        config.document.authority_epoch,
        crate::management_v2_journal::ReservationRootBinding::from_config(&config.document),
    )
}

fn validate(values: &[String]) -> bool {
    config_command(values, "validate-once")
}

fn validate_once(values: &[String], now: u64) -> Result<(), HostError> {
    let config = crate::host_config::load_pinned(Path::new(&values[3]), &values[5], now)?;
    crate::FileAuthorityStore::open_anchored(
        &config.document.authority_store_directory,
        &config.document.authority_anchor_directory,
    )?;
    crate::management_v2_journal::ManagementJournalV2::open(
        Path::new(&config.document.management_state_directory),
        Path::new(&config.document.management_anchor_directory),
        config.document.authority_epoch,
        crate::management_v2_journal::ReservationRootBinding::from_config(&config.document),
    )?;
    Ok(())
}

fn config_command(values: &[String], command: &str) -> bool {
    values.len() == 6
        && values[1] == command
        && values[2] == "--config"
        && absolute(&values[3])
        && values[4] == "--config-sha256"
        && digest(&values[5])
}
