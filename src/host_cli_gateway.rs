fn replay_witness(values: &[String]) -> bool {
    peer_command(values, "consume-transport-replay")
}

fn replay_witness_once(values: &[String], now: u64) -> Result<(), HostError> {
    let wire = host_cli_io::read_gateway_request()?;
    let (host, gateway) = internal_configs(values, now)?;
    let response = crate::host_replay_witness::handle(&host, &gateway, &values[9], &wire, now)?;
    host_cli_io::write_response(&response)
}

fn peer_head(values: &[String]) -> bool {
    peer_command(values, "peer-status-head")
}

fn peer_command(values: &[String], command: &str) -> bool {
    values.len() == 12
        && values[1] == "handle-once"
        && values[2] == "--config"
        && absolute(&values[3])
        && values[4] == "--config-sha256"
        && digest(&values[5])
        && values[6] == "--gateway-config"
        && absolute(&values[7])
        && values[8] == "--gateway-config-sha256"
        && digest(&values[9])
        && values[10] == "--command"
        && values[11] == command
}

fn peer_head_once(values: &[String], now: u64) -> Result<(), HostError> {
    let wire = host_cli_io::read_gateway_request()?;
    let (host, gateway) = internal_configs(values, now)?;
    let response = crate::host_peer_head::handle(&host, &gateway, &values[9], &wire, now)?;
    host_cli_io::write_response(&response)
}

fn internal_configs(
    values: &[String],
    now: u64,
) -> Result<
    (
        crate::host_config::VerifiedHostConfig,
        crate::gateway_contract::GatewayConfigDocument,
    ),
    HostError,
> {
    let host = crate::host_config::load_pinned(Path::new(&values[3]), &values[5], now)?;
    let gateway = crate::gateway_config::load_document(Path::new(&values[7]), &values[9], now)?;
    if gateway.host_config_sha256 != values[5]
        || Path::new(&gateway.host_config_path) != Path::new(&values[3])
        || !crate::gateway_validation::compatible(&host.document, &gateway)
    {
        Err(HostError::ConfigInvalid)
    } else {
        Ok((host, gateway))
    }
}

fn management(values: &[String]) -> bool {
    peer_command(values, "management-v2")
}

fn management_once(values: &[String], now: u64) -> Result<(), HostError> {
    let wire = host_cli_io::read_gateway_request()?;
    let response = crate::host_gateway_handler::handle(
        Path::new(&values[3]),
        &values[5],
        Path::new(&values[7]),
        &values[9],
        &wire,
        now,
    )?;
    host_cli_io::write_response(&response)
}
