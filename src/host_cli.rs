use std::{path::Path, time::SystemTime};

use crate::{HostError, host_cli_io};

pub fn run_authority_host_cli(arguments: impl Iterator<Item = String>) -> Result<(), HostError> {
    let values = arguments.collect::<Vec<_>>();
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Unavailable)?
        .as_secs();
    if management(&values) {
        return management_once(&values, now);
    }
    if peer_head(&values) {
        return peer_head_once(&values, now);
    }
    if replay_witness(&values) {
        return replay_witness_once(&values, now);
    }
    if initialize(&values) {
        return initialize_once(&values, now);
    }
    if validate(&values) {
        return validate_once(&values, now);
    }
    Err(HostError::RequestInvalid)
}

include!("host_cli_config.rs");
include!("host_cli_gateway.rs");

fn absolute(value: &str) -> bool {
    Path::new(value).is_absolute()
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
