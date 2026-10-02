use std::io::{Read, Write};

use crate::HostError;

pub(crate) fn read_gateway_request() -> Result<Vec<u8>, HostError> {
    read_bounded(540_000)
}

fn read_bounded(maximum: usize) -> Result<Vec<u8>, HostError> {
    let mut wire = Vec::new();
    std::io::stdin()
        .take(maximum as u64 + 1)
        .read_to_end(&mut wire)
        .map_err(|_| HostError::RequestInvalid)?;
    if wire.is_empty() || wire.len() > maximum {
        Err(HostError::RequestInvalid)
    } else {
        Ok(wire)
    }
}

pub(crate) fn write_response(wire: &[u8]) -> Result<(), HostError> {
    if wire.is_empty() || wire.len() > 1_048_576 {
        return Err(HostError::ResponseInvalid);
    }
    std::io::stdout()
        .write_all(wire)
        .map_err(|_| HostError::ResponseInvalid)
}
