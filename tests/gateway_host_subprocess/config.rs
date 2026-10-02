use std::path::PathBuf;

use crate::fixture::Fixture;

pub(crate) struct Documents {
    pub(crate) host: PathBuf,
    pub(crate) host_digest: String,
    pub(crate) gateway: PathBuf,
    pub(crate) gateway_digest: String,
}

pub(crate) fn write(fixture: &Fixture) -> Documents {
    let files = crate::config_files::write(fixture);
    let (host, host_digest) = crate::config_host::write(fixture, &files);
    let (gateway, gateway_digest) =
        crate::config_gateway::write(fixture, &files, &host, &host_digest);
    Documents {
        host,
        host_digest,
        gateway,
        gateway_digest,
    }
}
