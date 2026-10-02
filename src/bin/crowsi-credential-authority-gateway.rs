use std::process::ExitCode;

fn main() -> ExitCode {
    match crowsi_credential_authority::run_authority_gateway_cli(std::env::args()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "crowsi-credential-authority-gateway: {}",
                error.reason_code()
            );
            ExitCode::FAILURE
        }
    }
}
