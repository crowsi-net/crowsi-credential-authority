fn state(value: State, acceptance: &Acceptance) -> bool {
    match (
        &acceptance.execution_reservation,
        &acceptance.finalize_request_sha256,
        &acceptance.finalize_request,
        &acceptance.final_revoke_exchange,
    ) {
        (None, None, None, None) => {
            matches!(value, State::AwaitingRevocationFinal | State::Cancelled)
        }
        (Some(_), None, None, None) => value == State::RevocationExecutionReserved,
        (Some(_), Some(_), Some(_), Some(_)) => {
            matches!(value, State::Unknown | State::Completed)
        }
        _ => false,
    }
}

fn bare_digest(value: &str) -> bool {
    lower_hex(value, 64)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}

fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.trim() == value
}
