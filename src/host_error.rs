use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostError {
    ConfigInvalid,
    EvidenceInvalid,
    OperationInvalid,
    PathInvalid,
    RequestInvalid,
    ResponseInvalid,
    StateInvalid,
    Unavailable,
}

impl HostError {
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ConfigInvalid => "credential-authority-host-config-invalid",
            Self::EvidenceInvalid => "credential-authority-host-evidence-invalid",
            Self::OperationInvalid => "credential-authority-host-operation-invalid",
            Self::PathInvalid => "credential-authority-host-path-invalid",
            Self::RequestInvalid => "credential-authority-host-request-invalid",
            Self::ResponseInvalid => "credential-authority-host-response-invalid",
            Self::StateInvalid => "credential-authority-host-state-invalid",
            Self::Unavailable => "credential-authority-host-unavailable",
        }
    }
}

impl Display for HostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for HostError {}

impl From<crate::AuthorityError> for HostError {
    fn from(_: crate::AuthorityError) -> Self {
        Self::Unavailable
    }
}
