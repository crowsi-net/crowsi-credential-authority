use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    AccountUnavailable,
    AtomicCommitFailed,
    BlindProviderRetryForbidden,
    CredentialAlreadyOwned,
    FreshStepUpRequired,
    GrantAlreadyConsumed,
    GrantExpired,
    IdentityAssertionInvalid,
    IdentityAssertionReplay,
    IntegrityViolation,
    InvalidValue(&'static str),
    NotFound,
    OwnerReferenceNotOpaque,
    OwnerReferenceNotPairwise,
    ProjectionLimitOutOfRange,
    ProviderReceiptInvalid,
    ProviderReconciliationRequired,
    ProviderReconciliationSignatureInvalid,
    ProviderReissueReceiptRequired,
    RollbackDetected,
    SnapshotTooLarge,
    StaleRevocationEpoch,
    StepUpDeviceMismatch,
    StoreUnavailable,
    StorePathInvalid,
    TargetDeviceMismatch,
    TargetKeyProofInvalid,
    TransferAlreadyConsumed,
    TransferCancelled,
    UnknownField(String),
    WrongAction,
    WrongAudience,
    WrongDevice,
    WrongOwner,
}

impl Display for AuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AuthorityError {}
