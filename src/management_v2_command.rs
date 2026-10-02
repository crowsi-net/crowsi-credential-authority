use crowsi_credential_authority_contracts::ManagementCommandV2;

pub(crate) const fn route(command: &ManagementCommandV2) -> &'static str {
    match command {
        ManagementCommandV2::Snapshot { .. } => "snapshot",
        ManagementCommandV2::SourceOptions { .. } => "source-options",
        ManagementCommandV2::SourceApprove { .. } => "source-approve",
        ManagementCommandV2::PendingList { .. } => "pending",
        ManagementCommandV2::TargetOptions { .. } => "target-options",
        ManagementCommandV2::TargetApprove { .. } => "target-approve",
        ManagementCommandV2::ApprovalOptions { .. } => "approval-options",
        ManagementCommandV2::ApproveRevocation { .. } => "approve-revocation",
        ManagementCommandV2::Cancel { .. } => "cancel",
        ManagementCommandV2::Reconcile { .. } => "reconcile",
    }
}

pub(crate) const fn historic_mutation(command: &ManagementCommandV2) -> bool {
    !matches!(
        command,
        ManagementCommandV2::Snapshot { .. }
            | ManagementCommandV2::PendingList { .. }
            | ManagementCommandV2::Cancel { .. }
    )
}
