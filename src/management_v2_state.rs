use crowsi_credential_authority_contracts::{ActorRequirementV2, RequiredActorRole};

pub(crate) fn reconcile_actor() -> ActorRequirementV2 {
    actor(RequiredActorRole::ReconcileOnly)
}
pub(crate) fn none_actor() -> ActorRequirementV2 {
    actor(RequiredActorRole::NoActor)
}
fn actor(role: RequiredActorRole) -> ActorRequirementV2 {
    ActorRequirementV2 {
        role,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}
