use crate::AuthorityError;
use std::fmt::{Display, Formatter};

macro_rules! bounded_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(AuthorityError::InvalidValue(stringify!($name)));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_id!(CredentialId);
bounded_id!(DeviceId);
bounded_id!(GrantId);
bounded_id!(ProviderAccountRef);
bounded_id!(ServiceId);
bounded_id!(TransferId);

impl GrantId {
    pub(crate) fn trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl TransferId {
    pub(crate) fn trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct OpaqueOwnerRef(String);

impl OpaqueOwnerRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        if value.contains('@') || value.len() > 128 {
            return Err(AuthorityError::OwnerReferenceNotOpaque);
        }
        if !value.starts_with("psa_") || value.len() < 24 {
            return Err(AuthorityError::OwnerReferenceNotPairwise);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(AuthorityError::OwnerReferenceNotOpaque);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for OpaqueOwnerRef {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct GrantAudience(String);

impl GrantAudience {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        if !value.starts_with("crowsi://") || value.len() > 128 {
            return Err(AuthorityError::InvalidValue("grant audience"));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct GrantAction(String);

impl GrantAction {
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            return Err(AuthorityError::InvalidValue("grant action"));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
