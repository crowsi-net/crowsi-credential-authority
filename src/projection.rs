use crate::{AuthorityError, OpaqueOwnerRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataProjectionQuery {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) limit: usize,
}

impl MetadataProjectionQuery {
    #[must_use]
    pub const fn new(owner: OpaqueOwnerRef, limit: usize) -> Self {
        Self { owner, limit }
    }

    pub fn decode_strict(input: &str) -> Result<Self, AuthorityError> {
        if input.len() > 4_096 {
            return Err(AuthorityError::InvalidValue("projection query"));
        }
        let value: serde_json::Value = serde_json::from_str(input)
            .map_err(|_| AuthorityError::InvalidValue("projection query"))?;
        let object = value
            .as_object()
            .ok_or(AuthorityError::InvalidValue("projection query"))?;
        for field in object.keys() {
            if field != "owner_ref" && field != "limit" {
                return Err(AuthorityError::UnknownField(field.clone()));
            }
        }
        if object.len() != 2 {
            return Err(AuthorityError::InvalidValue("projection query"));
        }
        let owner = object
            .get("owner_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or(AuthorityError::InvalidValue("owner_ref"))?;
        let limit = object
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(AuthorityError::InvalidValue("limit"))?;
        Ok(Self {
            owner: OpaqueOwnerRef::parse(owner)?,
            limit,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataProjection {
    encoded: String,
}

impl MetadataProjection {
    #[must_use]
    pub const fn contains_secret_values(&self) -> bool {
        false
    }

    pub fn encode_json(&self) -> Result<String, AuthorityError> {
        Ok(self.encoded.clone())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self, AuthorityError> {
        let encoded = serde_json::to_string(value).map_err(|_| AuthorityError::StoreUnavailable)?;
        if encoded.len() > 262_144 {
            return Err(AuthorityError::ProjectionLimitOutOfRange);
        }
        Ok(Self { encoded })
    }
}
