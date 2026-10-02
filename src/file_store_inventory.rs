use crate::{
    AuthorityError,
    file_store_path::{PinnedDirectory, StorePaths},
};

pub(crate) fn empty(paths: &StorePaths) -> Result<bool, AuthorityError> {
    paths.validate()?;
    Ok(names(&paths.state)?.is_empty() && names(&paths.anchor)?.is_empty())
}

pub(crate) fn names(root: &PinnedDirectory) -> Result<Vec<String>, AuthorityError> {
    root.validate_source()?;
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root.path()).map_err(|_| AuthorityError::StoreUnavailable)? {
        let name = entry
            .map_err(|_| AuthorityError::StoreUnavailable)?
            .file_name()
            .into_string()
            .map_err(|_| AuthorityError::IntegrityViolation)?;
        if name.is_empty() || name.len() > 160 || values.len() >= 16 {
            return Err(AuthorityError::IntegrityViolation);
        }
        values.push(name);
    }
    values.sort();
    root.validate_source()?;
    Ok(values)
}
