fn pristine(root: &Path, allowed: Option<&str>) -> Result<(), HostError> {
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let name = entry
            .map_err(|_| HostError::StateInvalid)?
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if allowed.is_none_or(|value| value != name) {
            return Err(HostError::StateInvalid);
        }
    }
    Ok(())
}
