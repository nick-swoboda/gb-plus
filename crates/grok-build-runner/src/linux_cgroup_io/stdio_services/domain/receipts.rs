//! Remove interrupted publications without interfering with a live owner.

use super::*;

pub(super) fn remove_abandoned_temporaries(
    records: &Dir,
    names: &[String],
    maximum: u64,
) -> Result<(), String> {
    let mut removed = false;
    for temporary in names.iter().filter(|name| name.starts_with("next-lease-")) {
        let name = temporary.strip_prefix("next-").unwrap();
        let identity = name
            .strip_prefix("lease-")
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or("Unknown temporary service receipt remains recoverable.")?;
        if identity.len() != 64
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Unknown temporary service receipt remains recoverable.".into());
        }
        if records.try_exists(name).map_err(failure)? {
            let bytes = counter::read_private_metadata(records, name, 8192)?;
            let record: Record = serde_json::from_slice(&bytes).map_err(failure)?;
            validate_record(&record, name, maximum)?;
            if process_start(record.owner_pid)? == Some(record.owner_start) {
                continue;
            }
        }
        // Partial JSON is expected at a crash cut. Its bytes are not execution
        // authority. No committed record means no effects could have started;
        // an existing record is authoritative and its owner is proven gone.
        let bytes = counter::read_private_metadata(records, temporary, 8192)?;
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            let record: Record = serde_json::from_value(value).map_err(failure)?;
            validate_record(&record, name, maximum)?;
        }
        records.remove_file(temporary).map_err(failure)?;
        removed = true;
    }
    if removed {
        super::super::super::sync_directory(records).map_err(failure)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
