//! TUF delegated-role signature authorization.
//!
//! Compiled only with the `tuf-delegation` feature.
//! No additional cryptographic implementation or dependencies.

use crate::{
    error::{Error, Result},
    schema::{role::RoleKeys, signed::Signed, targets::Targets},
    verify::{signatures::verify_signatures, state::Checked},
};

/// Authenticate delegated metadata using authority granted
/// by an already-verified parent targets role.
///
/// This checks signatures only. Snapshot consistency, expiry,
/// rollback protection and path authorization are required
/// before any target may be trusted.
pub(crate) fn verify_delegated_signatures(
    parent: &Checked<Targets>,
    role_name: &str,
    metadata: Signed<Targets>,
) -> Result<Checked<Targets>> {
    let delegations = parent
        .get()
        .delegations
        .as_ref()
        .ok_or(Error::NoKeysForRole)?;

    let role = delegations
        .roles
        .iter()
        .find(|role| role.name == role_name)
        .ok_or(Error::NoKeysForRole)?;

    let authorized = RoleKeys::new(role.keyids.clone(), role.threshold);

    if authorized.threshold == 0
        || authorized.keyids.is_empty()
        || authorized.threshold as usize > authorized.keyids.len()
    {
        return Err(Error::NoKeysForRole);
    }

    if metadata.signed.role_type != "targets" || !metadata.signed.spec_version.starts_with("1.") {
        return Err(Error::Deserialize);
    }

    let canonical = stuf_encoding::canonicalize(&metadata.signed)?;

    verify_signatures(
        &metadata.signatures,
        &authorized,
        &delegations.keys,
        &canonical,
    )?;

    Ok(Checked(metadata.signed))
}
