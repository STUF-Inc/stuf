//! TUF delegated-role signature authorization.
//!
//! Compiled only with the `tuf-delegation` feature.
//! No additional cryptographic implementation or dependencies.

use super::delegation_rules::matches_path_pattern;

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

/// Whether a delegated role is authorized for a target path.
///
/// This checks path restrictions only. It does not authenticate
/// metadata or authorize installing firmware.
pub(crate) fn role_allows_path(
    role: &crate::schema::targets::DelegatedRole,
    target_path: &str,
) -> bool {
    match (&role.paths, &role.path_hash_prefixes) {
        (Some(patterns), None) => patterns
            .iter()
            .any(|pattern| matches_path_pattern(pattern, target_path)),

        (None, Some(prefixes)) => {
            let digest = stuf_env::crypto::sha256_hex(target_path.as_bytes());

            prefixes.iter().any(|prefix| {
                !prefix.is_empty()
                    && prefix.len() <= 64
                    && prefix.bytes().all(|b| b.is_ascii_hexdigit())
                    && digest.starts_with(&prefix.to_ascii_lowercase())
            })
        }

        _ => false,
    }
}

#[cfg(all(test, feature = "crypto-ed25519", feature = "hash-sha256"))]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, string::ToString, vec};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    use crate::schema::{
        keys::{KeyId, KeyType, KeyValue, PublicKey, SignatureScheme},
        signed::Signature,
        targets::{DelegatedRole, Delegations},
    };

    struct TestKey {
        signing: SigningKey,
        id: KeyId,
        public: PublicKey,
    }

    impl TestKey {
        fn new() -> Self {
            let signing = SigningKey::generate(&mut OsRng);
            let bytes = signing.verifying_key().to_bytes();

            Self {
                id: KeyId(stuf_env::crypto::sha256_hex(&bytes)),
                public: PublicKey {
                    keytype: KeyType::Ed25519,
                    scheme: SignatureScheme::Ed25519,
                    keyval: KeyValue {
                        public: hex::encode(bytes),
                    },
                },
                signing,
            }
        }

        fn signature(&self, targets: &Targets) -> Signature {
            let bytes = stuf_encoding::canonicalize(targets).unwrap();
            Signature {
                keyid: self.id.clone(),
                sig: hex::encode(self.signing.sign(&bytes).to_bytes()),
            }
        }
    }

    fn empty_targets() -> Targets {
        Targets {
            role_type: "targets".to_string(),
            spec_version: "1.0.0".to_string(),
            version: 1,
            expires: 2_000_000_000,
            targets: BTreeMap::new(),
            delegations: None,
        }
    }

    fn parent(keys: &[&TestKey], threshold: u32) -> Checked<Targets> {
        let mut targets = empty_targets();
        let mut available = BTreeMap::new();

        for key in keys {
            available.insert(key.id.clone(), key.public.clone());
        }

        targets.delegations = Some(Delegations {
            keys: available,
            roles: vec![DelegatedRole {
                name: "sensors".to_string(),
                keyids: keys.iter().map(|k| k.id.clone()).collect(),
                threshold,
                terminating: false,
                paths: Some(vec!["sensors/*".to_string()]),
                path_hash_prefixes: None,
            }],
        });

        Checked(targets)
    }

    fn signed(targets: Targets, keys: &[&TestKey]) -> Signed<Targets> {
        let signatures = keys.iter().map(|k| k.signature(&targets)).collect();
        Signed {
            signed: targets,
            signatures,
        }
    }

    #[test]
    fn authorized_delegated_signature_passes() {
        let key = TestKey::new();
        let result = verify_delegated_signatures(
            &parent(&[&key], 1),
            "sensors",
            signed(empty_targets(), &[&key]),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn unauthorized_delegated_signature_fails() {
        let authorized = TestKey::new();
        let attacker = TestKey::new();

        let result = verify_delegated_signatures(
            &parent(&[&authorized], 1),
            "sensors",
            signed(empty_targets(), &[&attacker]),
        );
        assert!(matches!(result, Err(Error::ThresholdNotMet { .. })));
    }

    #[test]
    fn insufficient_delegated_threshold_fails() {
        let first = TestKey::new();
        let second = TestKey::new();

        let result = verify_delegated_signatures(
            &parent(&[&first, &second], 2),
            "sensors",
            signed(empty_targets(), &[&first]),
        );
        assert!(matches!(
            result,
            Err(Error::ThresholdNotMet {
                threshold: 2,
                valid: 1
            })
        ));
    }

    #[test]
    fn tampered_delegated_metadata_fails() {
        let key = TestKey::new();
        let mut metadata = signed(empty_targets(), &[&key]);

        metadata.signed.version += 1;

        let result = verify_delegated_signatures(&parent(&[&key], 1), "sensors", metadata);
        assert!(matches!(result, Err(Error::ThresholdNotMet { .. })));
    }
}

#[cfg(all(test, feature = "hash-sha256"))]
mod path_tests {
    use super::*;
    use alloc::{string::ToString, vec};

    use crate::schema::targets::DelegatedRole;

    fn role(
        paths: Option<alloc::vec::Vec<alloc::string::String>>,
        prefixes: Option<alloc::vec::Vec<alloc::string::String>>,
    ) -> DelegatedRole {
        DelegatedRole {
            name: "sensors".to_string(),
            keyids: vec![],
            threshold: 1,
            terminating: false,
            paths,
            path_hash_prefixes: prefixes,
        }
    }

    #[test]
    fn authorized_sensor_path_passes() {
        let r = role(Some(vec!["sensors/*".to_string()]), None);
        assert!(role_allows_path(&r, "sensors/temperature.bin"));
    }

    #[test]
    fn unauthorized_controller_path_fails() {
        let r = role(Some(vec!["sensors/*".to_string()]), None);
        assert!(!role_allows_path(&r, "controllers/motor.bin"));
    }

    #[test]
    fn wildcard_cannot_cross_directory() {
        let r = role(Some(vec!["sensors/*".to_string()]), None);
        assert!(!role_allows_path(&r, "sensors/subdir/firmware.bin"));
    }

    #[test]
    fn question_mark_matches_one_character() {
        let r = role(Some(vec!["firmware-?.bin".to_string()]), None);
        assert!(role_allows_path(&r, "firmware-a.bin"));
        assert!(!role_allows_path(&r, "firmware-alpha.bin"));
    }

    #[test]
    fn hash_prefix_authorizes_matching_target() {
        let path = "sensors/temperature.bin";
        let digest = stuf_env::crypto::sha256_hex(path.as_bytes());
        let prefix = digest[..8].to_string();

        let r = role(None, Some(vec![prefix]));
        assert!(role_allows_path(&r, path));
    }

    #[test]
    fn invalid_hash_prefix_fails_closed() {
        let r = role(None, Some(vec!["not-hex".to_string()]));
        assert!(!role_allows_path(&r, "sensors/temperature.bin"));
    }

    #[test]
    fn unrestricted_role_fails_closed() {
        let r = role(None, None);
        assert!(!role_allows_path(&r, "anything.bin"));
    }
}
