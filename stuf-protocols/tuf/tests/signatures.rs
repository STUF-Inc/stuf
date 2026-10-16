#![cfg(feature = "alloc")]

mod common;

use common::*;
use std::collections::BTreeMap;
use stuf_tuf::error::Error;
use stuf_tuf::schema::keys::KeyId;
use stuf_tuf::schema::role::RoleKeys;
use stuf_tuf::schema::signed::Signature;
use stuf_tuf::verify::signatures::verify_signatures;

#[test]
fn valid_ed25519_signature_passes() {
    let key = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key.key_id.clone(), key.public_key.clone());

    let canonical = b"test payload";
    let sig_hex = key.sign(canonical);
    let sigs = vec![Signature {
        keyid: key.key_id.clone(),
        sig: sig_hex,
    }];

    assert!(verify_signatures(&sigs, &key.role_keys(1), &available, canonical,).is_ok());
}

#[test]
fn tampered_payload_rejected() {
    let key = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key.key_id.clone(), key.public_key.clone());

    let canonical = b"original payload";
    let sig_hex = key.sign(canonical);
    let sigs = vec![Signature {
        keyid: key.key_id.clone(),
        sig: sig_hex,
    }];

    let result = verify_signatures(&sigs, &key.role_keys(1), &available, b"tampered payload");
    assert!(result.is_err());
}

#[test]
fn wrong_key_rejected() {
    let signing_key = TestKey::generate();
    let different_key = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(
        different_key.key_id.clone(),
        different_key.public_key.clone(),
    );

    let canonical = b"payload";
    let sig_hex = signing_key.sign(canonical);
    let sigs = vec![Signature {
        keyid: different_key.key_id.clone(),
        sig: sig_hex,
    }];

    assert!(verify_signatures(&sigs, &different_key.role_keys(1), &available, canonical,).is_err());
}

#[test]
fn threshold_not_met_rejected() {
    let key1 = TestKey::generate();
    let key2 = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key1.key_id.clone(), key1.public_key.clone());
    available.insert(key2.key_id.clone(), key2.public_key.clone());

    let role_keys = RoleKeys::new(vec![key1.key_id.clone(), key2.key_id.clone()], 2);
    let canonical = b"payload";
    let sigs = vec![Signature {
        keyid: key1.key_id.clone(),
        sig: key1.sign(canonical),
    }];

    let result = verify_signatures(&sigs, &role_keys, &available, canonical);
    assert!(matches!(
        result,
        Err(Error::ThresholdNotMet {
            threshold: 2,
            valid: 1
        })
    ));
}

#[test]
fn duplicate_sig_not_double_counted() {
    let key = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key.key_id.clone(), key.public_key.clone());

    let role_keys = RoleKeys::new(vec![key.key_id.clone()], 2);
    let canonical = b"payload";
    let sig_hex = key.sign(canonical);
    let sigs = vec![
        Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex.clone(),
        },
        Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex,
        },
    ];

    assert!(matches!(
        verify_signatures(&sigs, &role_keys, &available, canonical),
        Err(Error::ThresholdNotMet { .. })
    ));
}

#[test]
fn unknown_keyid_ignored() {
    let key = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key.key_id.clone(), key.public_key.clone());

    let canonical = b"payload";
    let sigs = vec![Signature {
        keyid: KeyId("unknown_key_id".to_string()),
        sig: key.sign(canonical),
    }];

    assert!(verify_signatures(&sigs, &key.role_keys(1), &available, canonical,).is_err());
}

#[test]
fn multi_key_threshold_met() {
    let key1 = TestKey::generate();
    let key2 = TestKey::generate();
    let mut available = BTreeMap::new();
    available.insert(key1.key_id.clone(), key1.public_key.clone());
    available.insert(key2.key_id.clone(), key2.public_key.clone());

    let role_keys = RoleKeys::new(vec![key1.key_id.clone(), key2.key_id.clone()], 2);
    let canonical = b"payload";
    let sigs = vec![
        Signature {
            keyid: key1.key_id.clone(),
            sig: key1.sign(canonical),
        },
        Signature {
            keyid: key2.key_id.clone(),
            sig: key2.sign(canonical),
        },
    ];

    assert!(verify_signatures(&sigs, &role_keys, &available, canonical).is_ok());
}
