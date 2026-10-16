#![cfg(feature = "alloc")]
#![cfg(feature = "tuf-delegation")]

mod common;

use common::*;
use std::collections::BTreeMap;

use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::schema::{
    snapshot::SnapshotMeta,
    targets::{DelegatedRole, Delegations, Hashes, Target},
};
use stuf_tuf::verify::chain::TrustAnchor;

const SENSOR: &[u8] = b"STUF_SENSOR_FIRMWARE_V1";

fn repository(target_path: &str, wrong_signer: bool) -> (Vec<u8>, MockTransport) {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();
    let dk = TestKey::generate();
    let attacker = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);

    let mut top = make_targets(FIRMWARE, FAR_FUTURE, 1);

    let mut keys = BTreeMap::new();
    keys.insert(dk.key_id.clone(), dk.public_key.clone());

    top.delegations = Some(Delegations {
        keys,
        roles: vec![DelegatedRole {
            name: "sensors".into(),
            keyids: vec![dk.key_id.clone()],
            threshold: 1,
            terminating: false,
            paths: Some(vec!["sensors/*".into()]),
            path_hash_prefixes: None,
        }],
    });

    let mut delegated = make_targets(FIRMWARE, FAR_FUTURE, 1);
    delegated.targets.clear();

    delegated.targets.insert(
        target_path.into(),
        Target {
            length: SENSOR.len() as u64,
            hashes: Hashes {
                sha256: Some(stuf_env::crypto::sha256_hex(SENSOR)),
                sha512: None,
            },
            custom: BTreeMap::new(),
        },
    );

    let delegated_bytes = sign_targets(&delegated, if wrong_signer { &attacker } else { &dk });

    let mut snapshot = make_snapshot(1, FAR_FUTURE, 1);

    snapshot.meta.insert(
        "sensors.json".into(),
        SnapshotMeta {
            version: 1,
            length: Some(delegated_bytes.len() as u64),
            hashes: Some(sha256_hash_map(&delegated_bytes)),
        },
    );

    let timestamp = make_timestamp(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&timestamp, &tsk))
        .with("snapshot.json", sign_snapshot(&snapshot, &sk))
        .with("targets.json", sign_targets(&top, &tk))
        .with("sensors.json", delegated_bytes)
        .with(target_path, SENSOR.to_vec());

    (sign_root(&root, &rk), transport)
}

#[test]
fn delegated_firmware_verifies_end_to_end() {
    let (root, transport) = repository("sensors/temperature.bin", false);

    let checked = TrustAnchor::new(&root, transport, FixedClock(NOW))
        .unwrap()
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap();

    assert!(checked
        .verify_target_delegated_one_level("sensors/temperature.bin")
        .is_ok());
}

#[test]
fn unauthorized_delegated_signer_rejected() {
    let (root, transport) = repository("sensors/temperature.bin", true);

    let checked = TrustAnchor::new(&root, transport, FixedClock(NOW))
        .unwrap()
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap();

    assert!(matches!(
        checked.verify_target_delegated_one_level("sensors/temperature.bin"),
        Err(Error::ThresholdNotMet { .. })
    ));
}

#[test]
fn delegated_role_cannot_escape_its_paths() {
    let (root, transport) = repository("controllers/motor.bin", false);

    let checked = TrustAnchor::new(&root, transport, FixedClock(NOW))
        .unwrap()
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap();

    assert!(matches!(
        checked.verify_target_delegated_one_level("controllers/motor.bin"),
        Err(Error::TargetNotFound)
    ));
}
