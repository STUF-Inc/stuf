#![cfg(feature = "alloc")]

mod common;

use common::*;
use stuf_tuf::schema::{
    role::RoleType, root::Root, signed::Signed, snapshot::Snapshot, targets::Targets,
    timestamp::Timestamp,
};

#[test]
fn root_roundtrip() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let bytes = serde_json::to_vec(&root).unwrap();
    let decoded: Root = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.role_type, "root");
    assert!(decoded.role_keys(&RoleType::Timestamp).is_some());
}

#[test]
fn timestamp_roundtrip() {
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let bytes = serde_json::to_vec(&ts).unwrap();
    let decoded: Timestamp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.version, 1);
    assert!(decoded.snapshot_meta().is_some());
    assert_eq!(decoded.snapshot_meta().unwrap().version, 1);
}

#[test]
fn snapshot_roundtrip() {
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let bytes = serde_json::to_vec(&snap).unwrap();
    let decoded: Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.meta_for("targets.json").is_some());
    assert_eq!(decoded.meta_for("targets.json").unwrap().version, 1);
}

#[test]
fn targets_roundtrip() {
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);
    let bytes = serde_json::to_vec(&targets).unwrap();
    let decoded: Targets = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.get_target("firmware.bin").is_some());
    assert_eq!(
        decoded.get_target("firmware.bin").unwrap().length,
        FIRMWARE.len() as u64
    );
}

#[test]
fn malformed_json_rejected() {
    let result: Result<Root, _> = serde_json::from_slice(b"not json at all {{{{");
    assert!(result.is_err());
}

#[test]
fn missing_required_field_rejected() {
    let result: Result<Signed<Root>, _> = serde_json::from_slice(b"{\"signed\": {}}");
    assert!(result.is_err());
}
