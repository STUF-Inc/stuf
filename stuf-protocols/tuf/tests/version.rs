#![cfg(feature = "alloc")]

mod common;

use common::*;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;

fn build_transport(
    root_key: &TestKey,
    targets_key: &TestKey,
    snapshot_key: &TestKey,
    timestamp_key: &TestKey,
    ts_version: u32,
    snap_version: u32,
    targets_version: u32,
    ts_snap_version: u32,
    snap_targets_version: u32,
) -> (Vec<u8>, MockTransport) {
    let root = make_root(
        root_key,
        targets_key,
        snapshot_key,
        timestamp_key,
        FAR_FUTURE,
        1,
    );
    let root_bytes = sign_root(&root, root_key);
    let ts = make_timestamp(ts_snap_version, FAR_FUTURE, ts_version);
    let snap = make_snapshot(snap_targets_version, FAR_FUTURE, snap_version);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, targets_version);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, timestamp_key))
        .with("snapshot.json", sign_snapshot(&snap, snapshot_key))
        .with("targets.json", sign_targets(&targets, targets_key))
        .with("firmware.bin", FIRMWARE.to_vec());

    (root_bytes, transport)
}

#[test]
fn snapshot_rollback_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    // Timestamp expects snapshot v5 but we receive v1
    let (root_bytes, transport) = build_transport(&rk, &tk, &sk, &tsk, 1, 1, 1, 5, 1);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    let result = anchor.verify_timestamp().unwrap().verify_snapshot();
    assert!(matches!(
        result,
        Err(Error::VersionMismatch {
            expected: 5,
            received: 1
        })
    ));
}

#[test]
fn targets_rollback_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    // Snapshot expects targets v5 but we receive v1
    let (root_bytes, transport) = build_transport(&rk, &tk, &sk, &tsk, 1, 1, 1, 1, 5);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets();
    assert!(matches!(
        result,
        Err(Error::VersionMismatch {
            expected: 5,
            received: 1
        })
    ));
}

#[test]
fn equal_version_accepted() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let (root_bytes, transport) = build_transport(&rk, &tk, &sk, &tsk, 1, 1, 1, 1, 1);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets();
    assert!(result.is_ok());
}
