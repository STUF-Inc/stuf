#![cfg(feature = "alloc")]

mod common;

use common::*;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;

// ── _type field validation ────────────────────────────────────────────────────

/// Helper: build valid signed metadata bytes, then mutate the _type field
/// at the JSON level and re-sign with the correct key.
fn sign_with_wrong_type(
    key: &TestKey,
    payload: &impl serde::Serialize,
    wrong_type: &str,
) -> Vec<u8> {
    // Serialize payload to JSON value, swap _type, re-sign
    let mut value = serde_json::to_value(payload).unwrap();
    value["_type"] = serde_json::Value::String(wrong_type.to_string());
    let canonical = stuf_encoding::canonicalize(&value).unwrap();
    let sig_hex = key.sign(&canonical);
    let envelope = serde_json::json!({
        "signed": value,
        "signatures": [{
            "keyid": key.key_id.0,
            "sig": sig_hex
        }]
    });
    serde_json::to_vec(&envelope).unwrap()
}

#[test]
fn root_with_wrong_type_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    // Sign root but with _type set to "timestamp"
    let bad_root_bytes = sign_with_wrong_type(&rk, &root, "timestamp");

    let result = TrustAnchor::new(&bad_root_bytes, MockTransport::new(), FixedClock(NOW));
    assert!(matches!(
        result,
        Err(Error::RoleTypeMismatch {
            expected: "root",
            ..
        })
    ));
}

#[test]
fn timestamp_with_wrong_type_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    // Sign timestamp metadata but with _type set to "snapshot"
    let bad_ts_bytes = sign_with_wrong_type(&tsk, &ts, "snapshot");
    let transport = MockTransport::new().with("timestamp.json", bad_ts_bytes);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor.verify_timestamp(),
        Err(Error::RoleTypeMismatch {
            expected: "timestamp",
            ..
        })
    ));
}

#[test]
fn snapshot_with_wrong_type_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);

    let bad_snap_bytes = sign_with_wrong_type(&sk, &snap, "targets");
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", bad_snap_bytes);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor.verify_timestamp().unwrap().verify_snapshot(),
        Err(Error::RoleTypeMismatch {
            expected: "snapshot",
            ..
        })
    ));
}

#[test]
fn targets_with_wrong_type_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    let bad_targets_bytes = sign_with_wrong_type(&tk, &targets, "root");
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", bad_targets_bytes);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor
            .verify_timestamp()
            .unwrap()
            .verify_snapshot()
            .unwrap()
            .verify_targets(),
        Err(Error::RoleTypeMismatch {
            expected: "targets",
            ..
        })
    ));
}

// ── spec_version validation ───────────────────────────────────────────────────

fn sign_with_bad_spec_version(key: &TestKey, payload: &impl serde::Serialize) -> Vec<u8> {
    let mut value = serde_json::to_value(payload).unwrap();
    value["spec_version"] = serde_json::Value::String("2.0.0".to_string());
    let canonical = stuf_encoding::canonicalize(&value).unwrap();
    let sig_hex = key.sign(&canonical);
    let envelope = serde_json::json!({
        "signed": value,
        "signatures": [{
            "keyid": key.key_id.0,
            "sig": sig_hex
        }]
    });
    serde_json::to_vec(&envelope).unwrap()
}

#[test]
fn root_with_spec_version_2_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let bad_root_bytes = sign_with_bad_spec_version(&rk, &root);

    let result = TrustAnchor::new(&bad_root_bytes, MockTransport::new(), FixedClock(NOW));
    assert!(matches!(result, Err(Error::UnsupportedSpecVersion)));
}

#[test]
fn timestamp_with_spec_version_2_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    let bad_ts_bytes = sign_with_bad_spec_version(&tsk, &ts);
    let transport = MockTransport::new().with("timestamp.json", bad_ts_bytes);

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor.verify_timestamp(),
        Err(Error::UnsupportedSpecVersion)
    ));
}

// ── Root expiry ───────────────────────────────────────────────────────────────

#[test]
fn expired_root_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, PAST, 1);
    let root_bytes = sign_root(&root, &rk);

    let result = TrustAnchor::new(&root_bytes, MockTransport::new(), FixedClock(NOW));
    assert!(matches!(result, Err(Error::Expired)));
}

#[test]
fn root_at_exact_expiry_boundary_accepted() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    // Clock exactly equals expiry — should pass (now > expires is the check)
    let root = make_root(&rk, &tk, &sk, &tsk, NOW, 1);
    let root_bytes = sign_root(&root, &rk);

    let result = TrustAnchor::new(&root_bytes, MockTransport::new(), FixedClock(NOW));
    assert!(result.is_ok());
}
