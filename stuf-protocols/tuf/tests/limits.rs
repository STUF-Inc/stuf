#![cfg(feature = "alloc")]

mod common;

use common::*;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;
use stuf_tuf::verify::limits::Limits;

// ── Size limits ───────────────────────────────────────────────────────────────

#[test]
fn default_limits_pass_normal_metadata() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", FIRMWARE.to_vec());

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(result.is_ok());
}

#[test]
fn oversized_root_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);

    // Set root limit absurdly low
    let limits = Limits::new(64, 2_048, 4_096, 16_384, 32, 16, 64);
    let transport = MockTransport::new();

    let result = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits);
    assert!(matches!(
        result,
        Err(Error::MetadataTooLarge { role: "root", .. })
    ));
}

#[test]
fn oversized_timestamp_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    // Set timestamp limit absurdly low
    let limits = Limits::new(16_384, 16, 4_096, 16_384, 32, 16, 64);
    let transport = MockTransport::new().with("timestamp.json", sign_timestamp(&ts, &tsk));

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    assert!(matches!(
        anchor.verify_timestamp(),
        Err(Error::MetadataTooLarge {
            role: "timestamp",
            ..
        })
    ));
}

#[test]
fn oversized_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);

    // Set snapshot limit absurdly low
    let limits = Limits::new(16_384, 2_048, 16, 16_384, 32, 16, 64);
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk));

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    assert!(matches!(
        anchor.verify_timestamp().unwrap().verify_snapshot(),
        Err(Error::MetadataTooLarge {
            role: "snapshot",
            ..
        })
    ));
}

#[test]
fn oversized_targets_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    // Set targets limit absurdly low
    let limits = Limits::new(16_384, 2_048, 4_096, 16, 32, 16, 64);
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk));

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    assert!(matches!(
        anchor
            .verify_timestamp()
            .unwrap()
            .verify_snapshot()
            .unwrap()
            .verify_targets(),
        Err(Error::MetadataTooLarge {
            role: "targets",
            ..
        })
    ));
}

// ── Structural limits ─────────────────────────────────────────────────────────

#[test]
fn too_many_keys_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);

    // Root has 4 keys, set limit to 2
    let limits = Limits::new(16_384, 2_048, 4_096, 16_384, 2, 16, 64);
    let transport = MockTransport::new();

    let result = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits);
    assert!(matches!(
        result,
        Err(Error::TooManyKeys {
            limit: 2,
            actual: 4
        })
    ));
}

#[test]
fn too_many_signatures_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);

    // Root has 1 signature, set limit to 0
    let limits = Limits::new(16_384, 2_048, 4_096, 16_384, 32, 0, 64);
    let transport = MockTransport::new();

    let result = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits);
    assert!(matches!(
        result,
        Err(Error::TooManySignatures {
            limit: 0,
            actual: 1
        })
    ));
}

#[test]
fn too_many_targets_entries_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    // Targets has 1 entry, set limit to 0
    let limits = Limits::new(16_384, 2_048, 4_096, 16_384, 32, 16, 0);
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk));

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    assert!(matches!(
        anchor
            .verify_timestamp()
            .unwrap()
            .verify_snapshot()
            .unwrap()
            .verify_targets(),
        Err(Error::TooManyTargets {
            limit: 0,
            actual: 1
        })
    ));
}

// ── Custom limits pass ────────────────────────────────────────────────────────

#[test]
fn generous_custom_limits_pass() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    // Very generous limits
    let limits = Limits::new(65_536, 65_536, 65_536, 65_536, 256, 256, 1024);
    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", FIRMWARE.to_vec());

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(result.is_ok());
}

#[test]
fn tight_but_sufficient_limits_pass() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);

    let ts_bytes = sign_timestamp(&ts, &tsk);
    let snap_bytes = sign_snapshot(&snap, &sk);
    let targets_bytes = sign_targets(&targets, &tk);

    // Set limits to exactly the size of the metadata
    let limits = Limits::new(
        root_bytes.len(),
        ts_bytes.len(),
        snap_bytes.len(),
        targets_bytes.len(),
        4, // exactly 4 keys
        1, // exactly 1 signature per metadata
        1, // exactly 1 target
    );

    let transport = MockTransport::new()
        .with("timestamp.json", ts_bytes)
        .with("snapshot.json", snap_bytes)
        .with("targets.json", targets_bytes)
        .with("firmware.bin", FIRMWARE.to_vec());

    let anchor = TrustAnchor::with_limits(&root_bytes, transport, FixedClock(NOW), limits).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(result.is_ok());
}
