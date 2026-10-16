#![cfg(feature = "alloc")]

mod common;

use std::collections::BTreeMap;

use common::*;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_chain(firmware_in_targets: &[u8], firmware_served: &[u8]) -> (Vec<u8>, MockTransport) {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(firmware_in_targets, FAR_FUTURE, 1);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", firmware_served.to_vec());

    (root_bytes, transport)
}

/// Build a full chain with a custom Hashes for the firmware target.
fn build_chain_custom_target_hash(
    firmware: &[u8],
    sha256: Option<String>,
    sha512: Option<String>,
) -> (Vec<u8>, MockTransport) {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets_with_hash(firmware, sha256, sha512, FAR_FUTURE, 1);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", firmware.to_vec());

    (root_bytes, transport)
}

/// Build a chain where timestamp has a hash for snapshot.
#[allow(dead_code)]
fn build_chain_with_metadata_hashes() -> (Vec<u8>, MockTransport, TestKey, TestKey, TestKey, TestKey)
{
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);

    (root_bytes, MockTransport::new(), rk, tk, sk, tsk)
}

fn run_to_target(root_bytes: &[u8], transport: MockTransport) -> Result<(), Error> {
    let anchor = TrustAnchor::new(root_bytes, transport, FixedClock(NOW))?;
    anchor
        .verify_timestamp()?
        .verify_snapshot()?
        .verify_targets()?
        .verify_target("firmware.bin")?;
    Ok(())
}

fn run_to_snapshot(root_bytes: &[u8], transport: MockTransport) -> Result<(), Error> {
    let anchor = TrustAnchor::new(root_bytes, transport, FixedClock(NOW))?;
    anchor.verify_timestamp()?.verify_snapshot()?;
    Ok(())
}

fn run_to_targets(root_bytes: &[u8], transport: MockTransport) -> Result<(), Error> {
    let anchor = TrustAnchor::new(root_bytes, transport, FixedClock(NOW))?;
    anchor
        .verify_timestamp()?
        .verify_snapshot()?
        .verify_targets()?;
    Ok(())
}

// ── Existing: target hash/length checks ───────────────────────────────────────

#[test]
fn correct_hash_passes() {
    let (root_bytes, transport) = build_chain(FIRMWARE, FIRMWARE);
    assert!(run_to_target(&root_bytes, transport).is_ok());
}

#[test]
fn tampered_firmware_hash_rejected() {
    let tampered = b"TAMPERED_FIRMWARE_EVIL_EVIL_EVIL";
    let (root_bytes, transport) = build_chain(FIRMWARE, tampered);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::TargetHashMismatch)
    ));
}

#[test]
fn length_mismatch_rejected() {
    let longer = b"FIRMWARE_V1.1.0_GOLDEN_BROWN_PLUS_EXTRA_BYTES_APPENDED";
    let (root_bytes, transport) = build_chain(FIRMWARE, longer);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::TargetLengthMismatch { .. })
    ));
}

#[test]
fn unknown_target_rejected() {
    let (root_bytes, transport) = build_chain(FIRMWARE, FIRMWARE);
    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("does-not-exist.bin");
    assert!(matches!(result, Err(Error::TargetNotFound)));
}

// ── NEW: target hash length validation ────────────────────────────────────────

#[test]
fn truncated_sha256_in_targets_rejected() {
    // 32 hex chars instead of 64
    let short_hash = "abcd1234abcd1234abcd1234abcd1234".to_string();
    let (root_bytes, transport) = build_chain_custom_target_hash(FIRMWARE, Some(short_hash), None);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::InvalidHashLength {
            expected: 64,
            actual: 32
        })
    ));
}

#[test]
fn overlong_sha256_in_targets_rejected() {
    // 128 hex chars (sha512-length) in the sha256 field
    let long_hash = "a".repeat(128);
    let (root_bytes, transport) = build_chain_custom_target_hash(FIRMWARE, Some(long_hash), None);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::InvalidHashLength {
            expected: 64,
            actual: 128
        })
    ));
}

#[test]
fn empty_sha256_in_targets_rejected() {
    let (root_bytes, transport) =
        build_chain_custom_target_hash(FIRMWARE, Some(String::new()), None);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::InvalidHashLength {
            expected: 64,
            actual: 0
        })
    ));
}

#[test]
fn non_hex_sha256_in_targets_rejected() {
    // Correct length but contains non-hex chars
    let bad_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
    assert_eq!(bad_hex.len(), 64);
    let (root_bytes, transport) = build_chain_custom_target_hash(FIRMWARE, Some(bad_hex), None);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::InvalidHashEncoding)
    ));
}

#[test]
fn no_sha256_in_targets_rejected() {
    // Both hash fields are None — no supported hash
    let (root_bytes, transport) = build_chain_custom_target_hash(FIRMWARE, None, None);
    assert!(matches!(
        run_to_target(&root_bytes, transport),
        Err(Error::NoSupportedHash)
    ));
}

#[test]
fn correct_sha256_correct_length_passes() {
    // Explicitly construct the correct hash
    let hash = stuf_env::crypto::sha256_hex(FIRMWARE);
    assert_eq!(hash.len(), 64);
    let (root_bytes, transport) = build_chain_custom_target_hash(FIRMWARE, Some(hash), None);
    assert!(run_to_target(&root_bytes, transport).is_ok());
}

// ── NEW: metadata hash checks (timestamp→snapshot) ────────────────────────────

#[test]
fn correct_metadata_hash_timestamp_to_snapshot_passes() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let snap_bytes = sign_snapshot(&snap, &sk);

    let snap_hash = sha256_hash_map(&snap_bytes);
    let ts = make_timestamp_with_hash(
        1,
        FAR_FUTURE,
        1,
        Some(snap_hash),
        Some(snap_bytes.len() as u64),
    );

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", snap_bytes)
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", FIRMWARE.to_vec());

    assert!(run_to_target(&root_bytes, transport).is_ok());
}

#[test]
fn wrong_metadata_hash_timestamp_to_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let snap_bytes = sign_snapshot(&snap, &sk);

    // Correct length hash string, but wrong value
    let mut bad_hash = BTreeMap::new();
    bad_hash.insert("sha256".to_string(), "a".repeat(64));
    let ts = make_timestamp_with_hash(1, FAR_FUTURE, 1, Some(bad_hash), None);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", snap_bytes);

    assert!(matches!(
        run_to_snapshot(&root_bytes, transport),
        Err(Error::MetadataHashMismatch)
    ));
}

#[test]
fn truncated_metadata_hash_timestamp_to_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let snap_bytes = sign_snapshot(&snap, &sk);

    // Too-short hash in timestamp's snapshot meta
    let mut short_hash = BTreeMap::new();
    short_hash.insert("sha256".to_string(), "abcd1234".to_string());
    let ts = make_timestamp_with_hash(1, FAR_FUTURE, 1, Some(short_hash), None);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", snap_bytes);

    assert!(matches!(
        run_to_snapshot(&root_bytes, transport),
        Err(Error::InvalidHashLength { expected: 64, .. })
    ));
}

#[test]
fn non_hex_metadata_hash_timestamp_to_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let snap_bytes = sign_snapshot(&snap, &sk);

    let mut bad_hex = BTreeMap::new();
    bad_hex.insert("sha256".to_string(), "g".repeat(64));
    let ts = make_timestamp_with_hash(1, FAR_FUTURE, 1, Some(bad_hex), None);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", snap_bytes);

    assert!(matches!(
        run_to_snapshot(&root_bytes, transport),
        Err(Error::InvalidHashEncoding)
    ));
}

// ── NEW: metadata hash checks (snapshot→targets) ──────────────────────────────

#[test]
fn correct_metadata_hash_snapshot_to_targets_passes() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);
    let targets_bytes = sign_targets(&targets, &tk);

    let targets_hash = sha256_hash_map(&targets_bytes);
    let snap = make_snapshot_with_hash(
        1,
        FAR_FUTURE,
        1,
        Some(targets_hash),
        Some(targets_bytes.len() as u64),
    );
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", targets_bytes)
        .with("firmware.bin", FIRMWARE.to_vec());

    assert!(run_to_target(&root_bytes, transport).is_ok());
}

#[test]
fn wrong_metadata_hash_snapshot_to_targets_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);
    let targets_bytes = sign_targets(&targets, &tk);

    let mut bad_hash = BTreeMap::new();
    bad_hash.insert("sha256".to_string(), "b".repeat(64));
    let snap = make_snapshot_with_hash(1, FAR_FUTURE, 1, Some(bad_hash), None);
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", targets_bytes);

    assert!(matches!(
        run_to_targets(&root_bytes, transport),
        Err(Error::MetadataHashMismatch)
    ));
}

// ── NEW: metadata length checks ───────────────────────────────────────────────

#[test]
fn wrong_metadata_length_timestamp_to_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let snap_bytes = sign_snapshot(&snap, &sk);

    // Declare wrong length in timestamp
    let ts = make_timestamp_with_hash(1, FAR_FUTURE, 1, None, Some(1));

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", snap_bytes);

    assert!(matches!(
        run_to_snapshot(&root_bytes, transport),
        Err(Error::MetadataLengthMismatch { .. })
    ));
}

#[test]
fn wrong_metadata_length_snapshot_to_targets_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(FIRMWARE, FAR_FUTURE, 1);
    let targets_bytes = sign_targets(&targets, &tk);

    // Declare wrong length in snapshot
    let snap = make_snapshot_with_hash(1, FAR_FUTURE, 1, None, Some(1));
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", targets_bytes);

    assert!(matches!(
        run_to_targets(&root_bytes, transport),
        Err(Error::MetadataLengthMismatch { .. })
    ));
}
