#![cfg(feature = "alloc")]

mod common;

use common::*;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;

fn build_full_chain() -> (Vec<u8>, MockTransport) {
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

    (root_bytes, transport)
}

#[test]
fn full_chain_succeeds() {
    let (root_bytes, transport) = build_full_chain();
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
fn tampered_root_rejected() {
    let (mut root_bytes, transport) = build_full_chain();
    let mid = root_bytes.len() / 2;
    root_bytes[mid] ^= 0xff;
    assert!(TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).is_err());
}

#[test]
fn wrong_key_for_timestamp_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();
    let wrong_key = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);

    let transport = MockTransport::new().with("timestamp.json", sign_timestamp(&ts, &wrong_key));

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(anchor.verify_timestamp().is_err());
}

#[test]
fn expired_timestamp_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, PAST, 1);

    let transport = MockTransport::new().with("timestamp.json", sign_timestamp(&ts, &tsk));

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(anchor.verify_timestamp(), Err(Error::Expired)));
}

#[test]
fn expired_snapshot_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, PAST, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk));

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor.verify_timestamp().unwrap().verify_snapshot(),
        Err(Error::Expired)
    ));
}

#[test]
fn expired_targets_rejected() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);
    let targets = make_targets(FIRMWARE, PAST, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk));

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(
        anchor
            .verify_timestamp()
            .unwrap()
            .verify_snapshot()
            .unwrap()
            .verify_targets(),
        Err(Error::Expired)
    ));
}

#[test]
fn transport_error_propagated() {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let transport = MockTransport::new(); // empty — nothing available

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(matches!(anchor.verify_timestamp(), Err(Error::Transport)));
}

#[test]
fn mix_and_match_metadata_rejected() {
    let rk_a = TestKey::generate();
    let tk_a = TestKey::generate();
    let sk_a = TestKey::generate();
    let tsk_a = TestKey::generate();
    let sk_b = TestKey::generate();

    let root_a = make_root(&rk_a, &tk_a, &sk_a, &tsk_a, FAR_FUTURE, 1);
    let root_bytes_a = sign_root(&root_a, &rk_a);
    let ts_a = make_timestamp(1, FAR_FUTURE, 1);
    let snap_b = make_snapshot(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts_a, &tsk_a))
        .with("snapshot.json", sign_snapshot(&snap_b, &sk_b)); // wrong keys

    let anchor = TrustAnchor::new(&root_bytes_a, transport, FixedClock(NOW)).unwrap();
    assert!(anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .is_err());
}
