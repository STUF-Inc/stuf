#![cfg(feature = "alloc")]

mod common;

use common::*;
use serde::Serialize;
use stuf_env::clock::FixedClock;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;

// ── Key sorting ───────────────────────────────────────────────────────────────

#[test]
fn keys_sorted_alphabetically() {
    #[derive(Serialize)]
    struct Data {
        zebra: i32,
        alpha: i32,
        middle: i32,
    }
    let data = Data {
        zebra: 3,
        alpha: 1,
        middle: 2,
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"alpha":1,"middle":2,"zebra":3}"#);
}

#[test]
fn nested_objects_sorted_recursively() {
    #[derive(Serialize)]
    struct Inner {
        z: i32,
        a: i32,
    }
    #[derive(Serialize)]
    struct Outer {
        z_outer: Inner,
        a_outer: i32,
    }
    let data = Outer {
        z_outer: Inner { z: 2, a: 1 },
        a_outer: 0,
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"a_outer":0,"z_outer":{"a":1,"z":2}}"#);
}

#[test]
fn underscore_prefix_sorts_before_letters() {
    // TUF uses "_type" which should sort before "consistent_snapshot", "expires", etc.
    let data = serde_json::json!({
        "version": 1,
        "_type": "root",
        "expires": 9999,
        "consistent_snapshot": false
    });
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(s.starts_with(r#"{"_type":"root","consistent_snapshot":false"#));
}

// ── No whitespace ─────────────────────────────────────────────────────────────

#[test]
fn no_whitespace_in_output() {
    let data = serde_json::json!({
        "a": [1, 2, 3],
        "b": {"c": true}
    });
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert!(!s.contains(' '));
    assert!(!s.contains('\n'));
    assert!(!s.contains('\t'));
}

// ── Primitives ────────────────────────────────────────────────────────────────

#[test]
fn null_bool_integers() {
    let result = stuf_encoding::canonicalize(&serde_json::json!(null)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "null");

    let result = stuf_encoding::canonicalize(&serde_json::json!(true)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "true");

    let result = stuf_encoding::canonicalize(&serde_json::json!(false)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "false");

    let result = stuf_encoding::canonicalize(&serde_json::json!(42)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "42");

    let result = stuf_encoding::canonicalize(&serde_json::json!(0)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "0");

    let result = stuf_encoding::canonicalize(&serde_json::json!(-1)).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "-1");
}

#[test]
fn arrays_preserve_order() {
    let data = serde_json::json!([3, 1, 2]);
    let result = stuf_encoding::canonicalize(&data).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "[3,1,2]");
}

#[test]
fn empty_object_and_array() {
    let result = stuf_encoding::canonicalize(&serde_json::json!({})).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "{}");

    let result = stuf_encoding::canonicalize(&serde_json::json!([])).unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "[]");
}

// ── String escaping ───────────────────────────────────────────────────────────

#[test]
fn predefined_escapes() {
    #[derive(Serialize)]
    struct Data {
        s: String,
    }
    let data = Data {
        s: "tab\there\nnewline\rcarriage\\slash\"quote".to_string(),
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"s":"tab\there\nnewline\rcarriage\\slash\"quote"}"#);
}

#[test]
fn control_chars_hex_escaped() {
    #[derive(Serialize)]
    struct Data {
        s: String,
    }
    let data = Data {
        s: "\u{0001}\u{001f}".to_string(),
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"s":"\u0001\u001f"}"#);
}

#[test]
fn backspace_and_formfeed_escaped() {
    #[derive(Serialize)]
    struct Data {
        s: String,
    }
    let data = Data {
        s: "\u{0008}\u{000C}".to_string(),
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"s":"\b\f"}"#);
}

#[test]
fn non_ascii_passes_through_literal() {
    #[derive(Serialize)]
    struct Data {
        s: String,
    }
    let data = Data {
        s: "café".to_string(),
    };
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    assert_eq!(s, r#"{"s":"café"}"#);
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn deterministic_output() {
    let data = serde_json::json!({
        "z": 1,
        "a": 2,
        "m": {"z": true, "a": false}
    });
    let result1 = stuf_encoding::canonicalize(&data).unwrap();
    let result2 = stuf_encoding::canonicalize(&data).unwrap();
    assert_eq!(result1, result2);
}

#[test]
fn canonicalize_then_decode_then_canonicalize_is_stable() {
    let data = serde_json::json!({
        "version": 1,
        "_type": "timestamp",
        "expires": 1735689600,
        "meta": {"snapshot.json": {"version": 1}}
    });
    let canonical1 = stuf_encoding::canonicalize(&data).unwrap();
    let decoded: serde_json::Value = stuf_encoding::decode(&canonical1).unwrap();
    let canonical2 = stuf_encoding::canonicalize(&decoded).unwrap();
    assert_eq!(canonical1, canonical2);
}

// ── TUF-specific ──────────────────────────────────────────────────────────────

#[test]
fn tuf_root_metadata_canonical_form() {
    // Verify that TUF root metadata with _type field sorts correctly
    let data = serde_json::json!({
        "_type": "root",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": 9999999999u64,
        "consistent_snapshot": false,
        "keys": {},
        "roles": {}
    });
    let result = stuf_encoding::canonicalize(&data).unwrap();
    let s = std::str::from_utf8(&result).unwrap();
    // _type sorts first (underscore < letters in UTF-16)
    assert!(s.starts_with(r#"{"_type":"root""#));
    // consistent_snapshot before expires before keys
    let cs_pos = s.find("consistent_snapshot").unwrap();
    let exp_pos = s.find("expires").unwrap();
    let keys_pos = s.find("keys").unwrap();
    assert!(cs_pos < exp_pos);
    assert!(exp_pos < keys_pos);
}

#[test]
fn publisher_and_client_produce_same_canonical_bytes() {
    // Simulate what the publisher does (canonicalize then sign)
    // and what the client does (canonicalize then verify).
    // Both must produce identical bytes.
    use common::*;

    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);

    // Publisher side: canonicalize and sign
    let publisher_bytes = stuf_encoding::canonicalize(&root).unwrap();
    let sig = rk.sign(&publisher_bytes);

    // Client side: canonicalize the same struct
    let client_bytes = stuf_encoding::canonicalize(&root).unwrap();

    // Must be identical — this is why canonical JSON exists
    assert_eq!(publisher_bytes, client_bytes);

    // And the signature must verify against the client's bytes
    let verify_result = ed25519_dalek::VerifyingKey::from_bytes(
        &hex::decode(&rk.public_key.keyval.public)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
    .verify_strict(
        &client_bytes,
        &ed25519_dalek::Signature::from_bytes(&hex::decode(&sig).unwrap().try_into().unwrap()),
    );
    assert!(verify_result.is_ok());
}

// ── Negative tests ───────────────────────────────────────────────────────────

#[test]
fn decode_garbage_bytes_returns_error() {
    let result: Result<serde_json::Value, _> = stuf_encoding::decode(b"not json {{{{");
    assert!(result.is_err());
}

#[test]
fn decode_empty_bytes_returns_error() {
    let result: Result<serde_json::Value, _> = stuf_encoding::decode(b"");
    assert!(result.is_err());
}

#[test]
fn decode_truncated_json_returns_error() {
    let result: Result<serde_json::Value, _> = stuf_encoding::decode(b"{\"key\": \"val");
    assert!(result.is_err());
}

#[test]
fn decode_wrong_type_returns_error() {
    // Valid JSON, but wrong target type — array instead of object
    let result: Result<std::collections::BTreeMap<String, String>, _> =
        stuf_encoding::decode(b"[1,2,3]");
    assert!(result.is_err());
}

#[test]
fn decode_valid_json_succeeds() {
    let result: Result<serde_json::Value, _> = stuf_encoding::decode(b"{\"hello\":\"world\"}");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), serde_json::json!({"hello": "world"}));
}

#[test]
fn canonicalize_then_decode_roundtrips() {
    use common::*;

    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let bytes = stuf_encoding::canonicalize(&root).unwrap();
    let decoded: stuf_tuf::schema::root::Root = stuf_encoding::decode(&bytes).unwrap();
    assert_eq!(decoded.version, root.version);
    assert_eq!(decoded.role_type, root.role_type);
}

#[test]
fn chain_rejects_garbage_root_bytes() {
    // Encoding layer should reject before signatures are even checked
    let transport = common::MockTransport::new();
    let result = TrustAnchor::new(b"totally not json", transport, FixedClock(NOW));
    assert!(matches!(result, Err(Error::Deserialize)));
}

#[test]
fn chain_rejects_valid_json_wrong_schema() {
    // Valid JSON but not a Signed<Root> — encoding decodes but schema fails
    let transport = common::MockTransport::new();
    let result = TrustAnchor::new(b"{\"not\":\"a root\"}", transport, FixedClock(NOW));
    assert!(result.is_err());
}

#[test]
fn chain_rejects_truncated_metadata() {
    // Truncated JSON at every chain step
    let rk = common::TestKey::generate();
    let tk = common::TestKey::generate();
    let sk = common::TestKey::generate();
    let tsk = common::TestKey::generate();

    let root = common::make_root(&rk, &tk, &sk, &tsk, common::FAR_FUTURE, 1);
    let root_bytes = common::sign_root(&root, &rk);

    // Truncated timestamp
    let transport = common::MockTransport::new().with("timestamp.json", b"{\"signed\":{".to_vec());

    let anchor = TrustAnchor::new(&root_bytes, transport, FixedClock(NOW)).unwrap();
    assert!(anchor.verify_timestamp().is_err());
}
