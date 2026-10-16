#![cfg(feature = "alloc")]
#![cfg(feature = "tuf-delegation")]

use stuf_tuf::schema::targets::DelegatedRole;

fn parse(json: &str) -> Result<DelegatedRole, serde_json::Error> {
    serde_json::from_str(json)
}

#[test]
fn explicit_paths_accepted() {
    let role = parse(
        r#"{
        "name": "sensors",
        "keyids": ["key1"],
        "threshold": 1,
        "terminating": false,
        "paths": ["sensors/*"]
    }"#,
    )
    .unwrap();

    assert_eq!(role.paths.unwrap(), vec!["sensors/*"]);
}

#[test]
fn hash_prefixes_accepted() {
    let role = parse(
        r#"{
        "name": "bins",
        "keyids": ["key1"],
        "threshold": 1,
        "path_hash_prefixes": ["ab", "cd"]
    }"#,
    )
    .unwrap();

    assert_eq!(role.path_hash_prefixes.unwrap(), vec!["ab", "cd"]);
}

#[test]
fn both_path_types_rejected() {
    assert!(parse(
        r#"{
        "name": "invalid",
        "keyids": ["key1"],
        "threshold": 1,
        "paths": ["*"],
        "path_hash_prefixes": ["ab"]
    }"#
    )
    .is_err());
}

#[test]
fn missing_paths_rejected() {
    assert!(parse(
        r#"{
        "name": "invalid",
        "keyids": ["key1"],
        "threshold": 1
    }"#
    )
    .is_err());
}

#[test]
fn zero_threshold_rejected() {
    assert!(parse(
        r#"{
        "name": "invalid",
        "keyids": ["key1"],
        "threshold": 0,
        "paths": ["*"]
    }"#
    )
    .is_err());
}

#[test]
fn empty_keys_rejected() {
    assert!(parse(
        r#"{
        "name": "invalid",
        "keyids": [],
        "threshold": 1,
        "paths": ["*"]
    }"#
    )
    .is_err());
}
