//! Fixed-capacity, borrowed TUF delegated-role definitions.
//!
//! Parsing is not authentication. These views become authoritative
//! only after the parent metadata has been verified.

use crate::error::{Error, Result};
use stuf_encoding::no_heap as enc;

const MAX_ROLES: usize = 8;
const MAX_KEYIDS: usize = 8;
const MAX_PATHS: usize = 8;

#[derive(Clone, Copy, Debug)]
pub(super) enum PathScope<'a> {
    Paths([&'a str; MAX_PATHS], usize),
    HashPrefixes([&'a str; MAX_PATHS], usize),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DelegatedRoleView<'a> {
    pub name: &'a str,
    pub keyids: [&'a str; MAX_KEYIDS],
    pub keyids_len: usize,
    pub threshold: u32,
    pub terminating: bool,
    pub scope: PathScope<'a>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DelegationsView<'a> {
    pub roles: [Option<DelegatedRoleView<'a>>; MAX_ROLES],
    pub roles_len: usize,
}

// This stage parses roles only. The separate delegations.keys
// authorization map will be parsed in the next increment.
pub(super) fn parse_roles<'a>(delegations: &'a [u8]) -> Result<DelegationsView<'a>> {
    let array = enc::field(delegations, "roles").map_err(|_| Error::Deserialize)?;

    let mut items = [&[][..]; MAX_ROLES];
    let count = enc::array_items(array, &mut items).map_err(|_| Error::Deserialize)?;

    let mut result = DelegationsView {
        roles: [None; MAX_ROLES],
        roles_len: 0,
    };

    for item in items.iter().take(count) {
        let name = get_str(item, "name")?;
        if name.is_empty()
            || result.roles[..result.roles_len]
                .iter()
                .flatten()
                .any(|r| r.name == name)
        {
            return Err(Error::Deserialize);
        }

        let threshold = get_u64(item, "threshold")?;
        let key_array = enc::field(item, "keyids").map_err(|_| Error::Deserialize)?;

        let mut raw_ids = [&[][..]; MAX_KEYIDS];
        let id_count = enc::array_items(key_array, &mut raw_ids).map_err(|_| Error::Deserialize)?;

        if threshold == 0 || threshold > id_count as u64 {
            return Err(Error::NoKeysForRole);
        }

        let threshold = u32::try_from(threshold).map_err(|_| Error::NoKeysForRole)?;

        let mut keyids = [""; MAX_KEYIDS];
        for (i, raw) in raw_ids.iter().take(id_count).enumerate() {
            let keyid = enc::as_str(raw).map_err(|_| Error::Deserialize)?;
            if keyid.is_empty() || keyids[..i].contains(&keyid) {
                return Err(Error::NoKeysForRole);
            }
            keyids[i] = keyid;
        }

        let terminating = enc::field(item, "terminating")
            .and_then(enc::as_bool)
            .map_err(|_| Error::Deserialize)?;

        let paths = enc::field(item, "paths").ok();
        let prefixes = enc::field(item, "path_hash_prefixes").ok();

        let (raw, hashed) = match (paths, prefixes) {
            (Some(p), None) => (p, false),
            (None, Some(p)) => (p, true),
            _ => return Err(Error::Deserialize),
        };

        let mut raw_paths = [&[][..]; MAX_PATHS];
        let path_count = enc::array_items(raw, &mut raw_paths).map_err(|_| Error::Deserialize)?;

        if path_count == 0 {
            return Err(Error::Deserialize);
        }

        let mut values = [""; MAX_PATHS];
        for (i, raw_path) in raw_paths.iter().take(path_count).enumerate() {
            let value = enc::as_str(raw_path).map_err(|_| Error::Deserialize)?;

            if value.is_empty() {
                return Err(Error::Deserialize);
            }

            if hashed && (value.len() > 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(Error::Deserialize);
            }

            values[i] = value;
        }

        let scope = if hashed {
            PathScope::HashPrefixes(values, path_count)
        } else {
            PathScope::Paths(values, path_count)
        };

        result.roles[result.roles_len] = Some(DelegatedRoleView {
            name,
            keyids,
            keyids_len: id_count,
            threshold,
            terminating,
            scope,
        });
        result.roles_len += 1;
    }

    Ok(result)
}

fn get_str<'a>(obj: &'a [u8], name: &str) -> Result<&'a str> {
    enc::field(obj, name)
        .and_then(enc::as_str)
        .map_err(|_| Error::Deserialize)
}

fn get_u64(obj: &[u8], name: &str) -> Result<u64> {
    enc::field(obj, name)
        .and_then(enc::as_u64)
        .map_err(|_| Error::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_role_is_borrowed() {
        let json = br#"{
            "roles":[{
                "name":"sensors",
                "keyids":["k1","k2"],
                "threshold":2,
                "terminating":false,
                "paths":["sensors/*"]
            }]
        }"#;

        let parsed = parse_roles(json).unwrap();
        assert_eq!(parsed.roles_len, 1);
        let role = parsed.roles[0].unwrap();
        assert_eq!(role.name, "sensors");
        assert_eq!(role.threshold, 2);
        assert_eq!(role.keyids_len, 2);
        assert!(!role.terminating);
        match role.scope {
            PathScope::Paths(paths, n) => {
                assert_eq!(n, 1);
                assert_eq!(paths[0], "sensors/*");
            }
            _ => panic!("wrong path scope"),
        }
    }

    #[test]
    fn rejects_duplicate_signing_keys() {
        let json = br#"{"roles":[{
            "name":"sensors",
            "keyids":["k1","k1"],
            "threshold":2,
            "terminating":false,
            "paths":["sensors/*"]
        }]}"#;
        assert!(parse_roles(json).is_err());
    }

    #[test]
    fn rejects_unrestricted_role() {
        let json = br#"{"roles":[{
            "name":"sensors",
            "keyids":["k1"],
            "threshold":1,
            "terminating":false
        }]}"#;
        assert!(parse_roles(json).is_err());
    }

    #[test]
    fn rejects_oversized_role_array() {
        let json = br#"{"roles":[{},{},{},{},{},{},{},{},{}]}"#;
        assert!(parse_roles(json).is_err());
    }
}
