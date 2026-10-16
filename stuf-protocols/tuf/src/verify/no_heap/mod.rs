//! Feature-gated no-heap TUF verifier backend.
//!
//! This module owns only TUF-specific interpretation. Generic no-heap JSON/JCS
//! scanning lives in `stuf-encoding::no_heap`.

#[cfg(feature = "tuf-delegation")]
mod delegations;

use stuf_core::trust::Verified;
use stuf_encoding::no_heap as enc;

use stuf_env::{clock::Clock, transport::Transport};

use crate::{
    error::{Error, Result},
    verify::limits::Limits,
};

const MAX_KEYS: usize = 8;
const MAX_ROLE_KEYIDS: usize = 8;
const MAX_SIGNATURES: usize = 8;
const MAX_TARGETS: usize = 8;
const MAX_OBJECT_FIELDS: usize = 32;
const MAX_CANONICAL_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyType {
    Ed25519,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Ed25519,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoleName {
    Root,
    Timestamp,
    Snapshot,
    Targets,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct KeyView<'a> {
    keyid: &'a str,
    keytype: KeyType,
    scheme: Scheme,
    public: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RoleKeysView<'a> {
    keyids: [&'a str; MAX_ROLE_KEYIDS],
    keyids_len: usize,
    threshold: u32,
}

#[derive(Clone, Copy, Debug)]
struct SignatureView<'a> {
    keyid: &'a str,
    sig: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct MetaView<'a> {
    version: u32,
    length: Option<u64>,
    sha256: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct TargetView<'a> {
    pub name: &'a str,
    pub length: u64,
    pub sha256: &'a str,
}

#[derive(Clone, Copy, Debug)]
struct RootView<'a> {
    #[allow(dead_code)]
    expires: u64,
    #[allow(dead_code)]
    version: u32,
    keys: [Option<KeyView<'a>>; MAX_KEYS],
    keys_len: usize,
    roles: [Option<RoleKeysView<'a>>; 4],
}

#[derive(Clone, Copy, Debug)]
struct TimestampView<'a> {
    expires: u64,
    #[allow(dead_code)]
    version: u32,
    snapshot: MetaView<'a>,
}
#[derive(Clone, Copy, Debug)]
struct SnapshotView<'a> {
    expires: u64,
    version: u32,
    targets: MetaView<'a>,
    #[cfg(feature = "tuf-delegation")]
    meta_raw: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
struct TargetsView<'a> {
    expires: u64,
    version: u32,
    targets: [Option<TargetView<'a>>; MAX_TARGETS],
    targets_len: usize,
    #[cfg(feature = "tuf-delegation")]
    delegations_raw: Option<&'a [u8]>,
}

/// Entry point for no-heap verification.
pub struct TrustAnchor<'root, T, C>
where
    T: Transport,
    C: Clock,
{
    root: RootView<'root>,
    transport: T,
    clock: C,
    limits: Limits,
}

pub struct TimestampChecked<'root, 'ts, T, C>
where
    T: Transport,
    C: Clock,
{
    root: RootView<'root>,
    timestamp: TimestampView<'ts>,
    transport: T,
    clock: C,
    limits: Limits,
}

pub struct SnapshotChecked<'root, 'snap, T, C>
where
    T: Transport,
    C: Clock,
{
    root: RootView<'root>,
    snapshot: SnapshotView<'snap>,
    transport: T,
    clock: C,
    limits: Limits,
}

pub struct TargetsChecked<'root, 'snap, 'targets, T, C>
where
    T: Transport,
    C: Clock,
{
    #[allow(dead_code)]
    root: RootView<'root>,
    #[allow(dead_code)]
    snapshot: SnapshotView<'snap>,
    targets: TargetsView<'targets>,
    #[allow(dead_code)]
    transport: T,
    #[allow(dead_code)]
    clock: C,
    #[allow(dead_code)]
    limits: Limits,
}

fn check_size(bytes: &[u8], max: usize, role: &'static str) -> Result<()> {
    if bytes.len() > max {
        Err(Error::MetadataTooLarge {
            role,
            limit: max,
            actual: bytes.len(),
        })
    } else {
        Ok(())
    }
}

impl<'root, T, C> TrustAnchor<'root, T, C>
where
    T: Transport,
    C: Clock,
{
    pub fn new(root_bytes: &'root [u8], transport: T, clock: C) -> Result<Self> {
        Self::with_limits(root_bytes, transport, clock, Limits::default())
    }

    pub fn with_limits(
        root_bytes: &'root [u8],
        transport: T,
        clock: C,
        limits: Limits,
    ) -> Result<Self> {
        check_size(root_bytes, limits.max_root_bytes, "root")?;
        let signed = signed_payload(root_bytes)?;
        let sigs = signatures(root_bytes)?;
        let root = parse_root(signed, &limits)?;
        verify_role_signatures(signed, sigs, &root, RoleName::Root, &limits)?;

        // SECURITY: Check root expiry. See heap chain comment for rationale.
        check_expiry(root.expires, &clock)?;

        Ok(Self {
            root,
            transport,
            clock,
            limits,
        })
    }

    pub fn verify_timestamp(self) -> Result<TimestampChecked<'root, 'static, T, C>> {
        Err(Error::Transport)
    }

    pub fn verify_timestamp_bytes<'ts>(
        self,
        bytes: &'ts [u8],
    ) -> Result<TimestampChecked<'root, 'ts, T, C>> {
        check_size(bytes, self.limits.max_timestamp_bytes, "timestamp")?;
        let signed = signed_payload(bytes)?;
        let sigs = signatures(bytes)?;
        verify_role_signatures(signed, sigs, &self.root, RoleName::Timestamp, &self.limits)?;
        let timestamp = parse_timestamp(signed)?;
        check_expiry(timestamp.expires, &self.clock)?;
        Ok(TimestampChecked {
            root: self.root,
            timestamp,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

impl<'root, 'ts, T, C> TimestampChecked<'root, 'ts, T, C>
where
    T: Transport,
    C: Clock,
{
    pub fn verify_snapshot(self) -> Result<SnapshotChecked<'root, 'static, T, C>> {
        Err(Error::Transport)
    }

    pub fn verify_snapshot_bytes<'snap>(
        self,
        bytes: &'snap [u8],
    ) -> Result<SnapshotChecked<'root, 'snap, T, C>> {
        check_size(bytes, self.limits.max_snapshot_bytes, "snapshot")?;
        verify_metadata_ref(bytes, self.timestamp.snapshot)?;
        let signed = signed_payload(bytes)?;
        let sigs = signatures(bytes)?;
        verify_role_signatures(signed, sigs, &self.root, RoleName::Snapshot, &self.limits)?;
        let snapshot = parse_snapshot(signed)?;
        if snapshot.version != self.timestamp.snapshot.version {
            return Err(Error::VersionMismatch {
                expected: self.timestamp.snapshot.version,
                received: snapshot.version,
            });
        }
        check_expiry(snapshot.expires, &self.clock)?;
        Ok(SnapshotChecked {
            root: self.root,
            snapshot,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

impl<'root, 'snap, T, C> SnapshotChecked<'root, 'snap, T, C>
where
    T: Transport,
    C: Clock,
{
    pub fn verify_targets(self) -> Result<TargetsChecked<'root, 'snap, 'static, T, C>> {
        Err(Error::Transport)
    }

    pub fn verify_targets_bytes<'targets>(
        self,
        bytes: &'targets [u8],
    ) -> Result<TargetsChecked<'root, 'snap, 'targets, T, C>> {
        check_size(bytes, self.limits.max_targets_bytes, "targets")?;
        verify_metadata_ref(bytes, self.snapshot.targets)?;
        let signed = signed_payload(bytes)?;
        let sigs = signatures(bytes)?;
        verify_role_signatures(signed, sigs, &self.root, RoleName::Targets, &self.limits)?;
        let targets = parse_targets(signed, &self.limits)?;
        if targets.version != self.snapshot.targets.version {
            return Err(Error::VersionMismatch {
                expected: self.snapshot.targets.version,
                received: targets.version,
            });
        }
        check_expiry(targets.expires, &self.clock)?;
        Ok(TargetsChecked {
            root: self.root,
            snapshot: self.snapshot,
            targets,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

impl<'root, 'snap, 'targets, T, C> TargetsChecked<'root, 'snap, 'targets, T, C>
where
    T: Transport,
    C: Clock,
{
    pub fn verify_target(&self, _name: &str) -> Result<Verified<TargetView<'targets>>> {
        Err(Error::Transport)
    }

    pub fn verify_target_bytes(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<Verified<TargetView<'targets>>> {
        let t = self.find_target(name).ok_or(Error::TargetNotFound)?;
        if bytes.len() as u64 != t.length {
            return Err(Error::TargetLengthMismatch {
                expected: t.length,
                actual: bytes.len() as u64,
            });
        }
        verify_sha256_hex(bytes, t.sha256)?;
        Ok(Verified::new(t))
    }

    /// Authenticate and verify a one-level delegated firmware target.
    ///
    /// Delegation authority originates in authenticated parent
    /// targets and snapshot metadata.
    ///
    /// Recursive traversal and persistent rollback tracking
    /// are not implemented by this method.
    #[cfg(feature = "tuf-delegation")]
    pub fn verify_delegated_target_bytes<'delegate>(
        &self,
        role_name: &str,
        metadata: &'delegate [u8],
        target_name: &str,
        firmware: &[u8],
    ) -> Result<Verified<TargetView<'delegate>>> {
        // A delegated role cannot override a top-level target.
        if self.find_target(target_name).is_some() {
            return Err(Error::TargetNotFound);
        }

        // Read delegation authority from the verified parent.
        let parent_raw = self.targets.delegations_raw.ok_or(Error::NoKeysForRole)?;

        let parent = delegations::parse_delegations(parent_raw)?;

        // Respect the parent's delegation order and terminating roles.
        let mut selected = false;

        for candidate in parent.roles[..parent.roles_len].iter().flatten() {
            if delegated_scope_allows(candidate.scope, target_name) {
                if candidate.name == role_name {
                    selected = true;
                    break;
                }

                if candidate.terminating {
                    return Err(Error::TargetNotFound);
                }
            }
        }

        if !selected {
            return Err(Error::TargetNotFound);
        }

        // The snapshot reference is part of verified metadata.
        let reference = delegated_snapshot_ref(self.snapshot.meta_raw, role_name)?;

        check_size(metadata, self.limits.max_targets_bytes, "targets")?;

        verify_metadata_ref(metadata, reference)?;

        // Verify the delegated role's signatures and threshold.
        verify_delegated_signatures_bytes(&parent, role_name, metadata, &self.limits)?;

        let signed = signed_payload(metadata)?;
        let child = parse_targets(signed, &self.limits)?;

        if child.version != reference.version {
            return Err(Error::VersionMismatch {
                expected: reference.version,
                received: child.version,
            });
        }

        check_expiry(child.expires, &self.clock)?;

        let target = child.targets[..child.targets_len]
            .iter()
            .flatten()
            .find(|t| t.name == target_name)
            .copied()
            .ok_or(Error::TargetNotFound)?;

        if firmware.len() as u64 != target.length {
            return Err(Error::TargetLengthMismatch {
                expected: target.length,
                actual: firmware.len() as u64,
            });
        }

        verify_sha256_hex(firmware, target.sha256)?;

        Ok(Verified::new(target))
    }

    pub fn find_target(&self, name: &str) -> Option<TargetView<'targets>> {
        for i in 0..self.targets.targets_len {
            if let Some(t) = self.targets.targets[i] {
                if t.name == name {
                    return Some(t);
                }
            }
        }
        None
    }
}

#[cfg(feature = "tuf-delegation")]
fn delegated_snapshot_ref<'a>(meta: &'a [u8], role_name: &str) -> Result<MetaView<'a>> {
    if role_name.is_empty()
        || role_name.contains('/')
        || role_name.contains('\\')
        || role_name == "."
        || role_name == ".."
        || role_name.ends_with(".json")
    {
        return Err(Error::SnapshotMismatch);
    }

    let mut entries = [empty_entry(); MAX_OBJECT_FIELDS];

    let count = enc::object_entries(meta, &mut entries).map_err(|_| Error::SnapshotMismatch)?;

    let mut found = None;

    for entry in entries.iter().take(count) {
        if entry.key.strip_suffix(".json") == Some(role_name) {
            if found.is_some() {
                return Err(Error::SnapshotMismatch);
            }

            found = Some(parse_meta(entry.value)?);
        }
    }

    found.ok_or(Error::SnapshotMismatch)
}

#[cfg(feature = "tuf-delegation")]
fn delegated_scope_allows(scope: delegations::PathScope<'_>, target: &str) -> bool {
    match scope {
        delegations::PathScope::Paths(patterns, count) => patterns[..count]
            .iter()
            .any(|pattern| crate::verify::delegation_rules::matches_path_pattern(pattern, target)),

        delegations::PathScope::HashPrefixes(prefixes, count) => {
            let digest = stuf_env::crypto::sha256_hex(target.as_bytes());

            prefixes[..count].iter().any(|prefix| {
                !prefix.is_empty()
                    && digest
                        .get(..prefix.len())
                        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
            })
        }
    }
}

fn signed_payload(bytes: &[u8]) -> Result<&[u8]> {
    enc::field(bytes, "signed").map_err(|_| Error::Deserialize)
}
fn signatures(bytes: &[u8]) -> Result<&[u8]> {
    enc::field(bytes, "signatures").map_err(|_| Error::Deserialize)
}

fn check_expiry<C: Clock>(expires: u64, clock: &C) -> Result<()> {
    if clock.now_secs() > expires {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}

fn role_label(type_str: &str) -> &'static str {
    match type_str {
        "root" => "root",
        "timestamp" => "timestamp",
        "snapshot" => "snapshot",
        "targets" => "targets",
        _ => "unknown",
    }
}

fn parse_root<'a>(signed: &'a [u8], limits: &Limits) -> Result<RootView<'a>> {
    // TUF spec: verify _type field matches expected role
    let type_str = get_str(signed, "_type")?;
    if type_str != "root" {
        return Err(Error::role_type_mismatch("root", role_label(type_str)));
    }
    // TUF spec: reject unsupported major versions
    let spec_version = get_str(signed, "spec_version")?;
    if !spec_version.starts_with("1.") {
        return Err(Error::UnsupportedSpecVersion);
    }
    let expires = get_u64(signed, "expires")?;
    let version = get_u64(signed, "version")? as u32;
    let mut root = RootView {
        expires,
        version,
        keys: [None; MAX_KEYS],
        keys_len: 0,
        roles: [None; 4],
    };

    let keys_obj = enc::field(signed, "keys").map_err(|_| Error::Deserialize)?;
    let mut entries = [empty_entry(); MAX_OBJECT_FIELDS];
    let n = enc::object_entries(keys_obj, &mut entries).map_err(|_| Error::Deserialize)?;
    if n > limits.max_keys || n > MAX_KEYS {
        return Err(Error::TooManyKeys {
            limit: limits.max_keys.min(MAX_KEYS),
            actual: n,
        });
    }
    for e in entries.iter().take(n) {
        root.keys[root.keys_len] = Some(parse_key(e.key, e.value)?);
        root.keys_len += 1;
    }

    let roles_obj = enc::field(signed, "roles").map_err(|_| Error::Deserialize)?;
    let n = enc::object_entries(roles_obj, &mut entries).map_err(|_| Error::Deserialize)?;
    for e in entries.iter().take(n) {
        let role = match e.key {
            "root" => RoleName::Root,
            "timestamp" => RoleName::Timestamp,
            "snapshot" => RoleName::Snapshot,
            "targets" => RoleName::Targets,
            _ => continue,
        };
        root.roles[role_index(role)] = Some(parse_role_keys(role, e.value)?);
    }
    Ok(root)
}

fn parse_key<'a>(keyid: &'a str, value: &'a [u8]) -> Result<KeyView<'a>> {
    let keytype = match get_str(value, "keytype")? {
        "ed25519" => KeyType::Ed25519,
        _ => KeyType::Other,
    };
    let scheme = match get_str(value, "scheme")? {
        "ed25519" => Scheme::Ed25519,
        _ => Scheme::Other,
    };
    let keyval = enc::field(value, "keyval").map_err(|_| Error::Deserialize)?;
    let public_hex = get_str(keyval, "public")?;
    let mut public = [0u8; 32];
    hex_to_bytes(public_hex, &mut public).map_err(|_| Error::UnsupportedKeyType)?;
    Ok(KeyView {
        keyid,
        keytype,
        scheme,
        public,
    })
}

fn parse_role_keys<'a>(_role: RoleName, value: &'a [u8]) -> Result<RoleKeysView<'a>> {
    let threshold = get_u64(value, "threshold")? as u32;
    let keyids_array = enc::field(value, "keyids").map_err(|_| Error::Deserialize)?;
    let mut items = [&[][..]; MAX_ROLE_KEYIDS];
    let len = enc::array_items(keyids_array, &mut items).map_err(|_| Error::TooManyKeys {
        limit: MAX_ROLE_KEYIDS,
        actual: MAX_ROLE_KEYIDS + 1,
    })?;
    let mut keyids = [""; MAX_ROLE_KEYIDS];
    for i in 0..len {
        keyids[i] = enc::as_str(items[i]).map_err(|_| Error::Deserialize)?;
    }
    Ok(RoleKeysView {
        keyids,
        keyids_len: len,
        threshold,
    })
}

fn parse_timestamp<'a>(signed: &'a [u8]) -> Result<TimestampView<'a>> {
    let type_str = get_str(signed, "_type")?;
    if type_str != "timestamp" {
        return Err(Error::role_type_mismatch("timestamp", role_label(type_str)));
    }
    let spec_version = get_str(signed, "spec_version")?;
    if !spec_version.starts_with("1.") {
        return Err(Error::UnsupportedSpecVersion);
    }
    let expires = get_u64(signed, "expires")?;
    let version = get_u64(signed, "version")? as u32;
    let meta = enc::field(signed, "meta").map_err(|_| Error::Deserialize)?;
    let snap = enc::field(meta, "snapshot.json").map_err(|_| Error::SnapshotMismatch)?;
    Ok(TimestampView {
        expires,
        version,
        snapshot: parse_meta(snap)?,
    })
}

fn parse_snapshot<'a>(signed: &'a [u8]) -> Result<SnapshotView<'a>> {
    let type_str = get_str(signed, "_type")?;
    if type_str != "snapshot" {
        return Err(Error::role_type_mismatch("snapshot", role_label(type_str)));
    }
    let spec_version = get_str(signed, "spec_version")?;
    if !spec_version.starts_with("1.") {
        return Err(Error::UnsupportedSpecVersion);
    }
    let expires = get_u64(signed, "expires")?;
    let version = get_u64(signed, "version")? as u32;
    let meta = enc::field(signed, "meta").map_err(|_| Error::Deserialize)?;
    let targets = enc::field(meta, "targets.json").map_err(|_| Error::SnapshotMismatch)?;
    Ok(SnapshotView {
        expires,
        version,
        targets: parse_meta(targets)?,
        #[cfg(feature = "tuf-delegation")]
        meta_raw: meta,
    })
}

fn parse_meta<'a>(bytes: &'a [u8]) -> Result<MetaView<'a>> {
    let version = get_u64(bytes, "version")? as u32;
    let length = match enc::field(bytes, "length") {
        Ok(v) => Some(enc::as_u64(v).map_err(|_| Error::Deserialize)?),
        Err(_) => None,
    };
    let hashes = enc::field(bytes, "hashes").ok();
    let sha256 = match hashes {
        Some(h) => enc::field(h, "sha256")
            .ok()
            .map(|v| enc::as_str(v).map_err(|_| Error::Deserialize))
            .transpose()?,
        None => None,
    };
    Ok(MetaView {
        version,
        length,
        sha256,
    })
}

fn parse_targets<'a>(signed: &'a [u8], limits: &Limits) -> Result<TargetsView<'a>> {
    let type_str = get_str(signed, "_type")?;
    if type_str != "targets" {
        return Err(Error::role_type_mismatch("targets", role_label(type_str)));
    }
    let spec_version = get_str(signed, "spec_version")?;
    if !spec_version.starts_with("1.") {
        return Err(Error::UnsupportedSpecVersion);
    }
    let expires = get_u64(signed, "expires")?;
    let version = get_u64(signed, "version")? as u32;
    let targets_obj = enc::field(signed, "targets").map_err(|_| Error::Deserialize)?;
    let mut entries = [empty_entry(); MAX_OBJECT_FIELDS];
    let n = enc::object_entries(targets_obj, &mut entries).map_err(|_| Error::Deserialize)?;
    if n > limits.max_targets_entries || n > MAX_TARGETS {
        return Err(Error::TooManyTargets {
            limit: limits.max_targets_entries.min(MAX_TARGETS),
            actual: n,
        });
    }
    let mut out = TargetsView {
        expires,
        version,
        targets: [None; MAX_TARGETS],
        targets_len: 0,
        #[cfg(feature = "tuf-delegation")]
        delegations_raw: enc::field(signed, "delegations").ok(),
    };
    for e in entries.iter().take(n) {
        let length = get_u64(e.value, "length")?;
        let hashes = enc::field(e.value, "hashes").map_err(|_| Error::Deserialize)?;
        let sha256 = get_str(hashes, "sha256")?;
        out.targets[out.targets_len] = Some(TargetView {
            name: e.key,
            length,
            sha256,
        });
        out.targets_len += 1;
    }
    Ok(out)
}

fn empty_entry<'a>() -> enc::ObjectEntry<'a> {
    enc::ObjectEntry {
        key: "",
        raw_key: &[],
        value: &[],
    }
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

fn role_index(role: RoleName) -> usize {
    match role {
        RoleName::Root => 0,
        RoleName::Timestamp => 1,
        RoleName::Snapshot => 2,
        RoleName::Targets => 3,
    }
}

fn role_keys<'a>(root: &'a RootView<'a>, role: RoleName) -> Result<RoleKeysView<'a>> {
    root.roles[role_index(role)].ok_or(Error::NoKeysForRole)
}

fn find_key_in<'a>(
    keys: &[Option<KeyView<'a>>],
    keys_len: usize,
    keyid: &str,
) -> Option<KeyView<'a>> {
    for key in keys.iter().take(keys_len).flatten() {
        if key.keyid == keyid {
            return Some(*key);
        }
    }
    None
}

fn parse_signatures<'a, const N: usize>(
    array: &'a [u8],
    out: &mut [Option<SignatureView<'a>>; N],
) -> Result<usize> {
    let mut items = [&[][..]; MAX_SIGNATURES];
    let len = enc::array_items(array, &mut items).map_err(|_| Error::TooManySignatures {
        limit: N,
        actual: N + 1,
    })?;
    if len > N {
        return Err(Error::TooManySignatures {
            limit: N,
            actual: len,
        });
    }
    for i in 0..len {
        let keyid = get_str(items[i], "keyid")?;
        let sig_hex = get_str(items[i], "sig")?;
        let mut sig = [0u8; 64];
        hex_to_bytes(sig_hex, &mut sig).map_err(|_| Error::UnsupportedKeyType)?;
        out[i] = Some(SignatureView { keyid, sig });
    }
    Ok(len)
}

fn verify_role_signatures(
    signed_payload: &[u8],
    signatures_array: &[u8],
    root: &RootView<'_>,
    role: RoleName,
    limits: &Limits,
) -> Result<()> {
    let authorized = role_keys(root, role)?;

    verify_signatures_with_keys(
        signed_payload,
        signatures_array,
        authorized,
        &root.keys,
        root.keys_len,
        limits,
    )
}

/// Verify a signed payload against an explicitly authorized key set.
///
/// The caller is responsible for authenticating the metadata
/// that granted this role its signing authority.
pub(super) fn verify_signatures_with_keys(
    signed_payload: &[u8],
    signatures_array: &[u8],
    role_keys: RoleKeysView<'_>,
    keys: &[Option<KeyView<'_>>],
    keys_len: usize,
    limits: &Limits,
) -> Result<()> {
    if role_keys.threshold == 0
        || role_keys.threshold as usize > role_keys.keyids_len
        || role_keys.keyids_len == 0
        || keys_len > keys.len()
    {
        return Err(Error::NoKeysForRole);
    }
    let mut signatures = [None; MAX_SIGNATURES];
    let sig_len = parse_signatures(signatures_array, &mut signatures)?;
    if sig_len > limits.max_signatures {
        return Err(Error::TooManySignatures {
            limit: limits.max_signatures,
            actual: sig_len,
        });
    }

    let mut canonical = [0u8; MAX_CANONICAL_BYTES];
    let canonical = enc::canonicalize_json_to_buf(signed_payload, &mut canonical)
        .map_err(|_| Error::Encoding)?;

    let mut counted = [""; MAX_SIGNATURES];
    let mut counted_len = 0usize;
    let mut valid = 0u32;
    for sig in signatures.iter().take(sig_len).flatten() {
        if !role_contains_keyid(role_keys, sig.keyid) {
            continue;
        }
        if counted[..counted_len].iter().any(|id| *id == sig.keyid) {
            continue;
        }
        if let Some(key) = find_key_in(keys, keys_len, sig.keyid) {
            if key.keytype != KeyType::Ed25519 || key.scheme != Scheme::Ed25519 {
                continue;
            }
            if stuf_env::crypto::ed25519_verify(&key.public, canonical, &sig.sig).is_ok() {
                counted[counted_len] = sig.keyid;
                counted_len += 1;
                valid += 1;
            }
        }
    }
    if valid >= role_keys.threshold {
        Ok(())
    } else {
        Err(Error::ThresholdNotMet {
            threshold: role_keys.threshold,
            valid,
        })
    }
}

/// Authenticate child metadata using a parent's delegated-role keys.
///
/// SECURITY: `parent` must come from authenticated parent targets
/// metadata. This helper does not check snapshot consistency, expiry,
/// rollback, or target path authorization.
#[cfg(feature = "tuf-delegation")]
fn verify_delegated_signatures_bytes(
    parent: &delegations::DelegationsView<'_>,
    role_name: &str,
    child_bytes: &[u8],
    limits: &Limits,
) -> Result<()> {
    let role = parent.roles[..parent.roles_len]
        .iter()
        .flatten()
        .find(|role| role.name == role_name)
        .ok_or(Error::NoKeysForRole)?;

    let authorized = RoleKeysView {
        keyids: role.keyids,
        keyids_len: role.keyids_len,
        threshold: role.threshold,
    };

    let signed = signed_payload(child_bytes)?;
    let sigs = signatures(child_bytes)?;

    // A delegated metadata file is a targets role, not root,
    // timestamp, or snapshot.
    let role_type = get_str(signed, "_type")?;
    if role_type != "targets" {
        return Err(Error::role_type_mismatch("targets", role_label(role_type)));
    }

    let spec_version = get_str(signed, "spec_version")?;
    if !spec_version.starts_with("1.") {
        return Err(Error::UnsupportedSpecVersion);
    }

    verify_signatures_with_keys(
        signed,
        sigs,
        authorized,
        &parent.keys,
        parent.keys_len,
        limits,
    )
}

fn role_contains_keyid(role: RoleKeysView<'_>, keyid: &str) -> bool {
    role.keyids[..role.keyids_len].iter().any(|id| *id == keyid)
}

fn verify_metadata_ref(bytes: &[u8], meta: MetaView<'_>) -> Result<()> {
    if let Some(expected) = meta.length {
        let actual = bytes.len() as u64;
        if actual != expected {
            return Err(Error::MetadataLengthMismatch { expected, actual });
        }
    }
    if let Some(expected) = meta.sha256 {
        verify_sha256_hex(bytes, expected).map_err(|err| match err {
            Error::TargetHashMismatch => Error::MetadataHashMismatch,
            other => other,
        })?;
    }
    Ok(())
}

#[cfg(feature = "hash-sha256")]
fn verify_sha256_hex(bytes: &[u8], expected_hex: &str) -> Result<()> {
    if expected_hex.len() != 64 {
        return Err(Error::InvalidHashLength {
            expected: 64,
            actual: expected_hex.len(),
        });
    }
    if !expected_hex
        .as_bytes()
        .iter()
        .all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidHashEncoding);
    }
    let actual = stuf_env::crypto::sha256(bytes);
    let mut expected = [0u8; 32];
    hex_to_bytes(expected_hex, &mut expected).map_err(|_| Error::InvalidHashEncoding)?;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TargetHashMismatch)
    }
}

#[cfg(not(feature = "hash-sha256"))]
fn verify_sha256_hex(_bytes: &[u8], _expected_hex: &str) -> Result<()> {
    Err(Error::NoHashAlgorithm)
}

fn hex_to_bytes(hex: &str, out: &mut [u8]) -> core::result::Result<(), ()> {
    if hex.len() != out.len() * 2 {
        return Err(());
    }
    let bytes = hex.as_bytes();
    for i in 0..out.len() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_nibble(b: u8) -> core::result::Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn too_many_targets_fail_without_panicking() {
        let metadata = br#"{
            "_type":"targets",
            "spec_version":"1.0.0",
            "version":1,
            "expires":2000000000,
            "targets":{
                "t1":{"length":1,"hashes":{"sha256":"a"}},
                "t2":{"length":1,"hashes":{"sha256":"a"}},
                "t3":{"length":1,"hashes":{"sha256":"a"}},
                "t4":{"length":1,"hashes":{"sha256":"a"}},
                "t5":{"length":1,"hashes":{"sha256":"a"}},
                "t6":{"length":1,"hashes":{"sha256":"a"}},
                "t7":{"length":1,"hashes":{"sha256":"a"}},
                "t8":{"length":1,"hashes":{"sha256":"a"}},
                "t9":{"length":1,"hashes":{"sha256":"a"}}
            }
        }"#;

        assert!(matches!(
            parse_targets(metadata, &Limits::default()),
            Err(Error::TooManyTargets {
                limit: 8,
                actual: 9
            })
        ));
    }

    #[test]
    fn too_many_root_keys_fail_without_panicking() {
        let metadata = br#"{
            "_type":"root",
            "spec_version":"1.0.0",
            "version":1,
            "expires":2000000000,
            "keys":{
                "k1":{}, "k2":{}, "k3":{},
                "k4":{}, "k5":{}, "k6":{},
                "k7":{}, "k8":{}, "k9":{}
            },
            "roles":{}
        }"#;

        assert!(matches!(
            parse_root(metadata, &Limits::default()),
            Err(Error::TooManyKeys {
                limit: 8,
                actual: 9
            })
        ));
    }
}

#[cfg(all(test, feature = "tuf-delegation"))]
mod delegated_chain_guard_tests {
    use super::*;

    #[test]
    fn snapshot_lookup_requires_exact_role() {
        let meta = br#"{
            "sensors.json":{"version":4},
            "controllers.json":{"version":7}
        }"#;

        assert_eq!(delegated_snapshot_ref(meta, "sensors").unwrap().version, 4);

        assert!(delegated_snapshot_ref(meta, "sensor").is_err());

        assert!(delegated_snapshot_ref(meta, "../sensors").is_err());

        assert!(delegated_snapshot_ref(meta, "sensors.json").is_err());
    }

    #[test]
    fn delegated_paths_reject_out_of_scope_targets() {
        let scope = delegations::PathScope::Paths(["sensors/*", "", "", "", "", "", "", ""], 1);

        assert!(delegated_scope_allows(scope, "sensors/firmware.bin"));

        assert!(!delegated_scope_allows(scope, "controllers/firmware.bin"));

        assert!(!delegated_scope_allows(
            scope,
            "sensors/nested/firmware.bin"
        ));
    }

    #[test]
    fn delegated_hash_prefixes_are_scoped() {
        let target = "sensors/firmware.bin";

        let digest = stuf_env::crypto::sha256_hex(target.as_bytes());

        let prefix = &digest[..4];

        let scope = delegations::PathScope::HashPrefixes([prefix, "", "", "", "", "", "", ""], 1);

        assert!(delegated_scope_allows(scope, target));

        assert!(!delegated_scope_allows(scope, "other.bin"));
    }
}

#[cfg(all(test, feature = "tuf-delegation"))]
mod delegated_signature_tests {
    use super::*;

    fn parent<'a>() -> delegations::DelegationsView<'a> {
        delegations::DelegationsView {
            roles: [None; 8],
            roles_len: 0,
            keys: [None; MAX_KEYS],
            keys_len: 0,
        }
    }

    #[test]
    fn undeclared_role_cannot_authorize_metadata() {
        let child = br#"{
            "signed":{
                "_type":"targets",
                "spec_version":"1.0.0"
            },
            "signatures":[]
        }"#;

        let result =
            verify_delegated_signatures_bytes(&parent(), "unknown", child, &Limits::default());

        assert!(matches!(result, Err(Error::NoKeysForRole)));
    }

    #[test]
    fn wrong_metadata_type_is_rejected() {
        let mut parent = parent();
        parent.roles[0] = Some(delegations::DelegatedRoleView {
            name: "sensors",
            keyids: ["key1", "", "", "", "", "", "", ""],
            keyids_len: 1,
            threshold: 1,
            terminating: false,
            scope: delegations::PathScope::Paths(["sensors/*", "", "", "", "", "", "", ""], 1),
        });
        parent.roles_len = 1;

        let child = br#"{
            "signed":{
                "_type":"snapshot",
                "spec_version":"1.0.0"
            },
            "signatures":[]
        }"#;

        assert!(matches!(
            verify_delegated_signatures_bytes(&parent, "sensors", child, &Limits::default(),),
            Err(Error::RoleTypeMismatch { .. })
        ));
    }

    extern crate std;

    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed(version: u32) -> std::string::String {
        std::format!(
            r#"{{"_type":"targets","spec_version":"1.0.0",
                "version":{version},"expires":4102444800,
                "targets":{{}}}}"#
        )
    }

    fn signature(key: &SigningKey, keyid: &str, payload: &str) -> std::string::String {
        let mut buf = [0u8; MAX_CANONICAL_BYTES];
        let canonical = enc::canonicalize_json_to_buf(payload.as_bytes(), &mut buf).unwrap();

        let sig = key.sign(canonical);
        std::format!(
            r#"{{"keyid":"{keyid}","sig":"{}"}}"#,
            hex::encode(sig.to_bytes())
        )
    }

    fn child(payload: &str, signatures: &str) -> std::string::String {
        std::format!(r#"{{"signed":{payload},"signatures":[{signatures}]}}"#)
    }

    fn authorized_parent(
        threshold: u32,
        key1: &SigningKey,
        key2: &SigningKey,
    ) -> delegations::DelegationsView<'static> {
        let mut p = parent();

        p.roles[0] = Some(delegations::DelegatedRoleView {
            name: "sensors",
            keyids: ["k1", "k2", "", "", "", "", "", ""],
            keyids_len: 2,
            threshold,
            terminating: false,
            scope: delegations::PathScope::Paths(["sensors/*", "", "", "", "", "", "", ""], 1),
        });
        p.roles_len = 1;

        p.keys[0] = Some(KeyView {
            keyid: "k1",
            keytype: KeyType::Ed25519,
            scheme: Scheme::Ed25519,
            public: key1.verifying_key().to_bytes(),
        });
        p.keys[1] = Some(KeyView {
            keyid: "k2",
            keytype: KeyType::Ed25519,
            scheme: Scheme::Ed25519,
            public: key2.verifying_key().to_bytes(),
        });
        p.keys_len = 2;
        p
    }

    fn check(parent: &delegations::DelegationsView<'_>, bytes: &[u8]) -> Result<()> {
        verify_delegated_signatures_bytes(parent, "sensors", bytes, &Limits::default())
    }

    #[test]
    fn valid_delegated_ed25519_signature_passes() {
        let k1 = signing_key(1);
        let k2 = signing_key(2);
        let parent = authorized_parent(1, &k1, &k2);
        let payload = signed(1);
        let sig = signature(&k1, "k1", &payload);
        let metadata = child(&payload, &sig);

        assert!(check(&parent, metadata.as_bytes()).is_ok());
    }

    #[test]
    fn unauthorized_delegated_signer_fails() {
        let k1 = signing_key(1);
        let k2 = signing_key(2);
        let attacker = signing_key(3);
        let parent = authorized_parent(1, &k1, &k2);
        let payload = signed(1);

        // The attacker claims an authorized key ID but cannot
        // produce a signature from that key.
        let sig = signature(&attacker, "k1", &payload);
        let metadata = child(&payload, &sig);

        assert!(matches!(
            check(&parent, metadata.as_bytes()),
            Err(Error::ThresholdNotMet { .. })
        ));
    }

    #[test]
    fn tampered_delegated_payload_fails() {
        let k1 = signing_key(1);
        let k2 = signing_key(2);
        let parent = authorized_parent(1, &k1, &k2);

        let original = signed(1);
        let altered = signed(2);
        let sig = signature(&k1, "k1", &original);
        let metadata = child(&altered, &sig);

        assert!(matches!(
            check(&parent, metadata.as_bytes()),
            Err(Error::ThresholdNotMet { .. })
        ));
    }

    #[test]
    fn duplicate_delegated_signature_cannot_meet_threshold() {
        let k1 = signing_key(1);
        let k2 = signing_key(2);
        let parent = authorized_parent(2, &k1, &k2);
        let payload = signed(1);
        let sig = signature(&k1, "k1", &payload);
        let duplicates = std::format!("{sig},{sig}");
        let metadata = child(&payload, &duplicates);

        assert!(matches!(
            check(&parent, metadata.as_bytes()),
            Err(Error::ThresholdNotMet {
                threshold: 2,
                valid: 1
            })
        ));
    }

    #[test]
    fn two_distinct_delegated_signatures_meet_threshold() {
        let k1 = signing_key(1);
        let k2 = signing_key(2);
        let parent = authorized_parent(2, &k1, &k2);
        let payload = signed(1);

        let sig1 = signature(&k1, "k1", &payload);
        let sig2 = signature(&k2, "k2", &payload);
        let signatures = std::format!("{sig1},{sig2}");
        let metadata = child(&payload, &signatures);

        assert!(check(&parent, metadata.as_bytes()).is_ok());
    }
}
