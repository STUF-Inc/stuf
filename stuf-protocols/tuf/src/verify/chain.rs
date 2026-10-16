//! TUF verification chain — the core MVP flow.
//!
//! timestamp → snapshot → targets → firmware
//!
//! Each step only becomes available after the previous succeeds.
//! The chain is generic over Transport and Clock — injected by the app.
//! Crypto is called directly via stuf-env functions (feature-gated at
//! compile time). Encoding is called directly via stuf-encoding functions
//! (feature-gated at compile time).
//!
//! Configurable `Limits` bound the maximum size and complexity of
//! metadata the verifier will accept, preventing resource exhaustion.
//!
//! Internal chain state uses Checked<T> (signature checks passed).
//! The final output — verify_target / verify_target_bytes — returns
//! core's Verified<T>, the one true trust type.
//!
//! Two fetch modes:
//!   - verify_timestamp() etc. — chain fetches via Transport
//!   - verify_timestamp_bytes() etc. — caller passes pre-fetched &[u8]
//!     For no_alloc bare metal where the app owns all buffers.
//!
//! MVP scope: trusted root baked in, no root rotation.

use stuf_core::trust::Verified;
use stuf_env::clock::Clock;
use stuf_env::transport::Transport;

use crate::{
    error::{Error, Result},
    schema::{
        role::{Role, RoleType},
        root::Root,
        signed::Signed,
        snapshot::Snapshot,
        targets::{Target, Targets},
        timestamp::Timestamp,
    },
    verify::{
        expiry::check_expiry,
        hash::{verify_metadata_hash, verify_metadata_length, verify_target_hashes},
        limits::Limits,
        signatures::verify_signatures,
        state::{Checked, Unverified},
    },
};

// ── Size check helper ─────────────────────────────────────────────────────────

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

// ── Metadata field validation ─────────────────────────────────────────────────

/// Verify that the `_type` field matches the expected role.
/// TUF spec requires this to prevent role-confusion attacks where
/// a validly-signed metadata file is served in the wrong position.
fn check_role_type<R: Role>(actual_type: &str) -> Result<()> {
    if actual_type != R::expected_type_str() {
        // Map the actual string to a &'static str for the error.
        // Unknown values get "unknown".
        let actual: &'static str = match actual_type {
            "root" => "root",
            "timestamp" => "timestamp",
            "snapshot" => "snapshot",
            "targets" => "targets",
            _ => "unknown",
        };
        Err(Error::role_type_mismatch(R::expected_type_str(), actual))
    } else {
        Ok(())
    }
}

/// Verify that the spec_version major version is 1.
/// Future TUF spec versions may change metadata semantics.
fn check_spec_version(spec_version: &str) -> Result<()> {
    if !spec_version.starts_with("1.") {
        Err(Error::UnsupportedSpecVersion)
    } else {
        Ok(())
    }
}

// ── Structural limit checks ──────────────────────────────────────────────────

fn check_root_limits(root: &Root, limits: &Limits) -> Result<()> {
    if root.keys.len() > limits.max_keys {
        return Err(Error::TooManyKeys {
            limit: limits.max_keys,
            actual: root.keys.len(),
        });
    }
    Ok(())
}

fn check_signature_limits<T>(signed: &Signed<T>, limits: &Limits) -> Result<()> {
    if signed.signatures.len() > limits.max_signatures {
        return Err(Error::TooManySignatures {
            limit: limits.max_signatures,
            actual: signed.signatures.len(),
        });
    }
    Ok(())
}

fn check_targets_limits(targets: &Targets, limits: &Limits) -> Result<()> {
    if targets.targets.len() > limits.max_targets_entries {
        return Err(Error::TooManyTargets {
            limit: limits.max_targets_entries,
            actual: targets.targets.len(),
        });
    }
    Ok(())
}

// ── Type states ───────────────────────────────────────────────────────────────

/// Entry point — bootstrapped from a trusted root baked into the binary.
pub struct TrustAnchor<T, C>
where
    T: Transport,
    C: Clock,
{
    pub(crate) root: Checked<Root>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) limits: Limits,
}

pub struct TimestampChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    pub(crate) root: Checked<Root>,
    pub(crate) timestamp: Checked<Timestamp>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) limits: Limits,
}

pub struct SnapshotChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) limits: Limits,
}

#[allow(dead_code)]
pub struct TargetsChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) targets: Checked<Targets>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) limits: Limits,
}

// ── TrustAnchor ───────────────────────────────────────────────────────────────

impl<T, C> TrustAnchor<T, C>
where
    T: Transport,
    C: Clock,
{
    /// Bootstrap from a trusted root baked in at compile time.
    /// Uses default limits.
    pub fn new(root_bytes: &[u8], transport: T, clock: C) -> Result<Self> {
        Self::with_limits(root_bytes, transport, clock, Limits::default())
    }

    /// Bootstrap with custom metadata limits.
    pub fn with_limits(root_bytes: &[u8], transport: T, clock: C, limits: Limits) -> Result<Self> {
        check_size(root_bytes, limits.max_root_bytes, "root")?;

        let signed: Signed<Root> = stuf_encoding::decode(root_bytes)?;
        check_signature_limits(&signed, &limits)?;

        let unverified = Unverified::from_signed(signed);

        let root_inner = unverified.payload().clone();
        check_role_type::<Root>(&root_inner.role_type)?;
        check_spec_version(&root_inner.spec_version)?;
        check_root_limits(&root_inner, &limits)?;

        let role_keys = root_inner
            .role_keys(&RoleType::Root)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = stuf_encoding::canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &root_inner.keys,
            &canonical,
        )?;

        let checked = unverified.into_checked();

        // SECURITY: Check root expiry. The TUF spec requires clients to
        // verify expiry for all metadata including root. Even though in
        // this MVP the root is baked into the binary with no rotation
        // path, we enforce expiry so operators are forced to rebuild
        // before the root goes stale.
        check_expiry(checked.get().expires(), &clock)?;

        Ok(Self {
            root: checked,
            transport,
            clock,
            limits,
        })
    }

    /// Step 1 — fetch and verify timestamp.json via Transport.
    pub fn verify_timestamp(self) -> Result<TimestampChecked<T, C>> {
        let bytes = self
            .transport
            .fetch("timestamp.json")
            .map_err(|_| Error::Transport)?;
        self.verify_timestamp_inner(bytes.as_ref())
    }

    /// Step 1 (no_alloc) — verify pre-fetched timestamp bytes.
    pub fn verify_timestamp_bytes(self, bytes: &[u8]) -> Result<TimestampChecked<T, C>> {
        self.verify_timestamp_inner(bytes)
    }

    fn verify_timestamp_inner(self, bytes: &[u8]) -> Result<TimestampChecked<T, C>> {
        check_size(bytes, self.limits.max_timestamp_bytes, "timestamp")?;

        let signed: Signed<Timestamp> = stuf_encoding::decode(bytes)?;
        check_signature_limits(&signed, &self.limits)?;

        let unverified = Unverified::from_signed(signed);

        check_role_type::<Timestamp>(&unverified.payload().role_type)?;
        check_spec_version(&unverified.payload().spec_version)?;

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Timestamp)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = stuf_encoding::canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
        )?;

        let checked = unverified.into_checked();
        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(TimestampChecked {
            root: self.root,
            timestamp: checked,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

// ── TimestampChecked ──────────────────────────────────────────────────────────

impl<T, C> TimestampChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    /// Step 2 — fetch and verify snapshot.json via Transport.
    pub fn verify_snapshot(self) -> Result<SnapshotChecked<T, C>> {
        let bytes = self
            .transport
            .fetch("snapshot.json")
            .map_err(|_| Error::Transport)?;
        self.verify_snapshot_inner(bytes.as_ref())
    }

    /// Step 2 (no_alloc) — verify pre-fetched snapshot bytes.
    pub fn verify_snapshot_bytes(self, bytes: &[u8]) -> Result<SnapshotChecked<T, C>> {
        self.verify_snapshot_inner(bytes)
    }

    fn verify_snapshot_inner(self, bytes: &[u8]) -> Result<SnapshotChecked<T, C>> {
        check_size(bytes, self.limits.max_snapshot_bytes, "snapshot")?;

        let snap_meta = self
            .timestamp
            .get()
            .snapshot_meta()
            .ok_or(Error::SnapshotMismatch)?;

        // Verify snapshot bytes against timestamp's declared hash+length
        if let Some(ref hashes) = snap_meta.hashes {
            verify_metadata_hash(bytes, hashes)?;
        }
        verify_metadata_length(bytes, snap_meta.length)?;

        let signed: Signed<Snapshot> = stuf_encoding::decode(bytes)?;
        check_signature_limits(&signed, &self.limits)?;

        let unverified = Unverified::from_signed(signed);

        check_role_type::<Snapshot>(&unverified.payload().role_type)?;
        check_spec_version(&unverified.payload().spec_version)?;

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Snapshot)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = stuf_encoding::canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
        )?;

        let checked = unverified.into_checked();

        if checked.get().version() != snap_meta.version {
            return Err(Error::VersionMismatch {
                expected: snap_meta.version,
                received: checked.get().version(),
            });
        }

        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(SnapshotChecked {
            root: self.root,
            snapshot: checked,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

// ── SnapshotChecked ───────────────────────────────────────────────────────────

impl<T, C> SnapshotChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    /// Step 3 — fetch and verify targets.json via Transport.
    pub fn verify_targets(self) -> Result<TargetsChecked<T, C>> {
        let bytes = self
            .transport
            .fetch("targets.json")
            .map_err(|_| Error::Transport)?;
        self.verify_targets_inner(bytes.as_ref())
    }

    /// Step 3 (no_alloc) — verify pre-fetched targets bytes.
    pub fn verify_targets_bytes(self, bytes: &[u8]) -> Result<TargetsChecked<T, C>> {
        self.verify_targets_inner(bytes)
    }

    fn verify_targets_inner(self, bytes: &[u8]) -> Result<TargetsChecked<T, C>> {
        check_size(bytes, self.limits.max_targets_bytes, "targets")?;

        let snap_meta = self
            .snapshot
            .get()
            .meta_for("targets.json")
            .ok_or(Error::SnapshotMismatch)?;

        // Verify targets bytes against snapshot's declared hash+length
        if let Some(ref hashes) = snap_meta.hashes {
            verify_metadata_hash(bytes, hashes)?;
        }
        verify_metadata_length(bytes, snap_meta.length)?;

        let signed: Signed<Targets> = stuf_encoding::decode(bytes)?;
        check_signature_limits(&signed, &self.limits)?;

        let unverified = Unverified::from_signed(signed);

        check_role_type::<Targets>(&unverified.payload().role_type)?;
        check_spec_version(&unverified.payload().spec_version)?;

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Targets)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = stuf_encoding::canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
        )?;

        let checked = unverified.into_checked();

        check_targets_limits(checked.get(), &self.limits)?;

        if checked.get().version() != snap_meta.version {
            return Err(Error::VersionMismatch {
                expected: snap_meta.version,
                received: checked.get().version(),
            });
        }

        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(TargetsChecked {
            root: self.root,
            snapshot: self.snapshot,
            targets: checked,
            transport: self.transport,
            clock: self.clock,
            limits: self.limits,
        })
    }
}

// ── TargetsChecked ────────────────────────────────────────────────────────────

impl<T, C> TargetsChecked<T, C>
where
    T: Transport,
    C: Clock,
{
    /// Step 4 — fetch firmware via Transport and verify against targets metadata.
    /// Returns core's Verified<Target> — the one true trust type.
    pub fn verify_target(&self, name: &str) -> Result<Verified<Target>> {
        self.targets
            .get()
            .get_target(name)
            .ok_or(Error::TargetNotFound)?;
        let bytes = self.transport.fetch(name).map_err(|_| Error::Transport)?;
        self.verify_target_inner(name, bytes.as_ref())
    }

    /// Step 4 (no_alloc) — verify pre-fetched firmware bytes.
    /// Returns core's Verified<Target> — the one true trust type.
    pub fn verify_target_bytes(&self, name: &str, bytes: &[u8]) -> Result<Verified<Target>> {
        self.verify_target_inner(name, bytes)
    }

    fn verify_target_inner(&self, name: &str, bytes: &[u8]) -> Result<Verified<Target>> {
        let target_meta = self
            .targets
            .get()
            .get_target(name)
            .ok_or(Error::TargetNotFound)?;

        // Length check
        if bytes.len() as u64 != target_meta.length {
            return Err(Error::TargetLengthMismatch {
                expected: target_meta.length,
                actual: bytes.len() as u64,
            });
        }

        // Hash check — calls stuf-env directly
        verify_target_hashes(bytes, &target_meta.hashes)?;

        // Full TUF chain passed — return core's Verified<T>
        Ok(Verified::new(target_meta.clone()))
    }

    /// Verify a delegated targets metadata file against its
    /// authenticated parent and the trusted snapshot.
    ///
    /// This does not yet authorize a firmware target.
    #[cfg(feature = "tuf-delegation")]
    fn verify_delegated_metadata_bytes(
        &self,
        parent: &Checked<Targets>,
        role_name: &str,
        bytes: &[u8],
    ) -> Result<Checked<Targets>> {
        use crate::verify::delegation::verify_delegated_signatures;

        check_size(bytes, self.limits.max_targets_bytes, "targets")?;

        // The trusted snapshot must identify this metadata file.
        let filename = alloc::format!("{role_name}.json");

        let expected = self
            .snapshot
            .get()
            .meta_for(&filename)
            .ok_or(Error::SnapshotMismatch)?;

        // Verify integrity against snapshot metadata.
        if let Some(ref hashes) = expected.hashes {
            verify_metadata_hash(bytes, hashes)?;
        }
        verify_metadata_length(bytes, expected.length)?;

        // Deserialize and enforce signature-count limits.
        let signed: Signed<Targets> = stuf_encoding::decode(bytes)?;
        check_signature_limits(&signed, &self.limits)?;

        // Authenticate using keys authorized by the parent.
        let checked = verify_delegated_signatures(parent, role_name, signed)?;

        // Enforce the same structural limits as top-level targets.
        check_targets_limits(checked.get(), &self.limits)?;

        // The delegated version must match the trusted snapshot.
        if checked.get().version() != expected.version {
            return Err(Error::VersionMismatch {
                expected: expected.version,
                received: checked.get().version(),
            });
        }

        // Delegated metadata must not be expired.
        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(checked)
    }

    pub fn targets(&self) -> &Checked<Targets> {
        &self.targets
    }

    pub fn root(&self) -> &Checked<Root> {
        &self.root
    }
}
