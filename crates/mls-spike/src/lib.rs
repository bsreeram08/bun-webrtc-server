//! M2 risk spike: OpenMLS 0.9 against the assumptions in docs/workspace-architecture.md §2/§4.
//!
//! Not production code. It answers: does the credential binding, the journaled storage model,
//! server-sequenced commits, external joins, a custom roles extension, last-resort KeyPackages
//! and secret-free delivery-service validation work as planned, and what does it cost?

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
pub use openmls::prelude::*;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use serde::{Deserialize, Serialize};

pub const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// `roles` GroupContext extension (plan §2.4).
pub const ROLES_EXT: u16 = 0xF0A1;

#[derive(Debug, thiserror::Error)]
pub enum SpikeError {
    #[error("device certificate rejected: {0}")]
    Cert(String),
    #[error("policy rejected commit: {0}")]
    Policy(String),
    #[error("delivery service: {0}")]
    Ds(String),
    #[error("openmls: {0}")]
    Mls(String),
}
pub type Result<T> = std::result::Result<T, SpikeError>;
fn mls<E: std::fmt::Debug>(e: E) -> SpikeError {
    SpikeError::Mls(format!("{e:?}"))
}

// ---------------------------------------------------------------------------------------------
// Device certificates (plan §2.2): BasicCredential.identity = DeviceCert signed by the account key.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceCert {
    pub user_id: String,
    pub device_id: String,
    pub leaf_sig_key: Vec<u8>,
    pub aik_sign: Vec<u8>,
    pub sig: Vec<u8>,
}

impl DeviceCert {
    fn tbs(user_id: &str, device_id: &str, leaf_sig_key: &[u8], aik_sign: &[u8]) -> Vec<u8> {
        let mut out = b"webrtc-bun-devcert-v1".to_vec();
        for part in [user_id.as_bytes(), device_id.as_bytes(), leaf_sig_key, aik_sign] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }
    pub fn issue(aik: &SigningKey, user_id: &str, device_id: &str, leaf_sig_key: &[u8]) -> Self {
        let aik_sign = aik.verifying_key().to_bytes().to_vec();
        let sig = aik.sign(&Self::tbs(user_id, device_id, leaf_sig_key, &aik_sign)).to_bytes().to_vec();
        Self { user_id: user_id.into(), device_id: device_id.into(), leaf_sig_key: leaf_sig_key.into(), aik_sign, sig }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("cert serializes")
    }
}

/// Pinned account identity keys per user (TOFU directory on the client). The verifier rejects a
/// cert whose AIK is not the pinned one, whose signature fails, or whose leaf key differs from the
/// leaf node's actual signature key.
#[derive(Default, Clone)]
pub struct Pins(pub HashMap<String, [u8; 32]>);

impl Pins {
    pub fn verify(&self, credential: &Credential, leaf_sig_key: &[u8]) -> Result<DeviceCert> {
        let basic = BasicCredential::try_from(credential.clone()).map_err(|e| SpikeError::Cert(format!("not basic: {e:?}")))?;
        // Bound before parsing: OpenMLS accepts any identity length the TLS vector allows.
        if basic.identity().len() > limits::MAX_IDENTITY_BYTES {
            return Err(SpikeError::Cert(format!("identity is {} bytes", basic.identity().len())));
        }
        let cert: DeviceCert = serde_json::from_slice(basic.identity()).map_err(|e| SpikeError::Cert(format!("malformed: {e}")))?;
        // One identity, one encoding: ids must be canonical and the identity bytes must be exactly
        // our encoding of the decoded cert, so no two byte strings name the same user or device
        // (case, Unicode look-alikes, JSON escapes, whitespace or key order).
        if !canonical_user(&cert.user_id) || !canonical_device(&cert.device_id) {
            return Err(SpikeError::Cert(format!("non-canonical id {:?}/{:?}", cert.user_id, cert.device_id)));
        }
        if cert.encode() != basic.identity() {
            return Err(SpikeError::Cert("identity is not canonically encoded".into()));
        }
        let pinned = self.0.get(&cert.user_id).ok_or_else(|| SpikeError::Cert(format!("no pinned key for {}", cert.user_id)))?;
        if cert.aik_sign != pinned {
            return Err(SpikeError::Cert(format!("{} is not signed by the pinned account key", cert.device_id)));
        }
        if cert.leaf_sig_key != leaf_sig_key {
            return Err(SpikeError::Cert("leaf signature key does not match the certificate".into()));
        }
        let key = VerifyingKey::from_bytes(pinned).map_err(|e| SpikeError::Cert(e.to_string()))?;
        let sig = ed25519_dalek::Signature::from_slice(&cert.sig).map_err(|e| SpikeError::Cert(e.to_string()))?;
        key.verify(&DeviceCert::tbs(&cert.user_id, &cert.device_id, &cert.leaf_sig_key, &cert.aik_sign), &sig)
            .map_err(|_| SpikeError::Cert("bad account signature".into()))?;
        Ok(cert)
    }
    /// After a Welcome or a DS bootstrap: every member in the tree must carry a valid cert, and
    /// the group may not exceed the leaf bound.
    pub fn verify_members(&self, members: impl Iterator<Item = Member>) -> Result<Vec<DeviceCert>> {
        let certs: Vec<DeviceCert> = members.map(|m| self.verify(&m.credential, &m.signature_key)).collect::<Result<_>>()?;
        if certs.len() > limits::MAX_LEAVES {
            return Err(SpikeError::Policy(format!("{} leaves exceeds {}", certs.len(), limits::MAX_LEAVES)));
        }
        Ok(certs)
    }
}

/// Bounds OpenMLS does not impose by itself (it accepts anything the TLS length prefixes allow).
pub mod limits {
    /// Leaves (devices) per group: plan §2.8 public-channel ceiling.
    pub const MAX_LEAVES: usize = 2_500;
    /// Proposals (inline + by reference) per commit. Bulk invites are batched.
    pub const MAX_PROPOSALS: usize = 128;
    /// Wire bytes checked before any parsing. Set from the benchmark: a 2,500-leaf ratchet tree
    /// and Welcome stay below 4 MiB; commits with ≤128 adds stay below 1 MiB.
    pub const MAX_HANDSHAKE_BYTES: usize = 1 << 20;
    pub const MAX_APPLICATION_BYTES: usize = 64 << 10;
    pub const MAX_WELCOME_BYTES: usize = 4 << 20;
    pub const MAX_TREE_BYTES: usize = 4 << 20;
    pub const MAX_GROUP_INFO_BYTES: usize = 64 << 10;
    /// DeviceCert JSON inside BasicCredential.identity.
    pub const MAX_IDENTITY_BYTES: usize = 1_024;
    /// Serialized `roles` extension and its admin list.
    pub const MAX_ROLES_BYTES: usize = 4_096;
    pub const MAX_ADMINS: usize = 64;
}

fn bounded(kind: &str, bytes: &[u8], max: usize) -> Result<()> {
    if bytes.len() > max {
        return Err(SpikeError::Policy(format!("{kind} is {} bytes; limit {max}", bytes.len())));
    }
    Ok(())
}

/// Server usernames: 3–20 of [a-z0-9_]. Anything else is not a user id, so comparisons are exact.
pub fn canonical_user(id: &str) -> bool {
    (3..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
pub fn canonical_device(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub fn cert_of(credential: &Credential) -> Option<DeviceCert> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    serde_json::from_slice(basic.identity()).ok()
}

// ---------------------------------------------------------------------------------------------
// Storage (plan §4.4): a synchronous KV backend + an in-memory overlay that OpenMLS runs against,
// flushed as one batch of writes per API call.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Write {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// What IndexedDB / SQLite would implement. `apply` must be atomic.
pub trait Kv {
    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;
    fn apply(&mut self, batch: &[Write]);
}

#[derive(Default, Clone)]
pub struct MemKv(pub BTreeMap<Vec<u8>, Vec<u8>>);

impl MemKv {
    /// What a file / IndexedDB dump would hold between process runs.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0.iter().collect::<Vec<_>>()).unwrap()
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = serde_json::from_slice(bytes).unwrap();
        Self(rows.into_iter().collect())
    }
    pub fn bytes(&self) -> usize {
        self.0.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

impl Kv for MemKv {
    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.0.range(prefix.to_vec()..).take_while(|(k, _)| k.starts_with(prefix)).map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    fn apply(&mut self, batch: &[Write]) {
        for write in batch {
            match write {
                Write::Put(k, v) => {
                    self.0.insert(k.clone(), v.clone());
                }
                Write::Delete(k) => {
                    self.0.remove(k);
                }
            }
        }
    }
}

/// OpenMLS provider whose storage is an overlay preloaded from a [`Kv`]. OpenMLS mutates the
/// overlay synchronously; [`SpikeProvider::flush`] diffs it against the last flushed snapshot and
/// returns the journal that the host applies in one transaction (IndexedDB) or one SQL txn.
pub struct SpikeProvider {
    crypto: RustCrypto,
    overlay: MemoryStorage,
    snapshot: std::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl OpenMlsProvider for SpikeProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.overlay
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

impl Default for SpikeProvider {
    fn default() -> Self {
        Self { crypto: RustCrypto::default(), overlay: MemoryStorage::default(), snapshot: Default::default() }
    }
}

impl SpikeProvider {
    /// Preload everything under `prefix` (the spike loads all; see FINDINGS on key layout).
    pub fn preload(kv: &dyn Kv, prefix: &[u8]) -> Self {
        let rows: HashMap<_, _> = kv.scan(prefix).into_iter().collect();
        let provider = Self::default();
        *provider.overlay.values.write().unwrap() = rows.clone();
        *provider.snapshot.lock().unwrap() = rows;
        provider
    }
    pub fn flush(&self) -> Vec<Write> {
        let values = self.overlay.values.read().unwrap();
        let mut snapshot = self.snapshot.lock().unwrap();
        let mut writes = Vec::new();
        for (k, v) in values.iter() {
            if snapshot.get(k) != Some(v) {
                writes.push(Write::Put(k.clone(), v.clone()));
            }
        }
        for k in snapshot.keys() {
            if !values.contains_key(k) {
                writes.push(Write::Delete(k.clone()));
            }
        }
        *snapshot = values.clone();
        writes
    }
    pub fn rows(&self) -> usize {
        self.overlay.values.read().unwrap().len()
    }
}

// ---------------------------------------------------------------------------------------------
// Roles extension (plan §2.4) and the client-side policy check.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum JoinPolicy {
    Open,
    Invite,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    pub admins: Vec<String>,
    pub join_policy: JoinPolicy,
}

impl Roles {
    pub fn extension(&self) -> Extension {
        Extension::Unknown(ROLES_EXT, UnknownExtension(serde_json::to_vec(self).unwrap()))
    }
    /// The group's roles; malformed, oversized or admin-less roles are an error, never "no roles".
    pub fn of(extensions: &Extensions<GroupContext>) -> Result<Self> {
        let raw = &extensions.unknown(ROLES_EXT).ok_or_else(|| SpikeError::Policy("group has no roles extension".into()))?.0;
        bounded("roles extension", raw, limits::MAX_ROLES_BYTES)?;
        let roles: Self = serde_json::from_slice(raw).map_err(|e| SpikeError::Policy(format!("malformed roles: {e}")))?;
        if roles.admins.is_empty() || roles.admins.len() > limits::MAX_ADMINS {
            return Err(SpikeError::Policy(format!("roles must name 1..={} admins", limits::MAX_ADMINS)));
        }
        // Same canonical form as certificates, and exactly our encoding, so the admin check is a
        // byte comparison both sides compute identically.
        if !roles.admins.iter().all(|a| canonical_user(a)) || serde_json::to_vec(&roles).unwrap() != *raw {
            return Err(SpikeError::Policy("roles are not canonically encoded".into()));
        }
        Ok(roles)
    }
}

/// The only GroupContext a group may have: required_capabilities (which must include roles) and
/// one valid roles extension. Unknown or extra extension types are refused, whatever OpenMLS allows.
pub fn validate_context(extensions: &Extensions<GroupContext>) -> Result<Roles> {
    for extension in extensions.iter() {
        match extension.extension_type() {
            ExtensionType::RequiredCapabilities | ExtensionType::Unknown(ROLES_EXT) => {}
            other => return Err(SpikeError::Policy(format!("group context extension {other:?} is not allowed"))),
        }
    }
    let required = extensions.required_capabilities().ok_or_else(|| SpikeError::Policy("required_capabilities missing".into()))?;
    if !required.extension_types().contains(&ExtensionType::Unknown(ROLES_EXT)) {
        return Err(SpikeError::Policy("roles is no longer a required capability".into()));
    }
    Roles::of(extensions)
}

/// Whole-group check used wherever a device or the DS adopts a group it did not build itself:
/// joining by Welcome, joining by external commit, bootstrapping the DS from a GroupInfo.
pub fn validate_group_state(extensions: &Extensions<GroupContext>, members: impl Iterator<Item = Member>, pins: &Pins) -> Result<Roles> {
    let roles = validate_context(extensions)?;
    pins.verify_members(members)?;
    Ok(roles)
}

/// Authorization run by every receiver AND by the delivery service before a commit is sequenced
/// (see FINDINGS: a commit the DS accepts but clients reject forks the group, so the DS check is
/// not "UX only"). Inputs are all public: the roles extension, member credentials, the commit.
/// - Adding a device of a user already in the group: anyone (own linked devices).
/// - Adding a new user: admin, or join_policy == Open.
/// - External commit (self-join): users already in the group (own new device, resync) always;
///   new users only when join_policy == Open.
/// - Removing another user's leaves: admin only. Removing your own: always.
/// The one commit validator. Clients call it before `merge_staged_commit`; the DS calls it before
/// `merge_commit` and before appending to the log. Everything it reads is public, so both sides
/// reach the same verdict on the same commit.
///
/// OpenMLS has already checked: signatures, epoch, tree/parent hashes, KeyPackage validity and
/// lifetimes, capability support, duplicate signature/encryption keys. It does NOT check anything
/// application-level, which is all here:
/// - every introduced or changed leaf (Add, Update, UpdatePath, external join) carries a DeviceCert
///   signed by the pinned account key and bound to that leaf's signature key;
/// - Update proposals and UpdatePaths keep the same user and device (no identity swap via update);
/// - only Add / Remove / Update / GroupContextExtensions / ExternalInit proposals (inline or by
///   reference), at most MAX_PROPOSALS, and the group stays within MAX_LEAVES;
/// - roles: adds of new users and external self-joins need admin or an Open group; removing other
///   users needs admin; GroupContextExtensions need admin and must keep a valid roles extension and
///   the roles capability requirement.
pub fn validate_staged(
    extensions: &Extensions<GroupContext>,
    members: impl Iterator<Item = Member>,
    sender: &Sender,
    staged: &StagedCommit,
    pins: &Pins,
) -> Result<()> {
    // Policy is always evaluated against the PRE-commit context and roles, decoded by the one
    // strict decoder; a GroupContextExtensions proposal in this very commit never authorizes the
    // other proposals bundled with it.
    let roles = validate_context(extensions)?;
    let members: HashMap<LeafNodeIndex, DeviceCert> =
        members.map(|m| Ok((m.index, pins.verify(&m.credential, &m.signature_key)?))).collect::<Result<_>>()?;
    let users: std::collections::HashSet<&String> = members.values().map(|c| &c.user_id).collect();

    // Who is committing, as of the current (pre-commit) tree.
    let (committer, external) = match sender {
        Sender::Member(index) => (members.get(index).cloned().ok_or_else(|| SpikeError::Policy("committer not in tree".into()))?, false),
        Sender::NewMemberCommit => {
            let leaf = staged.update_path_leaf_node().ok_or_else(|| SpikeError::Policy("external commit without a path".into()))?;
            (pins.verify(leaf.credential(), leaf.signature_key().as_slice())?, true)
        }
        other => return Err(SpikeError::Policy(format!("commits from {other:?} are not accepted"))),
    };
    let admin = roles.admins.contains(&committer.user_id);
    if external && !users.contains(&committer.user_id) && roles.join_policy == JoinPolicy::Invite {
        return Err(SpikeError::Policy(format!("{} may not self-join an invite-only group", committer.user_id)));
    }

    // The committer's new leaf (UpdatePath) must stay the same user and device.
    if let Some(leaf) = staged.update_path_leaf_node() {
        let cert = pins.verify(leaf.credential(), leaf.signature_key().as_slice())?;
        if cert.user_id != committer.user_id || cert.device_id != committer.device_id {
            return Err(SpikeError::Policy("an update path may not change the leaf's user or device".into()));
        }
    }

    let mut count = 0usize;
    let (mut adds, mut removes) = (0usize, 0usize);
    for queued in staged.queued_proposals() {
        count += 1;
        match queued.proposal() {
            Proposal::Add(add) => {
                adds += 1;
                let leaf = add.key_package().leaf_node();
                let cert = pins.verify(leaf.credential(), leaf.signature_key().as_slice())?;
                if !users.contains(&cert.user_id) && !admin && roles.join_policy == JoinPolicy::Invite {
                    return Err(SpikeError::Policy(format!("{} may not add {} to an invite-only group", committer.user_id, cert.user_id)));
                }
            }
            Proposal::Remove(remove) => {
                removes += 1;
                let target = members.get(&remove.removed()).ok_or_else(|| SpikeError::Policy("remove of an empty leaf".into()))?;
                if target.user_id != committer.user_id && !admin {
                    return Err(SpikeError::Policy(format!("{} may not remove {}", committer.user_id, target.user_id)));
                }
            }
            Proposal::Update(update) => {
                let Sender::Member(index) = queued.sender() else { return Err(SpikeError::Policy("update from a non-member".into())) };
                let old = members.get(index).ok_or_else(|| SpikeError::Policy("update for an empty leaf".into()))?;
                let leaf = update.leaf_node();
                let cert = pins.verify(leaf.credential(), leaf.signature_key().as_slice())?;
                if cert.user_id != old.user_id || cert.device_id != old.device_id {
                    return Err(SpikeError::Policy("an update may not change the leaf's user or device".into()));
                }
            }
            Proposal::GroupContextExtensions(gce) => {
                if !admin {
                    return Err(SpikeError::Policy(format!("{} may not change group settings", committer.user_id)));
                }
                validate_context(gce.extensions())?;
            }
            Proposal::ExternalInit(_) if external => {}
            other => return Err(SpikeError::Policy(format!("{:?} proposals are not accepted", other.proposal_type()))),
        }
    }
    if count > limits::MAX_PROPOSALS {
        return Err(SpikeError::Policy(format!("{count} proposals exceeds {}", limits::MAX_PROPOSALS)));
    }
    let after = members.len() + adds + usize::from(external) - removes;
    if after > limits::MAX_LEAVES {
        return Err(SpikeError::Policy(format!("group would have {after} leaves; limit {}", limits::MAX_LEAVES)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Accounts and devices
// ---------------------------------------------------------------------------------------------

pub struct Account {
    pub user_id: String,
    pub aik: SigningKey,
}

impl Account {
    pub fn new(user_id: &str) -> Self {
        Self { user_id: user_id.into(), aik: SigningKey::generate(&mut rand::rngs::OsRng) }
    }
    pub fn pin(&self, pins: &mut Pins) {
        pins.0.insert(self.user_id.clone(), self.aik.verifying_key().to_bytes());
    }
}

pub fn capabilities() -> Capabilities {
    Capabilities::builder().extensions(vec![ExtensionType::Unknown(ROLES_EXT)]).build()
}

pub fn group_extensions(roles: &Roles) -> Extensions<GroupContext> {
    let required = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(ROLES_EXT)], &[], &[]);
    Extensions::from_vec(vec![Extension::RequiredCapabilities(required), roles.extension()]).unwrap()
}

pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder().wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY).use_ratchet_tree_extension(false).build()
}

/// A client device. Entry points that change group state, and the gate each runs:
///
/// | entry point            | gate                                                              |
/// |------------------------|-------------------------------------------------------------------|
/// | `create_group`         | `validate_context` on the extensions it is about to commit to     |
/// | `join` (Welcome)       | size bounds, then `validate_group_state` before `into_group`      |
/// | `join_external`        | size bounds, `validate_group_state` on the GroupInfo's tree, then |
/// |                        | `validate_staged` on our own external commit before keeping it    |
/// | `merge_own`            | `validate_staged` on our pending commit before merging            |
/// | `receive` (commit)     | size bounds, `validate_staged` before `merge_staged_commit`       |
/// | `receive` (proposal)   | always refused (never stored, so no by-reference bypass)          |
/// | `load` (restart)       | `validate_group_state` + own-leaf check on the persisted group    |
///
/// Commit *builders* (`add`, `remove`, `self_update*`, `set_extensions`, `commit`) only produce
/// bytes; they change nothing until `merge_own` validates them. The `MlsGroup` itself is private so
/// no caller can merge or join around these gates.
pub struct Device {
    pub user_id: String,
    pub device_id: String,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    pub provider: SpikeProvider,
    group: Option<MlsGroup>,
}

impl Device {
    pub fn new(account: &Account, device_id: &str) -> Self {
        Self::with_signer(account, device_id, SignatureKeyPair::new(CS.signature_algorithm()).unwrap(), SpikeProvider::default())
    }
    pub fn with_signer(account: &Account, device_id: &str, signer: SignatureKeyPair, provider: SpikeProvider) -> Self {
        let cert = DeviceCert::issue(&account.aik, &account.user_id, device_id, signer.public());
        let credential = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: signer.public().into() };
        signer.store(provider.storage()).unwrap();
        Self { user_id: account.user_id.clone(), device_id: device_id.into(), signer, credential, provider, group: None }
    }
    pub fn key_package(&self, last_resort: bool) -> KeyPackage {
        let mut builder = KeyPackage::builder().leaf_node_capabilities(capabilities());
        if last_resort {
            builder = builder.mark_as_last_resort();
        }
        builder.build(CS, &self.provider, &self.signer, self.credential.clone()).unwrap().key_package().clone()
    }
    pub fn create_group(&mut self, id: &[u8], roles: &Roles) -> Result<()> {
        let extensions = group_extensions(roles);
        validate_context(&extensions)?;
        let group = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(id))
            .ciphersuite(CS)
            .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(false)
            .with_capabilities(capabilities())
            .with_group_context_extensions(extensions)
            .build(&self.provider, &self.signer, self.credential.clone())
            .map_err(mls)?;
        self.group = Some(group);
        Ok(())
    }
    /// Read-only view; all state changes go through the gated entry points.
    pub fn group(&self) -> &MlsGroup {
        self.group.as_ref().expect("in a group")
    }
    pub fn in_group(&self) -> bool {
        self.group.is_some()
    }
    /// Reload after a process restart from a provider preloaded out of the KV store.
    pub fn load(user_id: &str, device_id: &str, provider: SpikeProvider, group_id: &GroupId, signature_key: &[u8], pins: &Pins) -> Result<Self> {
        let group = MlsGroup::load(provider.storage(), group_id).map_err(mls)?.ok_or_else(|| SpikeError::Mls("no persisted group".into()))?;
        let signer = SignatureKeyPair::read(provider.storage(), signature_key, CS.signature_algorithm()).ok_or_else(|| SpikeError::Mls("no persisted signer".into()))?;
        validate_group_state(group.extensions(), group.members(), pins)?;
        let own = group.own_leaf_node().ok_or_else(|| SpikeError::Mls("no own leaf".into()))?;
        let cert = pins.verify(own.credential(), own.signature_key().as_slice())?;
        if cert.user_id != user_id || cert.device_id != device_id || own.signature_key().as_slice() != signature_key {
            return Err(SpikeError::Cert("persisted group belongs to another device".into()));
        }
        let credential = CredentialWithKey { credential: own.credential().clone(), signature_key: signature_key.to_vec().into() };
        Ok(Self { user_id: user_id.into(), device_id: device_id.into(), signer, credential, provider, group: Some(group) })
    }
    pub fn epoch(&self) -> u64 {
        self.group.as_ref().unwrap().epoch().as_u64()
    }
    pub fn group_info(&self) -> Vec<u8> {
        let g = self.group.as_ref().unwrap();
        let info: MlsMessageOut = g.export_group_info(self.provider.crypto(), &self.signer, false).unwrap();
        info.tls_serialize_detached().unwrap()
    }
    pub fn tree(&self) -> Vec<u8> {
        self.group.as_ref().unwrap().export_ratchet_tree().tls_serialize_detached().unwrap()
    }
    /// Join from a Welcome, verifying every member's certificate before accepting the group.
    pub fn join(&mut self, welcome: &[u8], tree: &[u8], pins: &Pins) -> Result<()> {
        bounded("welcome", welcome, limits::MAX_WELCOME_BYTES)?;
        bounded("ratchet tree", tree, limits::MAX_TREE_BYTES)?;
        let welcome = match MlsMessageIn::tls_deserialize_exact(welcome).map_err(mls)?.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(SpikeError::Mls("not a welcome".into())),
        };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).map_err(mls)?;
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, Some(tree)).map_err(mls)?;
        // OpenMLS accepts any group a Welcome describes; the app checks members, size and roles.
        validate_group_state(staged.group_context().extensions(), staged.members(), pins)?;
        self.group = Some(staged.into_group(&self.provider).map_err(mls)?);
        Ok(())
    }
    /// External commit (public-channel self-join, own new device, or resync with the same key).
    /// The joining device runs the same gates as everyone else: the group it joins must be valid,
    /// and its own commit must pass `validate_staged` against the pre-join public state.
    pub fn join_external(&mut self, group_info: &[u8], tree: &[u8], pins: &Pins) -> Result<Vec<u8>> {
        bounded("group info", group_info, limits::MAX_GROUP_INFO_BYTES)?;
        bounded("ratchet tree", tree, limits::MAX_TREE_BYTES)?;
        // Pre-join state, rebuilt the way the DS builds it, and checked like a Welcome.
        let mut before = Ds::new(group_info, tree, pins.clone())?;
        let info = match MlsMessageIn::tls_deserialize_exact(group_info).map_err(mls)?.extract() {
            MlsMessageBodyIn::GroupInfo(i) => i,
            _ => return Err(SpikeError::Mls("not a group info".into())),
        };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).map_err(mls)?;
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_ratchet_tree(tree)
            .with_config(join_config())
            .build_group(&self.provider, info, self.credential.clone())
            .map_err(mls)?
            .leaf_node_parameters(LeafNodeParameters::builder().with_capabilities(capabilities()).build())
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.signer, |_| true)
            .map_err(mls)?
            .finalize(&self.provider)
            .map_err(mls)?;
        let commit = bundle.into_commit().tls_serialize_detached().unwrap();
        // Our own external commit through the exact DS/client validator before we keep the group.
        before.submit(&commit)?;
        self.group = Some(group);
        Ok(commit)
    }
    pub fn add(&mut self, kps: &[KeyPackage]) -> Result<(Vec<u8>, Vec<u8>)> {
        let provider = &self.provider;
        let (commit, welcome, _) = self.group.as_mut().unwrap().add_members(provider, &self.signer, kps).map_err(mls)?;
        Ok((commit.tls_serialize_detached().unwrap(), welcome.tls_serialize_detached().unwrap()))
    }
    pub fn remove(&mut self, leaves: &[LeafNodeIndex]) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let (commit, _, _) = self.group.as_mut().unwrap().remove_members(provider, &self.signer, leaves).map_err(mls)?;
        Ok(commit.tls_serialize_detached().unwrap())
    }
    pub fn self_update(&mut self) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let bundle = self.group.as_mut().unwrap().self_update(provider, &self.signer, LeafNodeParameters::default()).map_err(mls)?;
        Ok(bundle.into_commit().tls_serialize_detached().unwrap())
    }
    /// Self-update that swaps in a different credential (tests the identity-continuity rule).
    pub fn self_update_as(&mut self, credential: CredentialWithKey) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let params = LeafNodeParameters::builder().with_credential_with_key(credential).build();
        let bundle = self.group.as_mut().unwrap().self_update(provider, &self.signer, params).map_err(mls)?;
        Ok(bundle.into_commit().tls_serialize_detached().unwrap())
    }
    pub fn set_extensions(&mut self, extensions: Extensions<GroupContext>) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let (commit, _, _) = self.group.as_mut().unwrap().update_group_context_extensions(provider, extensions, &self.signer).map_err(mls)?;
        Ok(commit.tls_serialize_detached().unwrap())
    }
    /// Arbitrary commit: adds, removals and a GroupContextExtensions change bundled together.
    pub fn commit(&mut self, adds: Vec<KeyPackage>, removes: Vec<LeafNodeIndex>, extensions: Option<Extensions<GroupContext>>) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let group = self.group.as_mut().unwrap();
        let mut builder = group.commit_builder().propose_adds(adds).propose_removals(removes);
        if let Some(extensions) = extensions {
            builder = builder.propose_group_context_extensions(extensions).map_err(mls)?;
        }
        let bundle = builder
            .load_psks(provider.storage())
            .map_err(mls)?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .map_err(mls)?
            .stage_commit(provider)
            .map_err(mls)?;
        Ok(bundle.into_commit().tls_serialize_detached().unwrap())
    }
    pub fn propose_remove(&mut self, leaf: LeafNodeIndex) -> Result<Vec<u8>> {
        let provider = &self.provider;
        let (proposal, _) = self.group.as_mut().unwrap().propose_remove_member(provider, &self.signer, leaf).map_err(mls)?;
        Ok(proposal.tls_serialize_detached().unwrap())
    }
    /// Merge our own pending commit, but only after it passes the same validator receivers run.
    pub fn merge_own(&mut self, pins: &Pins) -> Result<()> {
        let provider = &self.provider;
        let group = self.group.as_mut().unwrap();
        let staged = group.pending_commit().ok_or_else(|| SpikeError::Mls("no pending commit".into()))?;
        validate_staged(group.extensions(), group.members(), &Sender::Member(group.own_leaf_index()), staged, pins)?;
        group.merge_pending_commit(provider).map_err(mls)
    }
    pub fn abandon_own(&mut self) {
        let provider = &self.provider;
        self.group.as_mut().unwrap().clear_pending_commit(provider.storage()).unwrap();
    }
    pub fn send(&mut self, text: &str) -> Vec<u8> {
        let provider = &self.provider;
        let message = self.group.as_mut().unwrap().create_message(provider, &self.signer, text.as_bytes()).unwrap();
        message.tls_serialize_detached().unwrap()
    }
    /// Process one message from the log: app messages return their text; commits are verified
    /// (certificates + roles policy) and merged, or rejected without touching the group.
    pub fn receive(&mut self, bytes: &[u8], pins: &Pins) -> Result<Option<String>> {
        bounded("message", bytes, limits::MAX_HANDSHAKE_BYTES)?;
        let message: ProtocolMessage = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls)?.try_into_protocol_message().map_err(mls)?;
        if matches!(message, ProtocolMessage::PrivateMessage(_)) {
            bounded("application message", bytes, limits::MAX_APPLICATION_BYTES)?;
        }
        let provider = &self.provider;
        let group = self.group.as_mut().unwrap();
        let processed = group.process_message(provider, message).map_err(mls)?;
        let sender = processed.sender().clone();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Some(String::from_utf8_lossy(&app.into_bytes()).into_owned())),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Validate against the pre-commit group; nothing is merged unless this passes.
                validate_staged(group.extensions(), group.members(), &sender, &staged, pins)?;
                group.merge_staged_commit(provider, *staged).map_err(mls)?;
                Ok(None)
            }
            // Standalone proposals are never stored (the DS refuses them too), so a proposal can't
            // reach a later commit "by reference" without going through validate_staged inline.
            ProcessedMessageContent::ProposalMessage(_) | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(SpikeError::Policy("standalone proposals are not accepted".into()))
            }
            _ => Ok(None),
        }
    }
    pub fn leaf_of(&self, user: &str, device: &str) -> LeafNodeIndex {
        self.group.as_ref().unwrap().members().find(|m| cert_of(&m.credential).is_some_and(|c| c.user_id == user && c.device_id == device)).expect("member").index
    }
}

/// One exported entry point that reaches the client paths (create, add, Welcome, external join,
/// commit processing, encrypt/decrypt) and the DS path, so the wasm size measurement is realistic.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn spike_roundtrip() -> u32 {
    let mut pins = Pins::default();
    let (alice, bob) = (Account::new("alice"), Account::new("bob"));
    alice.pin(&mut pins);
    bob.pin(&mut pins);
    let mut a = Device::new(&alice, "phone");
    a.create_group(b"w", &Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Open }).unwrap();
    let mut ds = Ds::new(&a.group_info(), &a.tree(), pins.clone()).unwrap();
    let mut b = Device::new(&bob, "phone");
    let (commit, welcome) = a.add(&[b.key_package(false)]).unwrap();
    ds.submit(&commit).unwrap();
    a.merge_own(&pins).unwrap();
    b.join(&welcome, &a.tree(), &pins).unwrap();
    let mut b2 = Device::new(&bob, "laptop");
    let ext = b2.join_external(&a.group_info(), &a.tree(), &pins).unwrap();
    ds.submit(&ext).unwrap();
    a.receive(&ext, &pins).unwrap();
    let text = b.receive(&a.send("hi"), &pins).unwrap().unwrap_or_default();
    text.len() as u32
}

// ---------------------------------------------------------------------------------------------
// Delivery service (plan §1.5/§2.5): PublicGroup, no secrets; sequences commits by epoch.
// ---------------------------------------------------------------------------------------------

pub struct Ds {
    crypto: RustCrypto,
    storage: MemoryStorage,
    /// Private: the only way to change it is `submit`, which runs `validate_staged` first.
    public: PublicGroup,
    pub log: Vec<Vec<u8>>,
    pub group_info: Vec<u8>,
    /// The server's view of account keys (from the device registry). The DS runs the same
    /// certificate + policy checks as clients so it never sequences a commit clients would reject.
    pub pins: Pins,
}

#[derive(Debug, PartialEq)]
pub enum Submit {
    Accepted(usize),
    /// Stale epoch: the client must process the log from its cursor and retry.
    Conflict { epoch: u64, seq: usize },
}

impl Ds {
    pub fn new(group_info: &[u8], tree: &[u8], pins: Pins) -> Result<Self> {
        bounded("group info", group_info, limits::MAX_GROUP_INFO_BYTES)?;
        bounded("ratchet tree", tree, limits::MAX_TREE_BYTES)?;
        let crypto = RustCrypto::default();
        let storage = MemoryStorage::default();
        let info = match MlsMessageIn::tls_deserialize_exact(group_info).map_err(mls)?.extract() {
            MlsMessageBodyIn::GroupInfo(i) => i,
            _ => return Err(SpikeError::Ds("not a group info".into())),
        };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).map_err(mls)?;
        let (public, _) = PublicGroup::from_external(&crypto, &storage, tree, info, ProposalStore::new()).map_err(mls)?;
        validate_group_state(public.group_context().extensions(), public.members(), &pins)?;
        Ok(Self { crypto, storage, public, log: Vec::new(), group_info: group_info.to_vec(), pins })
    }
    pub fn epoch(&self) -> u64 {
        self.public.group_context().epoch().as_u64()
    }
    /// Commits must target the current epoch and verify under the public tree; app messages must
    /// target the current epoch. Accepted messages are appended to the ordered log.
    pub fn submit(&mut self, bytes: &[u8]) -> Result<Submit> {
        bounded("message", bytes, limits::MAX_HANDSHAKE_BYTES)?;
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| SpikeError::Ds(format!("decode: {e:?}")))?;
        let protocol = message.try_into_protocol_message().map_err(|e| SpikeError::Ds(format!("{e:?}")))?;
        let epoch = protocol.epoch().as_u64();
        if epoch != self.epoch() {
            return Ok(Submit::Conflict { epoch: self.epoch(), seq: self.log.len() });
        }
        match protocol {
            ProtocolMessage::PublicMessage(public) => {
                let processed = self.public.process_message(&self.crypto, *public).map_err(|e| SpikeError::Ds(format!("rejected: {e:?}")))?;
                let sender = processed.sender().clone();
                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        // Same validator as clients, before merging or logging anything.
                        validate_staged(self.public.group_context().extensions(), self.public.members(), &sender, &staged, &self.pins)?;
                        self.public.merge_commit(&self.storage, *staged).map_err(|e| SpikeError::Ds(format!("{e:?}")))?;
                    }
                    _ => return Err(SpikeError::Policy("only commits may be sent as public messages".into())),
                }
            }
            // Application data: the DS sees only the epoch and the sender's (encrypted) metadata.
            ProtocolMessage::PrivateMessage(_) => bounded("application message", bytes, limits::MAX_APPLICATION_BYTES)?,
        }
        self.log.push(bytes.to_vec());
        Ok(Submit::Accepted(self.log.len() - 1))
    }
    /// Secret-free check that the DS state stays consistent with clients.
    pub fn tree(&self) -> Vec<u8> {
        self.public.export_ratchet_tree().tls_serialize_detached().unwrap()
    }
    pub fn rows_with_label(&self, label: &[u8]) -> usize {
        self.storage.values.read().unwrap().keys().filter(|k| k.starts_with(label)).count()
    }
}
