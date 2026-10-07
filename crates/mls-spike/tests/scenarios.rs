//! Plan §2 scenarios against OpenMLS 0.9 with a secret-free delivery service in the loop, plus the
//! policy-layer regressions (everything OpenMLS does not enforce for us).

use std::collections::BTreeMap;

use mls_spike::*;
use openmls::prelude::tls_codec::Serialize as _;

/// Devices plus a delivery service; every device reads the DS log from its own cursor.
struct World {
    ds: Ds,
    devices: BTreeMap<String, Device>,
    cursors: BTreeMap<String, usize>,
    authors: Vec<String>,
    pins: Pins,
}

impl World {
    fn new(creator: Device, pins: Pins) -> Self {
        let ds = Ds::new(&creator.group_info(), &creator.tree(), pins.clone()).unwrap();
        let name = format!("{}/{}", creator.user_id, creator.device_id);
        let mut world = Self { ds, devices: BTreeMap::new(), cursors: BTreeMap::new(), authors: Vec::new(), pins };
        world.devices.insert(name.clone(), creator);
        world.cursors.insert(name, 0);
        world
    }
    fn dev(&mut self, name: &str) -> &mut Device {
        self.devices.get_mut(name).unwrap()
    }
    fn submit(&mut self, name: &str, bytes: &[u8]) -> Result<Submit> {
        let result = self.ds.submit(bytes)?;
        if let Submit::Accepted(_) = result {
            self.authors.push(name.into());
        }
        Ok(result)
    }
    /// Submit our own commit; on acceptance merge it (validated) and refresh the DS GroupInfo.
    fn commit(&mut self, name: &str, bytes: &[u8]) {
        assert!(matches!(self.submit(name, bytes).unwrap(), Submit::Accepted(_)), "commit by {name} was not accepted");
        let pins = self.pins.clone();
        self.dev(name).merge_own(&pins).unwrap();
        self.ds.group_info = self.dev(name).group_info();
    }
    fn send(&mut self, name: &str, text: &str) {
        let bytes = self.dev(name).send(text);
        assert!(matches!(self.submit(name, &bytes).unwrap(), Submit::Accepted(_)));
    }
    /// A device that joined by external commit: its commit is already in the log.
    fn adopt_external(&mut self, device: Device, commit: &[u8]) {
        let name = format!("{}/{}", device.user_id, device.device_id);
        assert!(matches!(self.ds.submit(commit).unwrap(), Submit::Accepted(_)));
        self.authors.push(name.clone());
        self.cursors.insert(name.clone(), self.ds.log.len());
        self.ds.group_info = device.group_info();
        self.devices.insert(name, device);
    }
    /// Deliver the log to everyone (skipping their own entries). Returns texts received per device.
    fn sync(&mut self) -> BTreeMap<String, Vec<String>> {
        let mut out = BTreeMap::new();
        let names: Vec<String> = self.devices.keys().cloned().collect();
        for name in names {
            let from = self.cursors[&name];
            let mut got = Vec::new();
            for seq in from..self.ds.log.len() {
                if self.authors[seq] == name {
                    continue;
                }
                let bytes = self.ds.log[seq].clone();
                let pins = self.pins.clone();
                if let Some(text) = self.dev(&name).receive(&bytes, &pins).unwrap_or_else(|e| panic!("{name} failed on seq {seq}: {e}")) {
                    got.push(text);
                }
            }
            self.cursors.insert(name.clone(), self.ds.log.len());
            out.insert(name, got);
        }
        out
    }
    fn join(&mut self, device: Device, welcome: &[u8], tree: &[u8]) {
        let name = format!("{}/{}", device.user_id, device.device_id);
        let mut device = device;
        device.join(welcome, tree, &self.pins).unwrap();
        self.cursors.insert(name.clone(), self.ds.log.len());
        self.devices.insert(name, device);
    }
    fn authenticators(&self) -> Vec<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = self
            .devices
            .values()
            .filter(|d| d.in_group() && d.group().is_active())
            .map(|d| d.group().epoch_authenticator().as_slice().to_vec())
            .collect();
        all.dedup();
        all
    }
}

struct Setup {
    world: World,
    accounts: BTreeMap<String, Account>,
}

/// alice (admin) creates a group and adds bob and carol; everyone has 2 devices.
fn three_users_two_devices(policy: JoinPolicy) -> Setup {
    let mut pins = Pins::default();
    let accounts: BTreeMap<String, Account> = ["alice", "bob", "carol", "dave", "erin"].iter().map(|u| (u.to_string(), Account::new(u))).collect();
    for a in accounts.values() {
        a.pin(&mut pins);
    }
    let mut creator = Device::new(&accounts["alice"], "phone");
    creator.create_group(b"general", &Roles { admins: vec!["alice".into()], join_policy: policy }).unwrap();
    let mut world = World::new(creator, pins);
    let joiners: Vec<Device> = [("alice", "laptop"), ("bob", "phone"), ("bob", "laptop"), ("carol", "phone"), ("carol", "laptop")]
        .iter()
        .map(|(u, d)| Device::new(&accounts[*u], d))
        .collect();
    let kps: Vec<KeyPackage> = joiners.iter().map(|d| d.key_package(false)).collect();
    let (commit, welcome) = world.dev("alice/phone").add(&kps).unwrap();
    world.commit("alice/phone", &commit);
    let tree = world.dev("alice/phone").tree();
    for device in joiners {
        world.join(device, &welcome, &tree);
    }
    Setup { world, accounts }
}

fn is_rejection(result: &Result<impl std::fmt::Debug>) -> bool {
    matches!(result, Err(SpikeError::Policy(_)) | Err(SpikeError::Cert(_)))
}

/// Submit to the DS and to one client; both must reject with a policy/cert error.
fn both_reject(world: &mut World, client: &str, bytes: &[u8]) {
    let ds = world.ds.submit(bytes);
    assert!(is_rejection(&ds), "DS: {ds:?}");
    let pins = world.pins.clone();
    let got = world.dev(client).receive(bytes, &pins);
    assert!(is_rejection(&got), "client: {got:?}");
}

// --- Plan §2 scenarios ---------------------------------------------------------------------------

#[test]
fn group_of_three_users_with_two_devices_each_exchanges_messages() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    assert_eq!(world.dev("alice/phone").group().members().count(), 6);
    world.send("bob/laptop", "hi from bob's laptop");
    world.send("carol/phone", "hi from carol");
    let got = world.sync();
    assert_eq!(got["alice/phone"], vec!["hi from bob's laptop", "hi from carol"]);
    assert_eq!(got["bob/phone"], vec!["hi from bob's laptop", "hi from carol"]);
    assert_eq!(got["carol/laptop"], vec!["hi from bob's laptop", "hi from carol"]);
    assert_eq!(got["bob/laptop"], vec!["hi from carol"]);
    assert_eq!(world.authenticators().len(), 1, "everyone agrees on the epoch");
}

#[test]
fn a_removed_device_cannot_decrypt_afterwards() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let leaf = world.dev("alice/phone").leaf_of("carol", "laptop");
    let commit = world.dev("alice/phone").remove(&[leaf]).unwrap();
    world.commit("alice/phone", &commit);
    let pins = world.pins.clone();
    let removal = world.ds.log.last().unwrap().clone();
    world.dev("carol/laptop").receive(&removal, &pins).unwrap();
    assert!(!world.dev("carol/laptop").group().is_active());
    let mut laptop = world.devices.remove("carol/laptop").unwrap();
    world.sync();
    world.send("bob/phone", "after carol's laptop left");
    let bytes = world.ds.log.last().unwrap().clone();
    assert!(laptop.receive(&bytes, &pins).is_err(), "removed device must not decrypt new epochs");
    assert_eq!(world.sync()["carol/phone"], vec!["after carol's laptop left"]);
}

#[test]
fn a_self_update_rotates_the_leaf_and_the_epoch_secret() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let before_auth = world.authenticators();
    let leaf = world.dev("bob/phone").group().own_leaf_index();
    let before_key = world.dev("alice/phone").group().members().find(|m| m.index == leaf).unwrap().encryption_key;
    let commit = world.dev("bob/phone").self_update().unwrap();
    world.commit("bob/phone", &commit);
    world.sync();
    let after_key = world.dev("alice/phone").group().members().find(|m| m.index == leaf).unwrap().encryption_key;
    assert_ne!(before_key, after_key, "bob's leaf HPKE key changed (PCS)");
    assert_ne!(before_auth, world.authenticators());
    assert_eq!(world.authenticators().len(), 1);
}

#[test]
fn concurrent_commits_are_sequenced_and_the_loser_rebuilds() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let epoch = world.ds.epoch();
    let bob = world.dev("bob/phone").self_update().unwrap();
    let carol = world.dev("carol/phone").self_update().unwrap();
    world.commit("bob/phone", &bob);
    // Carol's commit targets the old epoch: the DS answers 409 with where to read from.
    assert_eq!(world.submit("carol/phone", &carol).unwrap(), Submit::Conflict { epoch: epoch + 1, seq: world.ds.log.len() });
    world.dev("carol/phone").abandon_own();
    world.sync();
    let retry = world.dev("carol/phone").self_update().unwrap();
    world.commit("carol/phone", &retry);
    world.sync();
    assert_eq!(world.ds.epoch(), epoch + 2);
    assert_eq!(world.authenticators().len(), 1);
    world.send("carol/phone", "made it");
    assert_eq!(world.sync()["alice/laptop"], vec!["made it"]);
}

#[test]
fn a_public_channel_accepts_an_external_self_join() {
    let Setup { mut world, accounts } = three_users_two_devices(JoinPolicy::Open);
    let mut dave = Device::new(&accounts["dave"], "phone");
    let commit = dave.join_external(&world.ds.group_info.clone(), &world.ds.tree(), &world.pins).unwrap();
    world.adopt_external(dave, &commit);
    world.sync();
    world.send("dave/phone", "hello channel");
    assert_eq!(world.sync()["bob/laptop"], vec!["hello channel"]);
    assert_eq!(world.authenticators().len(), 1);
}

#[test]
fn an_invite_only_group_rejects_a_stranger_but_accepts_an_own_new_device() {
    let Setup { mut world, accounts } = three_users_two_devices(JoinPolicy::Invite);
    let info = world.ds.group_info.clone();
    let tree = world.ds.tree();
    // The joining client itself refuses to self-join (same validator), before anything is sent.
    let mut stranger = Device::new(&accounts["dave"], "phone");
    assert!(matches!(stranger.join_external(&info, &tree, &world.pins), Err(SpikeError::Policy(_))));
    assert!(!stranger.in_group());
    let mut tablet = Device::new(&accounts["alice"], "tablet");
    let commit = tablet.join_external(&info, &tree, &world.pins).unwrap();
    world.adopt_external(tablet, &commit);
    world.sync();
    assert_eq!(world.dev("bob/phone").group().members().count(), 7);
}

#[test]
fn a_device_that_lost_its_state_resyncs_by_replacing_its_own_leaf() {
    let Setup { mut world, accounts } = three_users_two_devices(JoinPolicy::Invite);
    let old = world.devices.remove("bob/laptop").unwrap();
    // Same leaf signature key (kept in the platform keystore), fresh group state.
    let keystore = serde_json::to_vec(&old.signer).unwrap();
    drop(old);
    let signer: openmls_basic_credential::SignatureKeyPair = serde_json::from_slice(&keystore).unwrap();
    let mut fresh = Device::with_signer(&accounts["bob"], "laptop", signer, SpikeProvider::default());
    let commit = fresh.join_external(&world.ds.group_info.clone(), &world.ds.tree(), &world.pins).unwrap();
    world.adopt_external(fresh, &commit);
    world.sync();
    assert_eq!(world.dev("alice/phone").group().members().count(), 6, "old leaf removed in the same commit");
    world.send("alice/phone", "welcome back");
    assert_eq!(world.sync()["bob/laptop"], vec!["welcome back"]);
}

#[test]
fn a_last_resort_key_package_survives_reuse_and_a_normal_one_does_not() {
    let mut pins = Pins::default();
    let alice = Account::new("alice");
    let erin = Account::new("erin");
    alice.pin(&mut pins);
    erin.pin(&mut pins);
    let mut erin_dev = Device::new(&erin, "phone");
    let last_resort = erin_dev.key_package(true);
    assert!(last_resort.last_resort());
    let normal = erin_dev.key_package(false);
    for (id, kp, should_join) in [(&b"g1"[..], &last_resort, true), (b"g2", &last_resort, true), (b"g3", &normal, true), (b"g4", &normal, false)] {
        let mut a = Device::new(&alice, &format!("dev-{}", String::from_utf8_lossy(id)));
        a.create_group(id, &Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Invite }).unwrap();
        let (_, welcome) = a.add(&[kp.clone()]).unwrap();
        a.merge_own(&pins).unwrap();
        let joined = erin_dev.join(&welcome, &a.tree(), &pins);
        assert_eq!(joined.is_ok(), should_join, "group {id:?}: {joined:?}");
    }
}

#[test]
fn the_delivery_service_rejects_tampered_and_stale_commits_without_secrets() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let probe = world.dev("bob/phone").self_update().unwrap();
    world.dev("bob/phone").abandon_own();
    let mut commit = probe.clone();
    let signature_byte = commit.len() - 100; // the 64-byte Ed25519 signature precedes the two 32-byte tags
    commit[signature_byte] ^= 0x55;
    assert!(world.ds.submit(&commit).is_err(), "tampered signature must be rejected");
    // The DS cannot check the confirmation/membership tags (they need epoch secrets): a commit with a
    // corrupted tag is sequenced, and every member then rejects it. See FINDINGS "poison commits".
    let mut poisoned = probe.clone();
    let tag_byte = poisoned.len() - 5;
    poisoned[tag_byte] ^= 0x55;
    let mut probe_ds = Ds::new(&world.ds.group_info, &world.ds.tree(), world.pins.clone()).unwrap();
    assert!(matches!(probe_ds.submit(&poisoned).unwrap(), Submit::Accepted(_)), "DS cannot detect a bad tag");
    let pins = world.pins.clone();
    assert!(world.dev("carol/phone").receive(&poisoned, &pins).is_err(), "members do detect it");
    let good = world.dev("bob/phone").self_update().unwrap();
    world.commit("bob/phone", &good);
    assert!(matches!(world.ds.submit(&good).unwrap(), Submit::Conflict { .. }), "replay is stale");
    world.sync();
    assert_eq!(world.ds.tree(), world.dev("carol/laptop").tree());
    for label in [&b"EncryptionKeyPair"[..], b"SignatureKeyPair", b"EpochSecrets", b"MessageSecrets", b"EpochKeyPairs", b"KeyPackage"] {
        assert_eq!(world.ds.rows_with_label(label), 0, "{}", String::from_utf8_lossy(label));
    }
}

#[test]
fn group_state_round_trips_through_the_journaled_kv_store() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let mut kv = MemKv::default();
    let first = world.dev("carol/phone").provider.flush();
    kv.apply(&first);
    world.send("carol/phone", "before restart");
    let second = world.dev("carol/phone").provider.flush();
    assert!(!second.is_empty() && second.len() < first.len(), "an app message touches only a few rows ({} vs {})", second.len(), first.len());
    kv.apply(&second);
    world.sync();
    kv.apply(&world.dev("carol/phone").provider.flush());

    // "Process restart": serialize the KV, drop the device, reload from bytes through the gated loader.
    let saved = kv.to_bytes();
    let old = world.devices.remove("carol/phone").unwrap();
    let group_id = old.group().group_id().clone();
    let public = old.signer.public().to_vec();
    drop(old);
    let provider = SpikeProvider::preload(&MemKv::from_bytes(&saved), b"");
    let restored = Device::load("carol", "phone", provider, &group_id, &public, &world.pins).unwrap();
    world.devices.insert("carol/phone".into(), restored);
    world.send("alice/phone", "after restart");
    assert_eq!(world.sync()["carol/phone"], vec!["after restart"]);
    world.send("carol/phone", "still here");
    assert_eq!(world.sync()["bob/phone"], vec!["still here"]);
    // A persisted group cannot be loaded as somebody else's device.
    let provider = SpikeProvider::preload(&MemKv::from_bytes(&saved), b"");
    assert!(matches!(Device::load("bob", "phone", provider, &group_id, &public, &world.pins), Err(SpikeError::Cert(_))));
}

// --- Gate parity: every membership-changing message kind, DS verdict == client verdict -----------

type Case = (&'static str, bool, fn(&mut Setup) -> Vec<u8>);

fn cases() -> Vec<Case> {
    vec![
        ("admin adds a new user", true, |s| {
            let kp = Device::new(&s.accounts["erin"], "phone").key_package(false);
            s.world.dev("alice/phone").add(&[kp]).unwrap().0
        }),
        ("non-admin adds a new user (invite-only)", false, |s| {
            let kp = Device::new(&s.accounts["erin"], "phone").key_package(false);
            s.world.dev("bob/phone").add(&[kp]).unwrap().0
        }),
        ("non-admin adds their own new device", true, |s| {
            let kp = Device::new(&s.accounts["bob"], "tablet").key_package(false);
            s.world.dev("bob/phone").add(&[kp]).unwrap().0
        }),
        ("non-admin removes another user", false, |s| {
            let leaf = s.world.dev("bob/phone").leaf_of("carol", "phone");
            s.world.dev("bob/phone").remove(&[leaf]).unwrap()
        }),
        ("non-admin removes their own other device", true, |s| {
            let leaf = s.world.dev("bob/phone").leaf_of("bob", "laptop");
            s.world.dev("bob/phone").remove(&[leaf]).unwrap()
        }),
        ("self-update", true, |s| s.world.dev("bob/phone").self_update().unwrap()),
        ("update swapping the leaf's device id", false, |s| {
            let key = s.world.dev("bob/phone").signer.public().to_vec();
            let cert = DeviceCert::issue(&s.accounts["bob"].aik, "bob", "laptop", &key);
            let swapped = CredentialWithKey { credential: BasicCredential::new(cert.encode()).into(), signature_key: key.into() };
            s.world.dev("bob/phone").self_update_as(swapped).unwrap()
        }),
        ("non-admin changes roles", false, |s| {
            let ext = group_extensions(&Roles { admins: vec!["bob".into()], join_policy: JoinPolicy::Open });
            s.world.dev("bob/phone").set_extensions(ext).unwrap()
        }),
        ("admin changes roles", true, |s| {
            let ext = group_extensions(&Roles { admins: vec!["alice".into(), "bob".into()], join_policy: JoinPolicy::Open });
            s.world.dev("alice/phone").set_extensions(ext).unwrap()
        }),
        ("non-admin opens the group AND adds a stranger in one commit", false, |s| {
            let ext = group_extensions(&Roles { admins: vec!["bob".into()], join_policy: JoinPolicy::Open });
            let kp = Device::new(&s.accounts["erin"], "phone").key_package(false);
            s.world.dev("bob/phone").commit(vec![kp], vec![], Some(ext)).unwrap()
        }),
        ("admin opens the group AND adds a stranger in one commit", true, |s| {
            let ext = group_extensions(&Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Open });
            let kp = Device::new(&s.accounts["erin"], "phone").key_package(false);
            s.world.dev("alice/phone").commit(vec![kp], vec![], Some(ext)).unwrap()
        }),
        ("admin drops the roles extension", false, |s| s.world.dev("alice/phone").set_extensions(Extensions::empty()).unwrap()),
        ("standalone proposal", false, |s| {
            let leaf = s.world.dev("bob/phone").leaf_of("bob", "laptop");
            s.world.dev("bob/phone").propose_remove(leaf).unwrap()
        }),
        ("too many proposals", false, |s| {
            let kps: Vec<KeyPackage> = (0..=limits::MAX_PROPOSALS).map(|i| Device::new(&s.accounts["alice"], &format!("x{i}")).key_package(false)).collect();
            s.world.dev("alice/phone").add(&kps).unwrap().0
        }),
        ("add with a user id differing only in case", false, |s| {
            let impostor = Account::new("Erin");
            impostor.pin(&mut s.world.pins); // even if a pin existed, the id is not canonical
            let kp = Device::new(&impostor, "phone").key_package(false);
            s.world.dev("alice/phone").add(&[kp]).unwrap().0
        }),
        ("add with a canonical id but a re-encoded certificate", false, |s| {
            let mut device = Device::new(&s.accounts["erin"], "phone");
            let cert = DeviceCert::issue(&s.accounts["erin"].aik, "erin", "phone", device.signer.public());
            let spaced = serde_json::to_vec_pretty(&cert).unwrap(); // same fields, different bytes
            device.credential = CredentialWithKey { credential: BasicCredential::new(spaced).into(), signature_key: device.signer.public().into() };
            let kp = device.key_package(false);
            s.world.dev("alice/phone").add(&[kp]).unwrap().0
        }),
        ("add signed by an unpinned account key", false, |s| {
            let kp = Device::new(&Account::new("erin"), "phone").key_package(false);
            s.world.dev("alice/phone").add(&[kp]).unwrap().0
        }),
    ]
}

#[test]
fn every_entry_point_reaches_the_same_verdict() {
    for (name, expected, make) in cases() {
        let mut setup = three_users_two_devices(JoinPolicy::Invite);
        let bytes = make(&mut setup);
        let world = &mut setup.world;
        let pins = world.pins.clone();
        let ds = world.ds.submit(&bytes);
        let client = world.dev("carol/phone").receive(&bytes, &pins);
        let ds_ok = matches!(ds, Ok(Submit::Accepted(_)));
        assert_eq!(ds_ok, client.is_ok(), "{name}: DS {ds:?} vs client {client:?}");
        assert_eq!(ds_ok, expected, "{name}: expected accepted={expected}, got DS {ds:?}");
        if !expected {
            assert!(is_rejection(&ds) && is_rejection(&client), "{name}: rejected for the wrong reason: {ds:?} / {client:?}");
        }
    }
}

#[test]
fn the_committer_runs_the_same_gate_before_merging_its_own_commit() {
    for (name, expected, make) in cases() {
        let mut setup = three_users_two_devices(JoinPolicy::Invite);
        let pins = setup.world.pins.clone();
        let _ = make(&mut setup);
        // Each case's committer is the first device with a pending commit.
        let committer = setup.world.devices.iter().find(|(_, d)| d.group().pending_commit().is_some()).map(|(n, _)| n.clone());
        let Some(committer) = committer else { continue }; // standalone proposal: nothing to merge
        let merged = setup.world.dev(&committer).merge_own(&pins);
        assert_eq!(merged.is_ok(), expected, "{name}: merge_own {merged:?}");
    }
}

// --- Group-state gates (Welcome, DS bootstrap, external join, restart) ----------------------------

fn raw_group(creator: &Device, extensions: Extensions<GroupContext>) -> MlsGroup {
    MlsGroup::builder()
        .with_group_id(GroupId::from_slice(b"raw"))
        .ciphersuite(CS)
        .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .with_capabilities(capabilities())
        .with_group_context_extensions(extensions)
        .build(&creator.provider, &creator.signer, creator.credential.clone())
        .unwrap()
}

#[test]
fn groups_without_valid_roles_are_refused_by_welcome_ds_and_external_join() {
    let (alice, bob) = (Account::new("alice"), Account::new("bob"));
    let mut pins = Pins::default();
    alice.pin(&mut pins);
    bob.pin(&mut pins);
    for extensions in [Extensions::empty(), group_extensions(&Roles { admins: vec![], join_policy: JoinPolicy::Open })] {
        let creator = Device::new(&alice, "phone");
        let mut group = raw_group(&creator, extensions);
        let mut joiner = Device::new(&bob, "phone");
        let (_, welcome, _) = group.add_members(&creator.provider, &creator.signer, &[joiner.key_package(false)]).unwrap();
        group.merge_pending_commit(&creator.provider).unwrap();
        let welcome = welcome.tls_serialize_detached().unwrap();
        let tree = group.export_ratchet_tree().tls_serialize_detached().unwrap();
        let info: MlsMessageOut = group.export_group_info(creator.provider.crypto(), &creator.signer, false).unwrap();
        let info = info.tls_serialize_detached().unwrap();
        assert!(matches!(joiner.join(&welcome, &tree, &pins), Err(SpikeError::Policy(_))), "welcome");
        assert!(matches!(Ds::new(&info, &tree, pins.clone()), Err(SpikeError::Policy(_))), "DS bootstrap");
        assert!(matches!(Device::new(&bob, "laptop").join_external(&info, &tree, &pins), Err(SpikeError::Policy(_))), "external join");
    }
}

#[test]
fn a_welcome_listing_an_unverifiable_member_is_refused() {
    let alice = Account::new("alice");
    let bob = Account::new("bob");
    let mut pins = Pins::default();
    bob.pin(&mut pins); // alice's account key is unknown to bob
    let mut creator = Device::new(&alice, "phone");
    creator.create_group(b"g", &Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Invite }).unwrap();
    let mut joiner = Device::new(&bob, "phone");
    let (_, welcome) = creator.add(&[joiner.key_package(false)]).unwrap();
    // The creator's own merge needs the pins that bob lacks, so use a directory that knows both.
    let mut both = pins.clone();
    alice.pin(&mut both);
    creator.merge_own(&both).unwrap();
    assert!(matches!(joiner.join(&welcome, &creator.tree(), &pins), Err(SpikeError::Cert(_))));
}

#[test]
fn context_extensions_are_whitelisted_and_decoded_strictly() {
    let roles = Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Invite };
    assert!(validate_context(&group_extensions(&roles)).is_ok());
    // Unknown extension types are refused even next to valid roles.
    let required = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(ROLES_EXT)], &[], &[]);
    let with_unknown = Extensions::from_vec(vec![Extension::RequiredCapabilities(required.clone()), roles.extension(), Extension::Unknown(0xF0FF, UnknownExtension(vec![1]))]).unwrap();
    assert!(matches!(validate_context(&with_unknown), Err(SpikeError::Policy(_))));
    // Duplicate extension types: OpenMLS itself refuses to build them (and TLS-decoding rejects them).
    assert!(Extensions::<GroupContext>::from_vec(vec![roles.extension(), roles.extension()]).is_err());
    // Roles JSON: duplicate keys, unknown keys, non-canonical spacing and non-canonical ids all fail.
    for raw in [
        &br#"{"admins":["alice"],"join_policy":"Invite","admins":["mallory"]}"#[..],
        br#"{"admins":["alice"],"join_policy":"Invite","owner":"mallory"}"#,
        br#"{ "admins":["alice"],"join_policy":"Invite"}"#,
        br#"{"admins":["Alice"],"join_policy":"Invite"}"#,
        // "alice" with its first letter as a JSON escape: decodes to the same id, different bytes.
        &[b"{\"admins\":[\"".as_slice(), &[0x5c], b"u0061lice\"],\"join_policy\":\"Invite\"}"].concat(),
    ] {
        let ext = Extensions::from_vec(vec![Extension::RequiredCapabilities(required.clone()), Extension::Unknown(ROLES_EXT, UnknownExtension(raw.to_vec()))]).unwrap();
        assert!(matches!(validate_context(&ext), Err(SpikeError::Policy(_))), "{}", String::from_utf8_lossy(raw));
    }
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    let Setup { mut world, .. } = three_users_two_devices(JoinPolicy::Invite);
    let huge = vec![0u8; limits::MAX_HANDSHAKE_BYTES + 1];
    both_reject(&mut world, "carol/phone", &huge);
    let mut fresh = Device::new(&Account::new("xyz"), "y");
    assert!(matches!(fresh.join(&vec![0u8; limits::MAX_WELCOME_BYTES + 1], b"", &world.pins), Err(SpikeError::Policy(_))));
    assert!(matches!(fresh.join_external(&vec![0u8; limits::MAX_GROUP_INFO_BYTES + 1], b"", &world.pins), Err(SpikeError::Policy(_))));
    assert!(matches!(Ds::new(b"", &vec![0u8; limits::MAX_TREE_BYTES + 1], world.pins.clone()), Err(SpikeError::Policy(_))));
}
