//! Cost of the plan's group sizes. Native: `cargo run --release --bin bench`.
//! Wasm (V8 via node's WASI): see FINDINGS for the build + run commands.
use std::time::Instant;

use mls_spike::*;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let sizes: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let sizes = if sizes.is_empty() { vec![10, 100, 1000, 2500] } else { sizes };
    println!("| leaves | build group, 128-add batches (ms) | Welcome bytes (last batch) | join: process Welcome (ms) | verify N certs (ms) | tree bytes | add-1 commit+Welcome (ms) | add-1 commit bytes | add-1 Welcome bytes | member processes add-1 (ms) | joiner processes add-1 Welcome (ms) | self-update commit (ms) | member processes update (ms) | DS validates update (ms) | DS bootstrap (ms) | encrypt msg (µs) | decrypt msg (µs) | member store bytes | journal per msg (rows / bytes) | journal per commit (rows / bytes) |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for n in sizes {
        let mut pins = Pins::default();
        let alice = Account::new("alice");
        alice.pin(&mut pins);
        let mut creator = Device::new(&alice, "creator");
        creator.create_group(b"bench", &Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Invite }).unwrap();
        // n - 1 leaves = creator + (n - 3) others + member B (one account's devices keep setup
        // cheap); the measured add-1 then brings the group to exactly n. Invites go in batches of
        // MAX_PROPOSALS, as production will; B arrives in the last batch, so its Welcome describes
        // the full tree.
        let mut member = Device::new(&alice, "member");
        let mut kps: Vec<KeyPackage> = (0..n.saturating_sub(3)).map(|i| Device::new(&alice, &format!("d{i}")).key_package(false)).collect();
        kps.push(member.key_package(false));
        let t = Instant::now();
        let mut welcome = Vec::new();
        for batch in kps.chunks(limits::MAX_PROPOSALS) {
            let (_commit, w) = creator.add(batch).unwrap();
            creator.merge_own(&pins).unwrap();
            welcome = w;
        }
        let bulk_add = ms(t);
        let tree = creator.tree();
        let t = Instant::now();
        member.join(&welcome, &tree, &pins).unwrap(); // includes verifying all n member certificates
        let join = ms(t);
        let t = Instant::now();
        pins.verify_members(member.group().members()).unwrap();
        let verify = ms(t);

        // Add one more member.
        let joiner_dev = Device::new(&alice, "joiner");
        let kp = joiner_dev.key_package(false);
        let mut joiner = joiner_dev;
        let t = Instant::now();
        let (commit1, welcome1) = creator.add(&[kp]).unwrap();
        let add1 = ms(t);
        creator.merge_own(&pins).unwrap();
        let t = Instant::now();
        member.receive(&commit1, &pins).unwrap();
        let member_add1 = ms(t);
        let tree1 = creator.tree();
        let t = Instant::now();
        joiner.join(&welcome1, &tree1, &pins).unwrap();
        let joiner_welcome = ms(t);

        // Self-update and DS validation.
        let t = Instant::now();
        let ds = Ds::new(&creator.group_info(), &creator.tree(), pins.clone());
        let ds_boot = ms(t);
        let mut ds = ds.unwrap();
        let t = Instant::now();
        let update = creator.self_update().unwrap();
        let upd = ms(t);
        let t = Instant::now();
        assert!(matches!(ds.submit(&update).unwrap(), Submit::Accepted(_)));
        let ds_validate = ms(t);
        creator.merge_own(&pins).unwrap();
        let t = Instant::now();
        member.receive(&update, &pins).unwrap();
        let member_upd = ms(t);

        // Application messages.
        let rounds = 200;
        let mut msgs = Vec::with_capacity(rounds);
        let t = Instant::now();
        for i in 0..rounds {
            msgs.push(creator.send(&format!("message {i} with a typical chat length payload")));
        }
        let enc = ms(t) * 1000.0 / rounds as f64;
        let size = |writes: &[Write]| -> (usize, usize) {
            (writes.len(), writes.iter().map(|w| match w {
                Write::Put(k, v) => k.len() + v.len(),
                Write::Delete(k) => k.len(),
            }).sum())
        };
        let mut kv = MemKv::default();
        kv.apply(&member.provider.flush());
        let t = Instant::now();
        for m in &msgs {
            member.receive(m, &pins).unwrap();
        }
        let dec = ms(t) * 1000.0 / rounds as f64;
        let (_, after_msgs) = size(&member.provider.flush());
        // Journal cost of one received message and of one processed commit, separately.
        let one = creator.send("one more");
        member.receive(&one, &pins).unwrap();
        let (msg_rows, msg_bytes) = size(&member.provider.flush());
        let upd2 = creator.self_update().unwrap();
        creator.merge_own(&pins).unwrap();
        member.receive(&upd2, &pins).unwrap();
        let (commit_rows, commit_bytes) = size(&member.provider.flush());
        let _ = after_msgs;

        println!(
            "| {n} | {bulk_add:.1} | {} | {join:.1} | {verify:.1} | {} | {add1:.1} | {} | {} | {member_add1:.1} | {joiner_welcome:.1} | {upd:.1} | {member_upd:.1} | {ds_validate:.1} | {ds_boot:.1} | {enc:.0} | {dec:.0} | {} | {msg_rows} / {msg_bytes} | {commit_rows} / {commit_bytes} |",
            welcome.len(),
            tree.len(),
            commit1.len(),
            welcome1.len(),
            kv.bytes(),
        );
    }
}
