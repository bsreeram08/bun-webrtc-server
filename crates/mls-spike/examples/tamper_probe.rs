//! Flip each byte of a commit and see which tampering the secret-free DS detects vs a member.
use mls_spike::*;

fn main() {
    let mut pins = Pins::default();
    let alice = Account::new("alice");
    let bob = Account::new("bob");
    alice.pin(&mut pins);
    bob.pin(&mut pins);
    let mut a = Device::new(&alice, "phone");
    a.create_group(b"g", &Roles { admins: vec!["alice".into()], join_policy: JoinPolicy::Invite }).unwrap();
    let mut b = Device::new(&bob, "phone");
    let (_commit, welcome) = a.add(&[b.key_package(false)]).unwrap();
    a.merge_own(&pins).unwrap();
    b.join(&welcome, &a.tree(), &pins).unwrap();
    let info = a.group_info();
    let tree = a.tree();
    let good = a.self_update().unwrap();
    let (mut ds_accepts_client_rejects, mut both_reject) = (Vec::new(), 0usize);
    for off in 0..good.len() {
        let mut t = good.clone();
        t[off] ^= 0x01;
        let mut ds = Ds::new(&info, &tree, pins.clone()).unwrap();
        if matches!(ds.submit(&t), Ok(Submit::Accepted(_))) {
            // The member would process it from the log. Does it reject? (It must not advance.)
            let before = b.epoch();
            match b.receive(&t, &pins) {
                Err(_) => ds_accepts_client_rejects.push(good.len() - off),
                Ok(_) => {
                    println!("member ACCEPTED tamper at offset-from-end {} (epoch {before} -> {})", good.len() - off, b.epoch());
                    return;
                }
            }
        } else {
            both_reject += 1;
        }
    }
    println!("commit {} bytes: DS rejected {both_reject} tamperings; DS accepted but member rejected {} (offsets from end: {:?})", good.len(), ds_accepts_client_rejects.len(), ds_accepts_client_rejects);
}
