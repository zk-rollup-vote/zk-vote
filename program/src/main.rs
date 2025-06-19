#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let raw_votes_data = sp1_zkvm::io::read::<String>();
    let group_id = sp1_zkvm::io::read::<String>();

    let mut hash = [0u8; 32];
    let mut keccak256 = Keccak::v256();
    keccak256.update(&raw_votes_data.as_bytes());
    keccak256.finalize(&mut hash);

    let hex_string = hex::encode(hash);
    let fmt_group_id = group_id.strip_prefix("0x").unwrap();

    if hex_string != fmt_group_id {
        panic!("Invalid hash data");
    }
}