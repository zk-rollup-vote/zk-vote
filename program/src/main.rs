#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::{sol, SolType};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Vote {
    pub id_tps: String,
    pub city_name: String,
    pub district_name: String,
    pub vote_result: [Candidate; 2],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Candidate {
    pub name: String,
    pub vote: u64,
}

sol! {
    #[derive(Debug)]
    struct PublicValuesStruct {
        uint256 groupId;
        uint256 candidateA;
        uint256 candidateB;
        uint256 candidateC;
    }
  }

pub fn main() {
    let raw_votes_data = sp1_zkvm::io::read::<String>();
    let group_id = sp1_zkvm::io::read::<String>();

    let votes: Vec<Vote> = serde_json::from_str(&raw_votes_data).unwrap();
    let hash = keccak256(&raw_votes_data);
    let hex_string = hex::encode(hash);
    let fmt_group_id = group_id.strip_prefix("0x").unwrap();

    if hex_string != fmt_group_id {
        panic!("Invalid hash data");
    }

    let group_id: U256 = U256::from_be_bytes(hash.into());
    let mut total_candidate_a = 0;
    let mut total_candidate_b = 0;

    for vote in votes {
        total_candidate_a += vote.vote_result[0].vote;
        total_candidate_b += vote.vote_result[1].vote;    
    }

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        groupId: group_id,
        candidateA: U256::from(total_candidate_a),
        candidateB: U256::from(total_candidate_b),
        candidateC: U256::from(0),
    });

    sp1_zkvm::io::commit_slice(&bytes);
}