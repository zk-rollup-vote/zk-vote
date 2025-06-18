#[warn(unused_imports)]
use alloy_sol_types::{sol, SolType};
use clap::Parser;
use reqwest;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::io;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKVOTE_ELF: &[u8] =
    include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Votes {
    pub data: Vec<Vote>,
}

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

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    println!("Welcome to the zkVote");
    println!("You will be asked to input BASE URL and Group ID.");

    println!("{}", "What is your BASE URL?");
    let mut base_url = String::new();

    io::stdin()
        .read_line(&mut base_url)
        .expect("Failed to read from stdin");

    println!("{}", "What is your GROUP ID?");
    let mut group_id = String::new();

    io::stdin()
        .read_line(&mut group_id)
        .expect("Failed to read from stdin");

    println!(
        "Answers: BASE URL {}, GROUP ID {}",
        &base_url.trim(),
        &group_id.trim(),
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/votes/{}", &base_url.trim(), &group_id.trim()))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let mut votes: Vec<Vote> = vec![];

    match response.status() {
        reqwest::StatusCode::OK => {
            match response.json::<Votes>().await {
                Ok(result) => votes = result.data,
                Err(error) => println!(
                    "Hm, the response didn't match the shape we expected. {}",
                    error
                ),
            };
        }
        other => {
            panic!("Uh oh! Something unexpected happened: {:?}", other);
        }
    };

    println!("Generating Proof ");
    let start = Instant::now();

    let mut stdin = SP1Stdin::new();
    stdin.write(&serde_json::to_string(&votes).unwrap());
    stdin.write(&group_id.trim());

    let client = ProverClient::new();

    if args.execute {
        let (output, report) = client.execute(ZKVOTE_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        println!("public struct: {:?}", decoded);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        let (pk, vk) = client.setup(ZKVOTE_ELF);

        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");

        proof.save("proof-with-pis.bin").expect("saving proof failed");
    }

    let duration = start.elapsed();
    println!("Execution time: {:?}", duration);
}