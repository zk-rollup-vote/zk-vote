use aligned_sdk::common::types::{
    AlignedVerificationData, Network, FeeEstimationType, ProvingSystemId, VerificationData,
};
use aligned_sdk::verification_layer::{deposit_to_aligned, estimate_fee};
use aligned_sdk::verification_layer::{get_nonce_from_ethereum, submit_and_wait_verification};
use clap::Parser;
use dialoguer::Confirm;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, Bytes, H160, U256};
use reqwest;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::io;
use serde::{Deserialize, Serialize};
use std::time::Instant;

abigen!(VoteInboxContract, "VoteInboxContract.json",);

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKVOTE_ELF: &[u8] =
    include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    keystore_path: String,
    #[arg(
        short,
        long,
        default_value = "https://ethereum-holesky-rpc.publicnode.com"
    )]
    rpc_url: String,
    #[arg(short, long, default_value = "wss://batcher.alignedlayer.com")]
    batcher_url: String,
    #[arg(short, long, default_value = "holesky")]
    network: String,
    #[arg(short, long)]
    voteinbox_contract_address: H160,
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

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    let rpc_url = args.rpc_url.clone();

    let keystore_password = rpassword::prompt_password("Enter keystore password: ")
        .expect("Failed to read keystore password");

    let provider =
        Provider::<Http>::try_from(rpc_url.as_str()).expect("Failed to connect to provider");

    let chain_id = provider
        .get_chainid()
        .await
        .expect("Failed to get chain_id");

    let wallet = LocalWallet::decrypt_keystore(args.keystore_path, &keystore_password)
        .expect("Failed to decrypt keystore")
        .with_chain_id(chain_id.as_u64());

    let signer = SignerMiddleware::new(provider.clone(), wallet.clone());

    let network = match args.network.to_lowercase().as_str() {
        "devnet" => Network::Devnet,
        "holesky" => Network::Holesky,
        "holesky_stage" => Network::HoleskyStage,
        "mainnet" => Network::Mainnet,
        "mainnet_stage" => Network::MainnetStage,
        _ => Network::Holesky,
    };

    if Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Do you want to deposit 0.004eth in Aligned ?\nIf you already deposited Ethereum to Aligned before, this is not needed")
        .interact()
        .expect("Failed to read user input") {   

        deposit_to_aligned(U256::from(4000000000000000u128), signer.clone(), network.clone()).await
        .expect("Failed to pay for proof submission");
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

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(ZKVOTE_ELF);

    let proof: SP1ProofWithPublicValues = client
        .prove(&pk, &stdin)
        .compressed()
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");

    // Serialize proof into bincode (format used by sp1)
    let serialized_proof = bincode::serialize(&proof).expect("Failed to serialize proof");

    let verification_data = VerificationData {
        proving_system: ProvingSystemId::SP1,
        proof: serialized_proof,
        proof_generator_addr: wallet.address(),
        vm_program_code: Some(ZKVOTE_ELF.to_vec()),
        verification_key: None,//Some(bincode::serialize(&vk).expect("Failed to serialize verification key")),
        pub_input: Some(proof.public_values.to_vec()),
    };

    let max_fee = estimate_fee(&rpc_url, FeeEstimationType::Instant)
        .await
        .expect("failed to fetch gas price from the blockchain");

    let max_fee_string = ethers::utils::format_units(max_fee, 18).unwrap();

    if !Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(format!("Aligned will use at most {max_fee_string} eth to verify your proof. Do you want to continue?"))
        .interact()
        .expect("Failed to read user input")
    {   return; }

    let nonce = get_nonce_from_ethereum(&rpc_url, wallet.address(), network.clone())
        .await
        .expect("Failed to get next nonce");

    println!("Submitting your proof...");

    let aligned_verification_data = submit_and_wait_verification(
        &rpc_url,
        network,
        &verification_data,
        max_fee,
        wallet.clone(),
        nonce,
    )
    .await
    .unwrap();

    println!(
        "Proof submitted and verified successfully on batch {}",
        hex::encode(aligned_verification_data.batch_merkle_root)
    );

    println!("Submit vote...");

    submit_vote_with_verified_proof(
        &aligned_verification_data,
        signer,
        &args.voteinbox_contract_address,
        proof.public_values.as_slice(),
    )
    .await
    .expect("Submit vote failed ...");

    let duration = start.elapsed();
    println!("Execution time: {:?}", duration);
}

async fn submit_vote_with_verified_proof(
    aligned_verification_data: &AlignedVerificationData,
    signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    voteinbox_contract_addr: &Address,
    pub_values: &[u8],
) -> anyhow::Result<()> {
    let jr_contract = VoteInboxContract::new(*voteinbox_contract_addr, signer.into());
    let index_in_batch = U256::from(aligned_verification_data.index_in_batch);
    let ver_data_flattened_bytes: Vec<u8> = aligned_verification_data
        .batch_inclusion_proof
        .merkle_path
        .as_slice()
        .iter()
        .flat_map(|array| array.to_vec())
        .collect();

    let merkle_path = Bytes::from(ver_data_flattened_bytes);

    let receipt = jr_contract
        .submit_vote(
            aligned_verification_data
                .verification_data_commitment
                .proof_commitment,
            aligned_verification_data
                .verification_data_commitment
                .pub_input_commitment,
            aligned_verification_data
                .verification_data_commitment
                .proving_system_aux_data_commitment,
            aligned_verification_data
                .verification_data_commitment
                .proof_generator_addr,
            aligned_verification_data.batch_merkle_root,
            merkle_path,
            index_in_batch,
            Bytes::from(pub_values.to_vec()),
        )
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send tx {}", e))?
        .await
        .map_err(|e| anyhow::anyhow!("Failed to submit tx {}", e))?;

    match receipt {
        Some(receipt) => {
            println!(
                "Vote submitted!. Transaction hash: {:x}",
                receipt.transaction_hash
            );
            Ok(())
        }
        None => {
            anyhow::bail!("Failed to save vote: no receipt");
        }
    }
}