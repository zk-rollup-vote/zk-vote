use std::env;
use std::time::Duration;
use std::sync::Arc;
use tokio::time::sleep;
use serde::{Deserialize, Serialize};
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::types::{Address, U256, Bytes};
use ethers::signers::{LocalWallet, Signer};
use alloy_sol_types::sol;
use reqwest::Client;
use aligned_sdk::common::types::{
    AlignedVerificationData, Network, ProvingSystemId, VerificationData, FeeEstimationType,
};
use aligned_sdk::verification_layer::{get_nonce_from_ethereum, submit_and_wait_verification, estimate_fee};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKVOTE_ELF: &[u8] =
    include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Votes {
    pub data: Vec<Vote>,
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

// Define the contract ABI using ethers abigen macro
abigen!(VoteRepo, "VoteRepoContract.json");
abigen!(VoteInbox, "VoteInboxContract.json",);

struct VoteProcessor {
    voterepo_contract: VoteRepo<Provider<Http>>,
    voteinbox_contract: VoteInbox<Provider<Http>>,
    http_client: Client,
    operator_api_url: String,
    poll_interval: Duration,
    wallet: LocalWallet,
    provider: Arc<Provider<Http>>,
    signer: SignerMiddleware<Provider<Http>, LocalWallet>,
    network: Network,
}

impl VoteProcessor {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let operator_api_url = env::var("OPERATOR_API_URL").expect("OPERATOR_API_URL must be set");

        let poll_interval_secs: u64 = env::var("POLL_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .expect("POLL_INTERVAL_SECONDS must be a valid number");
        
        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

        let voterepo_contract_address = env::var("VOTEREPO_CONTRACT_ADDRESS")
            .expect("VOTEREPO_CONTRACT_ADDRESS must be set")
            .parse::<Address>()?;
        let voteinbox_contract_address = env::var("VOTEINBOX_CONTRACT_ADDRESS")
            .expect("VOTEINBOX_CONTRACT_ADDRESS must be set")
            .parse::<Address>()?;
        
        let network = match env::var("NETWORK")
            .unwrap_or_else(|_| "holesky".to_string())
            .to_lowercase()
            .as_str()
        {
            "devnet" => Network::Devnet,
            "holesky" => Network::Holesky,
            "holesky_stage" => Network::HoleskyStage,
            "mainnet" => Network::Mainnet,
            "mainnet_stage" => Network::MainnetStage,
            _ => Network::Holesky,
        };

        let provider = Arc::new(Provider::<Http>::try_from(rpc_url.as_str())?);
        let voterepo_contract = VoteRepo::new(voterepo_contract_address, provider.clone());
        let voteinbox_contract = VoteInbox::new(voteinbox_contract_address, provider.clone());
        let http_client = Client::new();

        let chain_id = provider.get_chainid().await?;
        let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id.as_u64());
        let signer = SignerMiddleware::new(Provider::<Http>::try_from(rpc_url.as_str())?, wallet.clone());

        Ok(Self {
            voterepo_contract,
            voteinbox_contract,
            http_client,
            operator_api_url,
            poll_interval: Duration::from_secs(poll_interval_secs),
            wallet,
            provider,
            signer,
            network,
        })
    }

    async fn get_next_hash(&self) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        match self.voterepo_contract.get_next_hash().call().await {
            Ok(hash_bytes) => {
                let hash: [u8; 32] = hash_bytes.into();
                // Check if it's a zero hash (no more hashes)
                if hash == [0u8; 32] {
                    Ok(None)
                } else {
                    Ok(Some(hash))
                }
            }
            Err(e) => {
                println!("Error getting next hash: {}", e);
                Ok(None)
            }
        }
    }

    async fn is_hash_executed(&self, hash: [u8; 32]) -> Result<bool, Box<dyn std::error::Error>> {
        let result = self.voterepo_contract.is_hash_executed(hash).call().await?;
        Ok(result)
    }

    async fn execute_next_hash(&self) -> Result<(), Box<dyn std::error::Error>> {
        let signed_contract = VoteRepo::new(self.voterepo_contract.address(), self.signer.clone().into());
        
        match signed_contract.execute_next_hash().send().await {
            Ok(pending_tx) => {
                match pending_tx.await {
                    Ok(Some(receipt)) => {
                        println!("Hash marked as executed! Transaction hash: {:x}", receipt.transaction_hash);
                        Ok(())
                    }
                    Ok(None) => {
                        Err("Failed to execute hash: no receipt".into())
                    }
                    Err(e) => {
                        Err(format!("Error waiting for executeNextHash transaction: {}", e).into())
                    }
                }
            }
            Err(e) => {
                Err(format!("Error sending executeNextHash transaction: {}", e).into())
            }
        }
    }

    async fn fetch_vote_data(&self, hash: [u8; 32]) -> Result<String, Box<dyn std::error::Error>> {
        let hash_hex = format!("0x{}", hex::encode(hash));
        let url = format!("{}/votes/{}", self.operator_api_url, hash_hex);
        
        println!("Fetching vote data from: {}", url);
        
        let response = self.http_client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await?;

        if response.status().is_success() {
            let vote_data = response.text().await?;
            Ok(vote_data)
        } else {
            Err(format!("Failed to fetch vote data: HTTP {}", response.status()).into())
        }
    }

    async fn generate_and_submit_proof(&self, hash: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating ZK proof for hash: 0x{}", hex::encode(hash));

        let vote_data = self.fetch_vote_data(hash).await?;
        let votes: Votes = serde_json::from_str(&vote_data)?;
        let group_id = format!("0x{}", hex::encode(hash));

        // Generate SP1 proof
        let mut stdin = SP1Stdin::new();
        stdin.write(&serde_json::to_string(&votes.data)?);
        stdin.write(&group_id);

        let client = ProverClient::from_env();
        let (pk, vk) = client.setup(ZKVOTE_ELF);

        let proof: SP1ProofWithPublicValues = client
            .prove(&pk, &stdin)
            .compressed()
            .run()
            .expect("Failed to generate proof");

        println!("Successfully generated proof!");

        // Verify proof locally first
        client.verify(&proof, &vk).expect("Failed to verify proof");
        println!("Successfully verified proof locally!");

        // Serialize proof for Aligned submission
        let serialized_proof = bincode::serialize(&proof)?;

        let verification_data = VerificationData {
            proving_system: ProvingSystemId::SP1,
            proof: serialized_proof,
            proof_generator_addr: self.wallet.address(),
            vm_program_code: Some(ZKVOTE_ELF.to_vec()),
            verification_key: None, //Some(bincode::serialize(&vk)?),
            pub_input: Some(proof.public_values.to_vec()),
        };

        // Estimate fee
        let max_fee = estimate_fee(&self.provider.url().to_string(), FeeEstimationType::Instant)
            .await
            .map_err(|e| format!("Failed to estimate fee: {:?}", e))?;
        println!("Estimated fee: {} ETH", ethers::utils::format_units(max_fee, 18)?);

        // Get nonce
        let nonce = get_nonce_from_ethereum(
            &self.provider.url().to_string(), 
            self.wallet.address(), 
            self.network.clone()
        )
        .await
        .map_err(|e| format!("Failed to get nonce: {:?}", e))?;

        println!("Submitting proof to Aligned...");

        // Submit to Aligned for verification
        let aligned_verification_data = submit_and_wait_verification(
            &self.provider.url().to_string(),
            self.network.clone(),
            &verification_data,
            max_fee,
            self.wallet.clone(),
            nonce,
        )
        .await
        .map_err(|e| format!("Failed to submit and verify proof: {:?}", e))?;

        println!(
            "Proof submitted and verified successfully on batch {}",
            hex::encode(aligned_verification_data.batch_merkle_root)
        );

        // Submit to VoteInbox contract
        self.submit_vote_to_contract(&aligned_verification_data, proof.public_values.as_slice()).await?;

        println!("Vote successfully submitted to contract!");
        Ok(())
    }

    async fn submit_vote_to_contract(
        &self,
        aligned_verification_data: &AlignedVerificationData,
        pub_values: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let vote_contract = VoteInbox::new(self.voteinbox_contract.address(), self.signer.clone().into());
        let index_in_batch = U256::from(aligned_verification_data.index_in_batch);
        
        let ver_data_flattened_bytes: Vec<u8> = aligned_verification_data
            .batch_inclusion_proof
            .merkle_path
            .as_slice()
            .iter()
            .flat_map(|array| array.to_vec())
            .collect();

        let merkle_path = Bytes::from(ver_data_flattened_bytes);

        let receipt = vote_contract
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
            .await?
            .await?;

        match receipt {
            Some(receipt) => {
                println!(
                    "Vote submitted to contract! Transaction hash: {:x}",
                    receipt.transaction_hash
                );
                Ok(())
            }
            None => {
                Err("Failed to save vote: no receipt".into())
            }
        }
    }
    
    async fn process_hash(&self, hash: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        println!("Processing hash: 0x{}", hex::encode(hash));

        // Check if already executed
        if self.is_hash_executed(hash).await? {
            println!("Hash already executed, skipping");
            return Ok(());
        }

        // Generate and submit ZK proof
        self.generate_and_submit_proof(hash).await?;

        // Mark hash as executed in the contract
        self.execute_next_hash().await?;

        println!("Successfully processed hash: 0x{}", hex::encode(hash));
        Ok(())
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting VoteProcessor server...");
        println!("Voterepo contract address: {}", self.voterepo_contract.address());
        println!("Voteinbox contract address: {}", self.voteinbox_contract.address());
        println!("Poll interval: {:?}", self.poll_interval);

        loop {
            match self.get_next_hash().await {
                Ok(Some(hash)) => {
                    if let Err(e) = self.process_hash(hash).await {
                        println!("Error processing hash 0x{}: {}", hex::encode(hash), e);
                    }
                }
                Ok(None) => {
                    println!("No new hash available");
                }
                Err(e) => {
                    println!("Error getting next hash: {}", e);
                }
            }

            sleep(self.poll_interval).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let processor = VoteProcessor::new().await?;
    processor.run().await
}
