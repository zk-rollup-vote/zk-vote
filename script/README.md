# Vote Processing Server

This server automatically processes vote data by:
1. Fetching vote hashes from a VoteRepo contract
2. Retrieving vote data from an API endpoint
3. Generating ZK proofs using SP1
4. Submitting proofs to Aligned Layer for verification
5. Calling the VoteInbox contract to record the votes on-chain

## Setup

### Environment Variables

Create a `.env` file with the following variables:

```bash
# RPC Configuration
RPC_URL=https://ethereum-holesky-rpc.publicnode.com

# Vote Repository Contract (the contract that manages vote hashes)
CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890

# Vote Inbox Contract (the contract that receives vote proofs)
VOTEINBOX_CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890

# API Configuration
OPERATOR_API_URL=https://your-operator-api.com

# Polling Configuration
POLL_INTERVAL_SECONDS=30

# Wallet Configuration
PRIVATE_KEY=0x1234567890abcdef...

# Aligned Layer Configuration
BATCHER_URL=wss://batcher.alignedlayer.com
NETWORK=holesky
```

### Running the Server

```bash
# Run the vote processing server
cargo run --bin server
```

## How it Works

1. **Hash Polling**: The server continuously polls the VoteRepo contract for new vote hashes
2. **Data Fetching**: For each new hash, it fetches the corresponding vote data from the API
3. **Validation**: It validates that the fetched data matches the expected hash
4. **Proof Generation**: It generates a ZK proof using SP1 that proves the vote tallies are correct
5. **Aligned Submission**: The proof is submitted to Aligned Layer for verification
6. **Contract Interaction**: Once verified, the server calls the VoteInbox contract to record the votes

## Contract Interactions

### VoteRepo Contract
- `getNextHash()`: Retrieves the next hash to process
- `isHashExecuted(bytes32)`: Checks if a hash has already been processed

### VoteInbox Contract
- `submitVote(...)`: Submits a verified vote proof to the contract

## Key Features

- **Automatic Processing**: Continuously monitors for new vote hashes
- **ZK Proof Generation**: Uses SP1 to generate zero-knowledge proofs
- **Aligned Integration**: Leverages Aligned Layer for proof verification
- **Error Handling**: Robust error handling with retry logic
- **Environment Configuration**: Fully configurable via environment variables 