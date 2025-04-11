# EIP-7702 Delegation Proof of Concept

This is a proof of concept to check if the code returned for an authority after a 7702 transaction delegating to a smart contract is non-zero.

## Prerequisites

- Solidity compiler (solc) installed locally
- Kurtosis installed locally
- Go 1.24 or later

## Environment Setup

1. Run Kurtosis with the pectra.yaml.norun configuration:
   ```bash
   kurtosis run --enclave testnet github.com/ethpandaops/ethereum-package --args-file pectra.yaml.norun 2>1&> kurtosis.log
   ```

2. Wait for the transition to Electra (approximately 1 epoch, which is about 7 minutes)

3. Update the multi_accounts.json RPC endpoints for the clients as per kurtosis.log. The file should contain the RPC endpoints for geth, nethermind, besu, reth, and erigon clients.

## Running the Proof of Concept

1. Build and run the Go program:
   ```bash
   go build -o poc_active_delegation && ./poc_active_delegation
   ```

2. The program will:
   - Compile and deploy the SimpleDelegate contract
   - Send 7702 transactions to delegate authorities to this contract for each client
   - Check the code at the authority addresses
   - Document the findings in this README.md file

## Test Setup

1. A simple smart contract was deployed at address: 0x8BBD9741751249dcF4B08240A3D0084F881585e8
2. For each Ethereum client, a 7702 transaction was sent to delegate an authority to this smart contract.
3. After the transaction was mined, the code at the authority address was checked.

## Results

| Client | Code Size | Code Hex | Delegation Works |
|--------|-----------|----------|------------------|
| geth | 0 bytes |  | false |
| besu | 0 bytes |  | false |
| reth | 0 bytes |  | false |
| erigon | 0 bytes |  | false |

## Conclusion

All clients return zero code for the authority address after a 7702 transaction. This contradicts the EIP-7702 specification, which states that EXTCODESIZE should return 23 (the size of 0xef0100 || address).