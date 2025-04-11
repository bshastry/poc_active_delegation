# EIP-7702 Delegation Proof of Concept

This is a proof of concept to check if the code returned for an authority after a 7702 transaction delegating to a smart contract is non-zero.

## Setup

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