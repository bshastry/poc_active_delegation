package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// Config represents the structure of the multi_accounts.json file
type Config struct {
	Endpoints            []Endpoint `json:"endpoints"`
	PrefundedAccountKeys []string   `json:"prefunded_account_keys"`
}

// Endpoint represents an Ethereum client endpoint
type Endpoint struct {
	ClientType  string `json:"ClientType"`
	RPC         string `json:"RPC"`
	WebSocket   string `json:"WebSocket"`
	ServiceName string `json:"ServiceName"`
	LogsDir     string `json:"LogsDir"`
}

// ClientInfo holds information about a connected client
type ClientInfo struct {
	ClientType string
	Client     *ethclient.Client
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

// Result holds the result of the delegation test for a client
type Result struct {
	ClientType      string
	CodeSize        int
	CodeHex         string
	DelegationWorks bool
}

// Global variables
var addressToPrivateKeyMap map[common.Address]*ecdsa.PrivateKey

// compileContract compiles a Solidity contract and returns the ABI and bytecode
func compileContract(contractPath string) (string, string, error) {
	// Run solc to compile the contract
	cmd := exec.Command("solc", "--bin", "--abi", "--overwrite", contractPath, "-o", "build")
	cmd.Stderr = os.Stderr

	// Create build directory if it doesn't exist
	if err := os.MkdirAll("build", 0755); err != nil {
		return "", "", fmt.Errorf("failed to create build directory: %w", err)
	}

	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("failed to compile contract: %w", err)
	}

	// Get the contract name from the path
	contractName := filepath.Base(contractPath)
	contractName = strings.TrimSuffix(contractName, filepath.Ext(contractName))

	// Read the ABI file
	abiPath := filepath.Join("build", contractName+".abi")
	abiBytes, err := ioutil.ReadFile(abiPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read ABI file: %w", err)
	}

	// Read the bin file
	binPath := filepath.Join("build", contractName+".bin")
	binBytes, err := ioutil.ReadFile(binPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read bin file: %w", err)
	}

	return string(abiBytes), string(binBytes), nil
}

// deploySimpleDelegate deploys the SimpleDelegate contract
func deploySimpleDelegate(client *ethclient.Client, privateKey *ecdsa.PrivateKey, chainID *big.Int) (common.Address, error) {
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to create transactor: %w", err)
	}

	// Compile the contract
	log.Println("Compiling SimpleDelegate.sol contract...")
	_, contractBin, err := compileContract("contracts/SimpleDelegate.sol")
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to compile contract: %w", err)
	}
	log.Println("Contract compiled successfully")

	// Decode the bytecode
	bytecode, err := hex.DecodeString(contractBin)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to decode bytecode: %w", err)
	}

	// Get the nonce
	nonce, err := client.PendingNonceAt(context.Background(), auth.From)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get nonce: %w", err)
	}
	auth.Nonce = big.NewInt(int64(nonce))

	// Estimate gas
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to suggest gas price: %w", err)
	}
	auth.GasPrice = gasPrice

	// Deploy the contract
	tx := types.NewContractCreation(nonce, big.NewInt(0), 3000000, gasPrice, bytecode)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for the transaction to be mined
	var receipt *types.Receipt
	for i := 0; i < 30; i++ {
		receipt, err = client.TransactionReceipt(context.Background(), signedTx.Hash())
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	if receipt == nil {
		return common.Address{}, fmt.Errorf("transaction not mined")
	}

	contractAddress := receipt.ContractAddress
	log.Printf("Contract deployed at: %s", contractAddress.Hex())
	return contractAddress, nil
}

// generateEIP7702Transaction generates an EIP-7702 transaction
func generateEIP7702Transaction(client ClientInfo, authority, delegate common.Address, nonce uint64, chainID *big.Int) (*types.Transaction, error) {
	// Get Gas Tip Cap (Priority Fee)
	gasTipCapBig, err := client.Client.SuggestGasTipCap(context.Background())
	if err != nil {
		log.Printf("Failed to get suggested gas tip cap, using default: %v", err)
		gasTipCapBig = big.NewInt(1_000_000_000) // 1 Gwei default
	}

	gasTipCapU256, overflow := uint256.FromBig(gasTipCapBig)
	if overflow {
		return nil, fmt.Errorf("gas tip cap %s overflows uint256", gasTipCapBig.String())
	}

	// Get Gas Fee Cap (Max Fee) - Base fee + Tip
	header, err := client.Client.HeaderByNumber(context.Background(), nil) // Get latest header for base fee
	var baseFee *big.Int
	if err != nil || header.BaseFee == nil {
		log.Printf("Failed to get header or base fee, using default base fee: %v", err)
		baseFee = big.NewInt(10_000_000_000) // 10 Gwei default base fee
	} else {
		baseFee = header.BaseFee
	}
	gasFeeCapBig := new(big.Int).Add(baseFee, gasTipCapBig)
	gasFeeCapU256, overflow := uint256.FromBig(gasFeeCapBig)
	if overflow {
		return nil, fmt.Errorf("gas fee cap %s overflows uint256", gasFeeCapBig.String())
	}

	// Set transaction parameters
	gasLimit := uint64(2000000)
	valueBig := big.NewInt(0)
	valueU256, _ := uint256.FromBig(valueBig)

	// Select a target address (different from the authority)
	to := delegate

	// Create an empty access list
	accessList := types.AccessList{}

	// Generate the authorization
	auth, err := generateValidAuthorization(client, authority, delegate, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization: %w", err)
	}

	nonce, err = client.Client.PendingNonceAt(context.Background(), client.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	log.Printf("Sender (%s) Nonce for Tx: %d", client.Address.Hex(), nonce)

	// Create the SetCodeTx
	innerTxData := &types.SetCodeTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  gasTipCapU256,
		GasFeeCap:  gasFeeCapU256,
		Gas:        gasLimit,
		To:         to,
		Value:      valueU256,
		Data:       []byte{},
		AccessList: accessList,
		AuthList:   []types.SetCodeAuthorization{*auth},
	}
	log.Printf("SetCodeTx Details: ChainID=%s, Nonce=%d, GasTipCap=%s, GasFeeCap=%s, Gas=%d, To=%s, Value=%s, Data=%x, AccessList=%v, AuthList=%+v",
		innerTxData.ChainID.String(), innerTxData.Nonce, innerTxData.GasTipCap.String(), innerTxData.GasFeeCap.String(), innerTxData.Gas, innerTxData.To.Hex(), innerTxData.Value.String(), innerTxData.Data, innerTxData.AccessList, innerTxData.AuthList)

	// Create and sign the transaction
	tx := types.NewTx(innerTxData)

	// Sign the transaction using the appropriate signer
	signer := types.NewPragueSigner(chainID)
	signedTx, err := types.SignTx(tx, signer, client.PrivateKey)
	if err != nil {
		// Try with Cancun signer as fallback
		signer = types.NewCancunSigner(chainID)
		signedTx, err = types.SignTx(tx, signer, client.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %w", err)
		}
	}

	return signedTx, nil
}

// generateValidAuthorization generates a valid EIP-7702 authorization
func generateValidAuthorization(client ClientInfo, authority, delegate common.Address, chainIDBig *big.Int) (*types.SetCodeAuthorization, error) {
	// Get the nonce for the signer
	signerAddr := authority
	signerKey := addressToPrivateKeyMap[signerAddr]

	signerNonce, err := client.Client.PendingNonceAt(context.Background(), signerAddr)
	if err != nil {
		log.Printf("Failed to get pending nonce for signer address %s: %v", signerAddr.Hex(), err)
		return nil, fmt.Errorf("failed to get nonce for signer %s: %w", signerAddr.Hex(), err)
	}
	log.Printf("Using provided AuthNonce: %d for authority %s", signerNonce, signerAddr.Hex())

	// Construct the EIP-7702 Authorization signing hash
	authChainID := chainIDBig.Uint64()
	magicByte := []byte{0x05} // EIP-7702 Magic Byte

	payloadItems := []interface{}{
		authChainID,
		delegate,
		signerNonce,
	}
	rlpEncodedPayload, err := rlp.EncodeToBytes(payloadItems)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode auth payload: %w", err)
	}

	// Concatenate: MAGIC (1) + chainId (8) + contract_address (20) + signer_nonce (8) = 37 bytes
	message := append(magicByte, rlpEncodedPayload...)

	// Calculate Keccak256 hash
	signingHash := crypto.Keccak256Hash(message)

	// Sign the hash using the signer's key
	signatureBytes, err := crypto.Sign(signingHash[:], signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign EIP-7702 auth hash for signer %s targeting contract %s: %w",
			signerAddr.Hex(), delegate.Hex(), err)
	}

	// Extract R, S, V
	sigR := new(big.Int).SetBytes(signatureBytes[:32])
	sigS := new(big.Int).SetBytes(signatureBytes[32:64])
	sigV := signatureBytes[64]

	// Adjust V: EIP-7702 uses 0 or 1. crypto.Sign returns 27/28. Subtract 27.
	if sigV >= 27 {
		sigV -= 27
	}

	// Ensure S is in the lower half of the curve order (EIP-2)
	secp256k1N, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1HalfN := new(big.Int).Div(secp256k1N, big.NewInt(2))
	if sigS.Cmp(secp256k1HalfN) > 0 {
		sigS.Sub(secp256k1N, sigS)
		sigV = 1 - sigV // Flip V when S is adjusted
	}

	// Create SetCodeAuthorization struct
	auth := &types.SetCodeAuthorization{
		ChainID: *uint256.NewInt(authChainID),
		Address: delegate,
		Nonce:   signerNonce,
		R:       *uint256.MustFromBig(sigR),
		S:       *uint256.MustFromBig(sigS),
		V:       sigV,
	}

	log.Printf("Generated valid authorization: Authority=%s, Delegate=%s, AuthNonce=%d, ChainID=%s, V=%d, R=%s, S=%s",
		signerAddr.Hex(), auth.Address.Hex(), auth.Nonce, auth.ChainID.String(), auth.V, auth.R.String(), auth.S.String())

	return auth, nil
}

// isActiveDelegation checks if an address has an active delegation according to EIP-7702
// Returns true if delegation is active, false otherwise
func isActiveDelegation(client *ethclient.Client, authority common.Address, clientType string) (bool, error) {
	// Get the code of the authority
	code, err := client.CodeAt(context.Background(), authority, nil)
	if err != nil {
		return false, fmt.Errorf("failed to get code for authority: %w", err)
	}

	// Log the code details for debugging
	log.Printf("[%s] Code for authority %s: %x (length: %d bytes)", clientType, authority.Hex(), code, len(code))

	// If there's any code at all, it's definitely an active delegation
	if len(code) > 0 {
		if len(code) == 23 {
			// Check if the code starts with 0xef0100 (the EIP-7702 prefix)
			expectedPrefix := []byte{0xef, 0x01, 0x00}
			if bytes.HasPrefix(code, expectedPrefix) {
				log.Printf("[%s] Delegation is active: code size is 23 bytes and starts with EIP-7702 prefix", clientType)
			} else {
				log.Printf("[%s] Code size is 23 bytes but doesn't start with expected EIP-7702 prefix", clientType)
			}
		} else {
			log.Printf("[%s] Delegation appears active: authority has code (length: %d bytes)", clientType, len(code))
		}
		return true, nil
	}

	// Get the code hash
	codeHash := crypto.Keccak256Hash(code)
	log.Printf("[%s] Code hash for authority %s: %s", clientType, authority.Hex(), codeHash.Hex())

	// Since we can't directly detect active delegations through code in some clients,
	// we assume the delegation is not active if the code is empty
	log.Printf("[%s] No code found for authority, delegation appears inactive", clientType)
	return false, nil
}

// loadConfig loads the configuration from multi_accounts.json
func loadConfig() (*Config, error) {
	// Read the configuration file
	configData, err := ioutil.ReadFile("multi_accounts.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the configuration
	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// initializeAddressToPrivateKeyMap initializes the map of EOA addresses to private keys
func initializeAddressToPrivateKeyMap(config *Config) error {
	// Initialize the map
	addressToPrivateKeyMap = make(map[common.Address]*ecdsa.PrivateKey)

	// Create EOA addresses from the private keys
	for i, privateKeyHex := range config.PrefundedAccountKeys {
		// Parse the private key
		privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
		if err != nil {
			log.Printf("Warning: Failed to parse private key %d: %v", i, err)
			continue
		}

		// Get the address from the private key
		address := crypto.PubkeyToAddress(privateKey.PublicKey)

		// Add to the map
		addressToPrivateKeyMap[address] = privateKey
		log.Printf("Mapped EOA address %s to private key %d", address.Hex(), i)
	}

	if len(addressToPrivateKeyMap) == 0 {
		return fmt.Errorf("failed to initialize any address to private key mappings")
	}

	return nil
}

// connectToClients connects to all Ethereum clients
func connectToClients(config *Config) ([]ClientInfo, error) {
	var clients []ClientInfo

	// Connect to each client
	for i, endpoint := range config.Endpoints {
		// Connect to the client
		client, err := ethclient.Dial(endpoint.RPC)
		if err != nil {
			log.Printf("Warning: Failed to connect to %s at %s: %v", endpoint.ClientType, endpoint.RPC, err)
			continue
		}

		// Get the private key for this client
		if i >= len(config.PrefundedAccountKeys) {
			log.Printf("Warning: No private key available for client %s", endpoint.ClientType)
			client.Close()
			continue
		}

		// Parse the private key
		privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(config.PrefundedAccountKeys[i], "0x"))
		if err != nil {
			log.Printf("Warning: Failed to parse private key for client %s: %v", endpoint.ClientType, err)
			client.Close()
			continue
		}

		// Get the address from the private key
		address := crypto.PubkeyToAddress(privateKey.PublicKey)

		addressToPrivateKeyMap[address] = privateKey
		log.Printf("Connected to %s at %s with address %s", endpoint.ClientType, endpoint.RPC, address.Hex())

		// Add the client to the list
		clients = append(clients, ClientInfo{
			ClientType: endpoint.ClientType,
			Client:     client,
			PrivateKey: privateKey,
			Address:    address,
		})
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf("failed to connect to any clients")
	}

	return clients, nil
}

// runDelegationTest runs the delegation test for a client
func runDelegationTest(client ClientInfo, contractAddress common.Address) (*Result, error) {
	log.Printf("Running delegation test for %s...", client.ClientType)

	// Get chain ID
	chainID, err := client.Client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	// Select an authority (use the client's address as the authority)
	authority := client.Address
	log.Printf("Using authority: %s and delegate: %s", authority.Hex(), contractAddress.Hex())

	// Get the nonce for the sender
	nonce, err := client.Client.PendingNonceAt(context.Background(), client.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	// Generate and send the EIP-7702 transaction
	tx, err := generateEIP7702Transaction(client, authority, contractAddress, nonce, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EIP-7702 transaction: %w", err)
	}

	err = client.Client.SendTransaction(context.Background(), tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send EIP-7702 transaction: %w", err)
	}
	log.Printf("EIP-7702 transaction sent: %s", tx.Hash().Hex())

	// Wait for the transaction to be mined
	log.Println("Waiting for transaction to be mined...")
	var receipt *types.Receipt
	maxAttempts := 30 // Maximum number of attempts
	for i := 0; i < maxAttempts; i++ {
		receipt, err = client.Client.TransactionReceipt(context.Background(), tx.Hash())
		if err == nil && receipt != nil {
			log.Printf("Transaction mined in block %d with status %d", receipt.BlockNumber.Uint64(), receipt.Status)
			break
		}
		log.Printf("Transaction not yet mined (attempt %d/%d), waiting...", i+1, maxAttempts)
		time.Sleep(1 * time.Second)
	}

	if receipt == nil {
		return nil, fmt.Errorf("transaction was not mined after %d attempts", maxAttempts)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("transaction failed with status %d", receipt.Status)
	}

	// Check if the delegation is active
	isActive, err := isActiveDelegation(client.Client, authority, client.ClientType)
	if err != nil {
		return nil, fmt.Errorf("failed to check if delegation is active: %w", err)
	}

	// Get the code of the authority
	code, err := client.Client.CodeAt(context.Background(), authority, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get code for authority: %w", err)
	}

	return &Result{
		ClientType:      client.ClientType,
		CodeSize:        len(code),
		CodeHex:         hex.EncodeToString(code),
		DelegationWorks: isActive,
	}, nil
}

func main() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting EIP-7702 delegation proof of concept")

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize the address to private key map
	if err := initializeAddressToPrivateKeyMap(config); err != nil {
		log.Fatalf("Failed to initialize address to private key map: %v", err)
	}

	// Connect to clients
	clients, err := connectToClients(config)
	if err != nil {
		log.Fatalf("Failed to connect to clients: %v", err)
	}
	defer func() {
		for _, client := range clients {
			client.Client.Close()
		}
	}()

	// Print connected clients
	log.Println("Connected to clients:")
	for _, client := range clients {
		log.Printf("  - %s: %s", client.ClientType, client.Address.Hex())
	}

	// Deploy the SimpleDelegate contract using the first client
	log.Println("Deploying SimpleDelegate contract...")
	chainID, err := clients[0].Client.ChainID(context.Background())
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	contractAddress, err := deploySimpleDelegate(clients[0].Client, clients[0].PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Failed to deploy SimpleDelegate contract: %v", err)
	}
	log.Printf("SimpleDelegate contract deployed at: %s", contractAddress.Hex())

	// Run the delegation test for each client
	var results []*Result
	for _, client := range clients {
		result, err := runDelegationTest(client, contractAddress)
		if err != nil {
			log.Printf("Failed to run delegation test for %s: %v", client.ClientType, err)
			continue
		}
		results = append(results, result)
	}

	// Print the results
	log.Println("\nResults:")
	for _, result := range results {
		log.Printf("Client: %s", result.ClientType)
		log.Printf("  Code Size: %d bytes", result.CodeSize)
		log.Printf("  Code Hex: %s", result.CodeHex)
		log.Printf("  Delegation Works: %v", result.DelegationWorks)
	}
}

// createReadme creates a README.md file with the findings
func createReadme(results []*Result, contractAddress common.Address) {
	log.Println("Creating README.md with findings...")

	content := `# EIP-7702 Delegation Proof of Concept

This is a proof of concept to check if the code returned for an authority after a 7702 transaction delegating to a smart contract is non-zero.

## Setup

1. A simple smart contract was deployed at address: ` + contractAddress.Hex() + `
2. For each Ethereum client, a 7702 transaction was sent to delegate an authority to this smart contract.
3. After the transaction was mined, the code at the authority address was checked.

## Results

| Client | Code Size | Code Hex | Delegation Works |
|--------|-----------|----------|------------------|
`

	for _, result := range results {
		content += fmt.Sprintf("| %s | %d bytes | %s | %v |\n",
			result.ClientType,
			result.CodeSize,
			result.CodeHex,
			result.DelegationWorks)
	}

	content += `
## Conclusion

`

	// Add conclusion based on results
	allZero := true
	for _, result := range results {
		if result.CodeSize > 0 {
			allZero = false
			break
		}
	}

	if allZero {
		content += "All clients return zero code for the authority address after a 7702 transaction. This contradicts the EIP-7702 specification, which states that EXTCODESIZE should return 23 (the size of 0xef0100 || address)."
	} else {
		content += "Some clients return non-zero code for the authority address after a 7702 transaction, which aligns with the EIP-7702 specification."
	}

	// Write the README.md file
	err := ioutil.WriteFile("README.md", []byte(content), 0644)
	if err != nil {
		log.Printf("Failed to write README.md: %v", err)
	} else {
		log.Println("README.md created successfully")
	}
}
