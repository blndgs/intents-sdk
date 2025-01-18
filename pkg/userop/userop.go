package userop

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	"golang.org/x/exp/slices"
)

func getKernelPrefix(kernelEnabledSig, kernelSig bool) uint8 {
	const (
		// Kernel prefix values
		// 0 is the default prefix value
		// 1 is the validation plugin prefix value
		// Used for plugin-based validation after a function has been enabled
		// with a specific validator
		// This is the prefix you use for all subsequent calls after enabling
		//a function with a validator
		validationPlugin1 = 1
		// 2 is the validation enabled prefix value. This mode allows setting
		// up the validator-executor mapping for a function
		validationEnabled2 = 2
	)

	switch {
	case kernelEnabledSig:
		return validationEnabled2
	case kernelSig:
		return validationPlugin1
	}

	return 0
}

// SignUserOperations is a helper function to sign one or multiple UserOperations.
func SignUserOperations(signer *signer.EOA, hashes []common.Hash, userOps []*model.UserOperation) error {
	messageHash := GenXHash(hashes)
	signerAddr := signer.Address.String()
	fmt.Printf("Signing UserOperations with address: %s\n", signerAddr)
	signature, err := GenerateSignature(messageHash, signer.PrivateKey)
	if err != nil {
		return err
	}

	// Assign the signature to all UserOperations
	for _, op := range userOps {
		op.Signature = signature
	}

	// Verify the signature
	if !VerifyHashSignature(messageHash, signature, signer.PublicKey) {
		return fmt.Errorf("signature is invalid")
	}

	return nil
}

// GenKernelEnableCalldata generates the calldata to enable the Intent Validator for the
// execValueBatch function.
func GenKernelEnableCalldata(
	ownerAddress common.Address, kernelValidatorAddr,
	kernelExecutorAddr common.Address,
) ([]byte, error) {
	// Function selector for enable(bytes)
	enableSelector := crypto.Keccak256([]byte("enable(bytes)"))[0:4]

	// Pack owner address as bytes
	ownerBytes := ownerAddress.Bytes()

	// Create the enable calldata for the validator
	validatorEnableCalldata := append(enableSelector, ownerBytes...)

	// Function selector for execValueBatch(uint256[],address[],bytes[])
	execBatchSelector := crypto.Keccak256([]byte("execValueBatch(uint256[],address[],bytes[])"))[0:4]

	// Create arrays for execValueBatch parameters
	values := []*big.Int{big.NewInt(0)} // No ETH transfer
	destinations := []common.Address{kernelValidatorAddr}
	functionCalls := [][]byte{validatorEnableCalldata}

	// Create ABI arguments
	uint256ArrayType, _ := abi.NewType("uint256[]", "", nil)
	addressArrayType, _ := abi.NewType("address[]", "", nil)
	bytesArrayType, _ := abi.NewType("bytes[]", "", nil)

	arguments := abi.Arguments{
		{Type: uint256ArrayType},
		{Type: addressArrayType},
		{Type: bytesArrayType},
	}

	// Pack the parameters
	packed, err := arguments.Pack(values, destinations, functionCalls)
	if err != nil {
		return nil, err
	}

	// Combine selector with packed parameters
	return append(execBatchSelector, packed...), nil
}

// PrefixSignature adds or resets the Kernel wallet prefix to the signature
// for a 69-byte total, with the first 4 bytes representing the prefix (which
// can be 0, 1, or 2) followed by the 65 ECDSA signature bytes.
func PrefixSignature(signature []byte, prefixValue uint8) ([]byte, error) {
	if prefixValue > 2 {
		return nil, fmt.Errorf("invalid prefix value > 2 -> %d", prefixValue)
	}

	sigLen := len(signature)
	switch sigLen {
	case 65:
		// Needs a new 69-byte slice
		prefixed := make([]byte, 69)

		// Write prefix (BigEndian: the last byte in these 4 is prefixValue)
		// 0x000 + prefix value of 0, 1, or 2
		binary.BigEndian.PutUint32(prefixed[:4], uint32(prefixValue))

		// Copy 65 bytes of the signature
		copy(prefixed[4:], signature)

		return prefixed, nil

	case 69:
		// Already has 4 prefix bytes, update them with the new prefix
		binary.BigEndian.PutUint32(signature[:4], uint32(prefixValue))
		return signature, nil

	default:
		return nil, fmt.Errorf("invalid signature length -> %d", sigLen)
	}
}

// GenXHash computes the hash of multiple UserOperations' hashes.
// It concatenates the hashes, sorts them, and hashes the result.
// The result is the xChainHash.
func GenXHash(opHashes []common.Hash) common.Hash {
	// Single userOp use case
	if len(opHashes) == 1 {
		return opHashes[0]
	}

	// clone opHashes to avoid sorting the original slice matching the userOps order
	sortedHashes := make([]common.Hash, len(opHashes))
	copy(sortedHashes, opHashes)

	slices.SortFunc(
		sortedHashes, func(a, b common.Hash) int {
			return bytes.Compare(a[:], b[:])
		},
	)

	// hash the sorted concatenated sortedHashes
	var concatenatedHashes []byte
	for _, hash := range sortedHashes {
		concatenatedHashes = append(concatenatedHashes, hash[:]...)
	}

	// Compute xChainHash
	return crypto.Keccak256Hash(concatenatedHashes)
}

// GenerateSignature signs the prefixed message hash with the private key.
func GenerateSignature(messageHash common.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	prefixedHash := getEtherMsgHash(messageHash)

	signature, err := crypto.Sign(prefixedHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	// Transform V from 0/1 to 27/28 according to the yellow paper
	if signature[64] == 0 || signature[64] == 1 {
		signature[64] += 27
	}

	return signature, nil
}

// getEtherMsgHash computes Ethereum signed message hash with fixed prefix.
func getEtherMsgHash(messageHash common.Hash) common.Hash {
	const ethMsgPrefix = "\x19Ethereum Signed Message:\n32"
	prefix := []byte(ethMsgPrefix)
	message := append(prefix, messageHash.Bytes()...)
	return crypto.Keccak256Hash(message)
}

// CondResetSignature resets the signature of UserOperations if the signature is invalid.
func CondResetSignature(publicKey *ecdsa.PublicKey, userOps []*model.UserOperation, hashes []common.Hash) error {
	isValid, err := VerifySignature(publicKey, userOps, hashes)
	if !isValid || err != nil {
		// Reset signatures on verification error
		for _, op := range userOps {
			op.Signature = nil
		}

		if err == nil {
			err = config.NewError("signature is invalid", nil)
		}

		return err
	}

	return nil
}

// VerifySignature verifies the signature of one or multiple UserOperations.
// VerifySignature verifies the signature of one or multiple UserOperations.
func VerifySignature(publicKey *ecdsa.PublicKey, userOps []*model.UserOperation, hashes []common.Hash) (bool, error) {
	if len(userOps) == 0 {
		return false, config.NewError("no user operations provided", nil)
	}

	signature := userOps[0].Signature
	if len(signature) != 65 {
		return false, config.NewError("signature must be 65 bytes long", nil)
	}
	if signature[64] != 27 && signature[64] != 28 {
		return false, config.NewError("invalid Ethereum signature (V is not 27 or 28)", nil)
	}

	messageHash := GenXHash(hashes)

	return VerifyHashSignature(messageHash, signature, publicKey), nil
}

// VerifyHashSignature verifies the signature against the message hash and public key.
func VerifyHashSignature(messageHash common.Hash, signature []byte, publicKey *ecdsa.PublicKey) bool {
	recoveredAddress := RecoverSigner(messageHash, signature)
	expectedAddress := crypto.PubkeyToAddress(*publicKey)

	return recoveredAddress == expectedAddress.String()
}

func RecoverSigner(messageHash common.Hash, signature []byte) string {
	sigCopy := bytes.Clone(signature)
	sigCopy[64] -= 27 // Transform V from 27/28 (yellow paper) to 0/1

	prefixedHash := getEtherMsgHash(messageHash)

	recoveredPubKey, err := crypto.SigToPub(prefixedHash.Bytes(), sigCopy)
	if err != nil {
		fmt.Printf("Failed to recover public key: %v\n", err)
		return ""
	}

	return crypto.PubkeyToAddress(*recoveredPubKey).String()
}
