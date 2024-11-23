package cmd

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-sdk/pkg/config"
	"github.com/blndgs/intents-sdk/pkg/userop"
	"github.com/blndgs/intents-sdk/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

// init initializes the recover command and adds it to the root command.
func init() {
	utils.AddCommonFlags(RecoverSignerCmd)
}

// RecoverSignerCmd represents the command to sign user operations.
var RecoverSignerCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the userOp signature's signer. Signatures with appended xData are supported. with 1 or more hashes and a signature",
	Run: func(cmd *cobra.Command, args []string) {
		nodes, _, entrypointAddr, eoaSigner := config.ReadConf(true)

		providedHashes := utils.GetHashes(cmd)
		if len(providedHashes) > 0 {
			fmt.Printf("Only a single userOp is required.\n")
			return
		}

		userOps := utils.GetUserOps(cmd)
		if len(userOps) == 0 || len(userOps) > 1 {
			fmt.Printf("Only a single userOp is supported\n")
			return
		}

		chainMonikers := utils.GetChainMonikers(cmd, nodes, len(userOps))
		if len(chainMonikers) > 2 {
			fmt.Printf("Only a single chain is supported\n")
			return
		}

		var chainID *big.Int
		if len(chainMonikers) == 1 {
			chainID = nodes[chainMonikers[0]].ChainID
			fmt.Printf("Recovering for the default chain: %s\n", nodes[chainMonikers[0]].ChainID)
		} else {
			chainID = nodes[chainMonikers[1]].ChainID
			fmt.Printf("Recovering for the provided chain: %s\n", nodes[chainMonikers[1]].ChainID)
		}

		op := userOps[0]

		opHash, err := getUserOpHash(op, entrypointAddr, chainID)
		if err != nil {
			fmt.Printf("could not generate userOp hash: %s\n", err)
			return
		}

		recoverSigner(opHash, op.Signature[:op.GetSignatureEndIdx()], eoaSigner.Address.String())
		displayUserOpStatus(op, chainID)
	},
}

// getUserOpHash restores the UserOperation hash by moving the intent JSON
// into the CallData field if it is not already there. It handles both conventional
// and cross-chain UserOperations.
//
// Returns:
// - common.Hash: The UserOperation hash.
// - error: Any error encountered.
func getUserOpHash(op *model.UserOperation, entryPointAddr common.Address, chainID *big.Int) (common.Hash, error) {
	if !op.HasIntent() {
		// conventional userOp
		return op.GetUserOpHash(entryPointAddr, chainID), nil
	}

	// move the intent JSON into the CallData field if it is not already there
	cpOp := *op
	// restore the intent userOp for the hash
	if !cpOp.IsCrossChainOperation() {
		if !cpOp.HasSignatureExact() {
			// Assume Intent JSON is appended to the signature payload
			intentJSON, err := cpOp.GetIntentJSON()
			if err != nil {
				fmt.Printf("Error parsing intent JSON: %s\n", err)
				return common.Hash{}, err
			}
			if !bytes.Equal(cpOp.Signature[cpOp.GetSignatureEndIdx():], []byte(intentJSON)) && bytes.Equal(cpOp.CallData, []byte(intentJSON)) {
				fmt.Printf("Intent JSON is already in the CallData field but an undetected value is appended to the signature payload. Most likely this detection algorithm is out of date with the userOp spec and the recovering result is misleading.\n")
			}
			cpOp.CallData = []byte(intentJSON)
		}
		return cpOp.GetUserOpHash(entryPointAddr, chainID), nil
	}

	// Validate the signature
	if userop.IsAggregate(op) {
		// Check if the callData field contains xData
		xData, err := model.ParseCrossChainData(cpOp.CallData)
		if err != nil {
			fmt.Printf("No xData found in the callData or the signature. Cannot recover.\n")
			return common.Hash{}, err
		}
		hashList := fillInHashList(xData, cpOp, entryPointAddr, chainID)

		xHash := userop.GenXHash(hashList)
		fmt.Printf("XChain hash from the userOp callData field: %s\n", xHash)
		return xHash, nil
	}

	// cross-chain userOp
	xData, err := model.ParseCrossChainData(op.Signature[op.GetSignatureEndIdx():])
	if err != nil {
		xData, err = model.ParseCrossChainData(op.CallData)
		if err != nil {
			fmt.Printf("No xData found in the callData or the signature. Cannot recover.\n")
			return common.Hash{}, err
		}
		fmt.Printf("Parsed xData in the calldata field.\n")
	} else {
		fmt.Printf("Parsed xData in the signature field.\n")
	}

	// add the op hash to the x-chain hash list
	hashList := fillInHashList(xData, cpOp, entryPointAddr, chainID)

	xHash := userop.GenXHash(hashList)
	fmt.Printf("XChain hash from the userOp signature field: %s\n", xHash)
	return xHash, nil
}

func fillInHashList(xData *model.CrossChainData, cpOp model.UserOperation, entryPointAddr common.Address, chainID *big.Int) []common.Hash {
	hashList := make([]common.Hash, len(xData.HashList))
	for i, hash := range xData.HashList {
		if hash.IsPlaceholder {
			intentJSON, err := cpOp.GetIntentJSON()
			if err != nil {
				panic(fmt.Errorf("cannot parse intent JSON in the userOP: %w", err))
			}
			cpOp.CallData = []byte(intentJSON)
			hashList[i] = cpOp.GetUserOpHash(entryPointAddr, chainID)
			fmt.Printf("UserOp hash: %s\n", hashList[i])
		} else {
			hashList[i] = common.Hash(hash.OperationHash)
			fmt.Printf("Other UserOp's hash: %s\n", hashList[i])
		}
	}
	return hashList
}

func recoverSigner(opHash common.Hash, signature []byte, eoaSigner string) {
	recovered := userop.RecoverSigner(opHash, signature)
	if len(signature) > model.KernelSignatureLength {
		fmt.Printf("XChain Signature is valid for recovered: %s\n", recovered)
	} else {
		fmt.Printf("Signature is valid for recovered: %s\n", recovered)
	}

	if recovered != eoaSigner {
		fmt.Printf("\nRecovered signer does not match the configured EOA signer: %s\n", eoaSigner)
		fmt.Printf("                                                             *\n")
	}
}

func displayUserOpStatus(op *model.UserOperation, chainID *big.Int) {
	state := userop.DetermineState(op)

	// Create a nicely formatted status display
	fmt.Printf("\n=== UserOperation Status ===\n")
	fmt.Printf("%s\n", state.FormatWithDetail(
		fmt.Sprintf("Chain ID: %s", chainID),
	))
}
