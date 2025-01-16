package cmd

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/pkg/userop"
	"github.com/blndgs/intents-cli/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

// init initializes the recover command and adds it to the root command.
func init() {
	if err := utils.AddCommonFlags(RecoverSignerCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// RecoverSignerCmd represents the command to sign user operations.
var RecoverSignerCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the userOp signature's signer. Signatures with appended xData are supported. with 1 or more hashes and a signature",
	RunE: func(cmd *cobra.Command, args []string) error {
		conf, err := config.ReadConf(true)
		if err != nil {
			return config.NewError("failed to read configuration", err)
		}

		providedHashes, err := utils.GetHashes(cmd)
		if err != nil {
			return config.NewError("failed to get hashes", err)
		}
		if len(providedHashes) > 0 {
			return config.NewError("Only a single userOp is required", nil)
		}

		userOps, err := utils.GetUserOps(cmd)
		if len(userOps) == 0 || len(userOps) > 1 || err != nil {
			return config.NewError("Only a single userOp is supported", err)
		}

		chainMonikers, err := utils.GetChainMonikers(cmd, conf.NodesMap, len(userOps))
		if len(chainMonikers) > 2 || err != nil {
			return config.NewError("Only 1 additional chain is supported besides the default", err)
		}

		var chainID *big.Int
		if len(chainMonikers) == 1 {
			chainID = conf.NodesMap[chainMonikers[0]].ChainID
			fmt.Printf("Recovering for the default chain: %s\n", conf.NodesMap[chainMonikers[0]].ChainID)
		} else {
			chainID = conf.NodesMap[chainMonikers[1]].ChainID
			fmt.Printf("Recovering for the provided chain: %s\n", conf.NodesMap[chainMonikers[1]].ChainID)
		}

		op := userOps[0]

		opHash, err := getUserOpHash(op, conf.EntryPointAddr, chainID)
		if err != nil {
			return config.NewError("could not generate userOp hash", err)
		}

		recoverSigner(opHash, op.Signature[:op.GetSignatureEndIdx()], conf.Signer.Address.String())
		displayUserOpStatus(op, chainID)

		if op.IsCrossChainOperation() {
			traceRes, err := userop.NewXDataExtractor().ExtractAndDebug(op)
			if err != nil {
				return config.NewError("No xData found", err)
			}
			fmt.Printf("Cross-chain tracing result: %s\n", traceRes)
		}

		return nil
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
		hashList, err := fillInHashList(xData, cpOp, entryPointAddr, chainID)
		if err != nil {
			return common.Hash{}, config.NewError("could not fill in the hash list", err)
		}

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
	hashList, err := fillInHashList(xData, cpOp, entryPointAddr, chainID)
	if err != nil {
		return common.Hash{}, config.NewError("could not fill in the hash list", err)
	}

	xHash := userop.GenXHash(hashList)
	fmt.Printf("XChain hash from the userOp signature field: %s\n", xHash)
	return xHash, nil
}

func fillInHashList(xData *model.CrossChainData, cpOp model.UserOperation, entryPointAddr common.Address, chainID *big.Int) ([]common.Hash, error) {
	hashList := make([]common.Hash, len(xData.HashList))
	for i, hash := range xData.HashList {
		if hash.IsPlaceholder {
			intentJSON, err := cpOp.GetIntentJSON()
			if err != nil {
				return nil, config.NewError("cannot parse intent JSON in the userOP", err)
			}
			cpOp.CallData = []byte(intentJSON)
			hashList[i] = cpOp.GetUserOpHash(entryPointAddr, chainID)
			fmt.Printf("UserOp hash: %s\n", hashList[i])
		} else {
			hashList[i] = common.Hash(hash.OperationHash)
			fmt.Printf("Other UserOp's hash: %s\n", hashList[i])
		}
	}
	return hashList, nil
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
