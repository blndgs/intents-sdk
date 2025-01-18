package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/blndgs/intents-cli/pkg/abi"
	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/pkg/ethclient"
	"github.com/blndgs/intents-cli/pkg/httpclient"
	"github.com/blndgs/intents-cli/pkg/userop"
	"github.com/blndgs/intents-cli/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

// SubmissionType represents different methods of submitting a UserOperation
type SubmissionType int

const (
	// Offline mode - only signs or generates or validates but does not submit the UserOperation
	Offline SubmissionType = iota
	// BundlerSubmit sends the UserOperation to an EIP-4337 bundler
	BundlerSubmit
	// BundlerSignSubmit signs and sends the UserOperation to an EIP-4337 bundler
	BundlerSignSubmit
	// DirectSubmit bypasses the bundler and sends directly to an Ethereum node
	DirectSubmit
)

type UserOpProcessor struct {
	Nodes                  config.NodesMap
	BundlerURL             string
	EntrypointAddr         common.Address
	KernelFactoryAddress   common.Address
	KernelValidatorAddress common.Address
	KernelExecutorAddress  common.Address
	Signer                 *signer.EOA
	ProvidedHashes         []common.Hash
	CachedHashes           []common.Hash
	ChainMonikers          []string
	ChainIDs               []*big.Int
	GenPrefixedKernelSig   bool
	GenKernelEnableSig     bool
}

func NewUserOpProcessor(
	userOps []*model.UserOperation, nodes config.NodesMap, bundlerURL string,
	entrypointAddr, kernelFactoryAddr, kernelValidatorAddr, kernelExecutorAddr common.Address, signer *signer.EOA,
	hashes []common.Hash, chainMonikers []string, kernelSig, enableSig bool,
) (*UserOpProcessor, error) {
	if len(userOps) == 0 {
		return nil, config.NewError("userOps is empty", nil)
	}
	if len(userOps) > 1 && len(hashes) > 0 {
		return nil, config.NewError(
			"hashes must be empty for multiple UserOperations as they are computed by the userOps", nil,
		)
	}

	chainIDs := make([]*big.Int, len(userOps))
	for opIdx := range userOps {
		chainMoniker := chainMonikers[opIdx]
		if len(userOps) == 1 && len(chainMonikers) == 2 {
			// user specified a different chainMoniker for the UserOperation
			chainMoniker = chainMonikers[1]
		}
		chainIDs[opIdx] = nodes[chainMoniker].ChainID
	}

	return &UserOpProcessor{
		Nodes:                  nodes,
		BundlerURL:             bundlerURL,
		EntrypointAddr:         entrypointAddr,
		KernelFactoryAddress:   kernelFactoryAddr,
		KernelValidatorAddress: kernelValidatorAddr,
		KernelExecutorAddress:  kernelExecutorAddr,
		Signer:                 signer,
		ProvidedHashes:         hashes,
		CachedHashes:           make([]common.Hash, 0, len(userOps)),
		ChainIDs:               chainIDs,
		ChainMonikers:          chainMonikers,
		GenPrefixedKernelSig:   kernelSig,
		GenKernelEnableSig:     enableSig,
	}, nil
}

// getProvidedHash returns the provided hash for the UserOperation at index i, if any.
func (p *UserOpProcessor) getProvidedHash(i int) common.Hash {
	if len(p.ProvidedHashes) > i && p.ProvidedHashes[i] != (common.Hash{}) {
		return p.ProvidedHashes[i]
	}
	return common.Hash{}
}

// set4337NonceForOp sets the EIP-4337 nonce for the UserOperation by determining the correct chainMoniker
// and calling Set4337Nonce.
func (p *UserOpProcessor) set4337NonceForOp(op *model.UserOperation, i int, userOps []*model.UserOperation) error {
	chainMoniker := p.ChainMonikers[i]
	if len(userOps) == 1 && len(p.ChainMonikers) == 2 {
		chainMoniker = p.ChainMonikers[1]
	}
	if err := p.Set4337Nonce(op, chainMoniker); err != nil {
		return config.NewError("failed setting EIP-4337 nonce", err)
	}
	return nil
}

// toSubmitOnChain checks if the UserOperation should be submitted on-chain.
// Only one UserOperation is ever submitted on-chain.
func (p *UserOpProcessor) toSubmitOnChain(
	userOps []*model.UserOperation, submissionAction SubmissionType, op *model.UserOperation,
) bool {
	return len(userOps) == 1 && ((submissionAction == BundlerSubmit && userop.IsAggregate(op)) || submissionAction == DirectSubmit)
}

// parseCrossChainData attempts to parse cross-chain data from either the callData or the signature.
func (p *UserOpProcessor) parseCrossChainData(op *model.UserOperation) (*model.CrossChainData, error) {
	if userop.HasXDataInCallData(op) {
		return model.ParseCrossChainData(op.CallData)
	} else if userop.HasXDataInSignature(op) {
		return model.ParseCrossChainData(op.Signature[op.GetSignatureEndIdx():])
	}
	return nil, config.NewError("no cross-chain xData found in cross-chain UserOp's callData or signature", nil)
}

// generateCrossChainHash parses the cross-chain data (from callData or signature) and generates a hash
// from the operation hashes.
func (p *UserOpProcessor) generateCrossChainHash(op *model.UserOperation) (common.Hash, error) {
	xData, err := p.parseCrossChainData(op)
	if err != nil {
		return common.Hash{}, err
	}

	hashes := make([]common.Hash, len(xData.HashList))
	for i, h := range xData.HashList {
		if h.IsPlaceholder {
			hashes[i] = op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[0])
		} else {
			hashes[i] = common.Hash(h.OperationHash)
		}
	}
	return userop.GenXHash(hashes), nil
}

// determineUserOpHash decides which strategy to use for computing the UserOperation hash:
// 1. Use provided hashes if available.
// 2. If not a bundler/ direct submit and not cross-chain, set the EIP-4337 nonce and compute the hash.
// 3. If a cross-chain operation under bundler/direct conditions, compute a cross-chain hash.
// 4. Otherwise, compute the default hash.
func (p *UserOpProcessor) determineUserOpHash(
	op *model.UserOperation, i int, userOps []*model.UserOperation, submissionAction SubmissionType,
) (common.Hash, error) {
	// Use provided hash if available
	if hash := p.getProvidedHash(i); hash != (common.Hash{}) {
		fmt.Printf("Provided UserOp hash: %s for ChainID: %s\n", hash, p.ChainIDs[i])
		return hash, nil
	}

	// If not direct or bundler submit, set the EIP-4337 nonce
	if submissionAction != BundlerSubmit && submissionAction != DirectSubmit {
		if err := p.set4337NonceForOp(op, i, userOps); err != nil {
			return common.Hash{}, err
		}
		// After setting nonce, compute the default hash
		return op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[i]), nil
	}

	// If cross-chain operation to submit on-chain, computes cross-chain hash
	if op.IsCrossChainOperation() && p.toSubmitOnChain(userOps, submissionAction, op) {
		hash, err := p.generateCrossChainHash(op)
		if err != nil {
			return common.Hash{}, err
		}
		fmt.Printf(
			"Generated XChain UserOp hash: %s for ChainID: %s, moniker: %s\n", hash, p.ChainIDs[i], p.ChainMonikers[i],
		)
		return hash, nil
	}

	// Otherwise, just compute the default hash
	hash := op.GetUserOpHash(p.EntrypointAddr, p.ChainIDs[i])
	fmt.Printf("Generated UserOp hash: %s for ChainID: %s, moniker: %s\n", hash, p.ChainIDs[i], p.ChainMonikers[i])
	return hash, nil
}

// setXOpHashes sets and caches the hash values for the given UserOperations.
// It delegates hash retrieval to helper functions that handle distinct logical branches.
func (p *UserOpProcessor) setXOpHashes(userOps []*model.UserOperation, submissionAction SubmissionType) error {
	for i, op := range userOps {
		hash, err := p.determineUserOpHash(op, i, userOps, submissionAction)
		if err != nil {
			return err
		}

		if len(p.CachedHashes) <= i || p.CachedHashes[i] != hash {
			p.CachedHashes = append(p.CachedHashes, hash)
		}
	}
	return nil
}

// ProcessUserOps processes the UserOperations by setting the UserOperation hashes,
// signing the UserOperations, and submitting the UserOperations to the bundler or
// directly to the Ethereum node.
func (p *UserOpProcessor) ProcessUserOps(userOps []*model.UserOperation, submissionAction SubmissionType) error {
	if err := p.setXOpHashes(userOps, submissionAction); err != nil {
		return config.NewError("error setting UserOperation hashes", err)
	}
	println()
	if len(userOps) > 1 {
		fmt.Printf("Aggregate xChain hash: %s\n", userop.GenXHash(p.CachedHashes))
	}

	// Prepare callData
	if len(userOps) == 1 {
		callData, err := abi.PrepareHandleOpCalldata(*userOps[0], userOps[0].Sender)
		if err != nil {
			return config.NewError("error preparing userOp callData", err)
		}
		fmt.Printf("\nEntrypoint handleOps callData: \n%s\n\n", callData)
	}

	if len(userOps[0].Signature) == 65 {
		if err := userop.CondResetSignature(p.Signer.PublicKey, userOps, p.CachedHashes); err != nil {
			return config.NewError("failed to verify signature", err)
		}
	}

	if len(userOps[0].Signature) == 0 || len(userOps) > 1 {
		// Unsigned userOp(s) or multiple userOps:
		// Set signature!
		if err := p.signAndPrintUserOps(userOps); err != nil {
			return err
		}
	} else {
		// Print JSON for verified userOp signature
		if submissionAction != DirectSubmit && submissionAction != BundlerSubmit {
			if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
				return config.NewError("failed to print signed userOp JSON", err)
			}
		}
	}

	switch submissionAction {
	case Offline:
		// Print signature only when the userOp is an Intent operation
		if userOps[0].HasIntent() && len(userOps) == 1 {
			utils.PrintPostIntentSolutionSignature(userOps[0])
		}

	case BundlerSubmit:
		// Submit to EIP-4337 bundler
		if err := p.sendUserOp(userOps[0]); err != nil {
			return err
		}

	case DirectSubmit:
		// Submit directly to Ethereum node
		if err := p.submit(context.Background(), p.ChainIDs[0], userOps[0]); err != nil {
			return err
		}

	default:
		return config.NewError(fmt.Sprintf("invalid submission type: %d", submissionAction), nil)
	}

	return nil
}

func (p *UserOpProcessor) Set4337Nonce(op *model.UserOperation, chainMoniker string) error {
	sender := op.Sender
	nodeConfig, ok := p.Nodes[chainMoniker]
	if !ok {
		return config.NewError(fmt.Sprintf("chainMoniker %s not found in Nodes map", chainMoniker), nil)
	}
	var err error
	aaNonce, err := ethclient.Get4337Nonce(nodeConfig.Node.RPCClient, sender)
	if err != nil {
		return fmt.Errorf("error getting nonce for sender %s on chain %s: %w", sender, chainMoniker, err)
	}
	utils.UpdateUserOp(op, aaNonce)
	return nil
}

func (p *UserOpProcessor) signAndPrintUserOps(userOps []*model.UserOperation) error {
	// UserOperations.
	// For multiple UserOperations, it prints the UserOperations with xCallData
	// values appended to the signature
	// It then prepares the userOperations for sending to the bundler and solver by
	// aggregating the UserOperations and prints the aggregated UserOperation.
	if p.BundlerURL == "" {
		return config.NewError("bundler URL is not set", nil)
	}

	if p.GenKernelEnableSig {
		// Override the userOps calldata value with the Kernel enable calldata
		callData, err := userop.GenKernelEnableCalldata(
			p.Signer.Address, p.KernelValidatorAddress, p.KernelExecutorAddress,
		)
		if err != nil {
			return config.NewError("failed to generate kernel enable calldata", err)
		}
		for _, op := range userOps {
			op.CallData = callData
		}
	}

	if err := userop.SignUserOperations(
		p.Signer, p.CachedHashes, userOps, p.GenKernelEnableSig,
		p.GenPrefixedKernelSig,
	); err != nil {
		return config.NewError(fmt.Sprintf("failed signing user operations of count:%d", len(userOps)), err)
	}

	recoveredAddress := userop.RecoverSigner(userop.GenXHash(p.CachedHashes), userOps[0].Signature)

	if len(userOps) == 1 {
		fmt.Printf("Signed userOp:\n%s\n", userOps[0])
		fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)

		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print signed userOp JSON", err)
		}
	} else {
		if err := p.setXCallDataValues(userOps); err != nil {
			return err
		}

		for i, op := range userOps {
			fmt.Printf("\nXChain userOp %d:\n%s\n", i, op)
			fmt.Printf("\nRecovered address: %s\n\n", recoveredAddress)
		}

		cpyOps := make([]*model.UserOperation, len(userOps))
		for i, op := range userOps {
			cpyOps[i] = new(model.UserOperation)
			*cpyOps[i] = *op
		}

		if err := p.moveXCallDataValues(cpyOps); err != nil {
			return config.NewError("failed to move xCallData values", err)
		}

		for i, op := range cpyOps {
			fmt.Printf("\nXChain UserOp with xCallData value appended to the signature value: %d:\n", i)
			if err := utils.PrintSignedOpJSON(op); err != nil {
				return config.NewError("failed to print signed userOp JSON", err)
			}
		}

		handleOpsCallData, err := abi.PrepareHandleOpCalldata(*cpyOps[1], cpyOps[1].Sender)
		if err != nil {
			return config.NewError("error preparing userOp handleOpsCallData", err)
		}
		fmt.Printf("\nHandleOps callData value (destination chain): \n%s\n\n", handleOpsCallData)

		if err := userOps[0].Aggregate(userOps[1]); err != nil {
			return config.NewError("failed to aggregate userOps", err)
		}

		fmt.Printf("\nAggregated userOp:\n%s\n", userOps[0])
		if err := utils.PrintSignedOpJSON(userOps[0]); err != nil {
			return config.NewError("failed to print signed userOp JSON", err)
		}
	}
	return nil
}

func (p *UserOpProcessor) moveXCallDataValues(userOps []*model.UserOperation) error {
	if len(userOps) != 2 {
		return config.NewError("only 2 UserOperations are supported", nil)
	}
	if !userOps[0].IsCrossChainOperation() || !userOps[1].IsCrossChainOperation() {
		return config.NewError("only cross-chain UserOperations are supported", nil)
	}

	if err := userOps[0].SetEVMInstructions([]byte{}); err != nil {
		return config.NewError("failed setting the sourceOp EVM instructions", err)
	}
	if err := userOps[1].SetEVMInstructions([]byte{}); err != nil {
		return config.NewError("failed setting the destOp EVM instructions", err)
	}
	return nil
}

func (p *UserOpProcessor) setXCallDataValues(userOps []*model.UserOperation) error {
	if len(userOps) != 2 {
		return config.NewError("only 2 UserOperations are supported", nil)
	}

	var err error
	userOps[0].CallData, err = userOps[0].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[1], true)
	if err != nil {
		return config.NewError("failed encoding the sourceOp xCallData value", err)
	}

	userOps[1].CallData, err = userOps[1].EncodeCrossChainCallData(p.EntrypointAddr, p.CachedHashes[0], false)
	if err != nil {
		return config.NewError("failed encoding the destOp xCallData value", err)
	}
	return nil
}

func (p *UserOpProcessor) sendUserOp(signedUserOp *model.UserOperation) error {
	hashResp, err := httpclient.SendUserOp(p.BundlerURL, p.EntrypointAddr, signedUserOp)
	if err != nil {
		return config.NewError("failed to send user operation", err)
	}

	fmt.Printf("sign and send userOps hashResp: %+v\n", hashResp)

	receipt, err := httpclient.GetUserOperationReceipt(p.BundlerURL, hashResp.Solved)
	if err != nil {
		fmt.Println("Error getting UserOperation receipt:", err)
		return config.NewError("failed to get user operation receipt", err)
	}

	fmt.Println("UserOperation Receipt:", string(receipt))
	return nil
}

func (p *UserOpProcessor) submit(ctx context.Context, chainID *big.Int, signedUserOp *model.UserOperation) error {
	gasParams, err := getGasParams(ctx, p.Nodes[config.DefaultRPCURLKey].Node.EthClient)
	if err != nil {
		return config.NewError("failed to get gas parameters", err)
	}

	opts := createTransactionOpts(
		p.Nodes[config.DefaultRPCURLKey].Node.EthClient, chainID, p.EntrypointAddr, p.Signer, signedUserOp, gasParams,
	)

	if err := executeUserOperation(opts); err != nil {
		return config.NewError("failed executing user operation", err)
	}
	return nil
}
