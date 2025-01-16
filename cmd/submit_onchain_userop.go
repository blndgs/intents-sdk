package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	geth "github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackup-wallet/stackup-bundler/pkg/entrypoint/transaction"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	stackup_userop "github.com/stackup-wallet/stackup-bundler/pkg/userop"
)

// init initializes the submitUserOp command and adds it to the root command.
func init() {
	if err := utils.AddCommonFlags(OnChainUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// OnChainUserOpCmd represents the command to submit user operations on-chain.
var OnChainUserOpCmd = &cobra.Command{
	Use:   "onchain",
	Short: "Submit a signed userOp on-chain bypassing the bundler",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read configuration and initialize necessary components.
		configuration, err := config.ReadConf(false)
		if err != nil {
			return config.NewError("failed to read configuration", err)
		}
		userOps, err := utils.GetUserOps(cmd)
		if err != nil {
			return config.NewError("failed to get user operations", err)
		}
		hashes, err := utils.GetHashes(cmd)
		if err != nil {
			return config.NewError("failed to get hashes", err)
		}
		chainMonikers, err := utils.GetChainMonikers(cmd, configuration.NodesMap, len(userOps))
		if err != nil {
			return config.NewError("failed to get chain monikers", err)
		}

		processor, err := NewUserOpProcessor(
			userOps, configuration.NodesMap, configuration.BundlerURL, configuration.EntryPointAddr,
			configuration.KernelFactoryAddr,
			configuration.KernelValidatorAddr,
			configuration.KernelExecutorAddr, configuration.Signer, hashes, chainMonikers, false, false,
		)
		if err != nil {
			return config.NewError("failed to create user operation processor", err)
		}

		if err := processor.ProcessUserOps(userOps, DirectSubmit); err != nil {
			return config.NewError("failed to process user operations", err)
		}

		return nil
	},
}

func getGasParams(ctx context.Context, rpc *geth.Client) (config.GasParams, error) {
	header, err := rpc.HeaderByNumber(ctx, nil)
	if err != nil {
		return config.GasParams{}, errors.Wrap(err, "failed to get latest block header")
	}
	baseFee := header.BaseFee

	tipCap, err := rpc.SuggestGasTipCap(ctx)
	if err != nil {
		return config.GasParams{}, errors.Wrap(err, "failed to get gas tip cap")
	}

	// legacy gas price calculation
	gasPrice := new(big.Int).Add(baseFee, tipCap)

	return config.GasParams{
		BaseFee:  baseFee,
		Tip:      tipCap,
		GasPrice: gasPrice,
	}, nil
}

func createTransactionOpts(
	rpcClient *geth.Client, chainID *big.Int, entrypointAddr common.Address, eoaSigner *signer.EOA,
	signedUserOp *model.UserOperation, gasParams config.GasParams,
) transaction.Opts {
	stackupUserOp := stackup_userop.UserOperation(*signedUserOp)

	// Calculate gas limit with buffer for Squid operations
	gasLimit := new(big.Int).Add(
		new(big.Int).Add(signedUserOp.PreVerificationGas, signedUserOp.VerificationGasLimit), signedUserOp.CallGasLimit,
	).Uint64() + 100_000

	return transaction.Opts{
		Eth:         rpcClient,
		EOA:         eoaSigner,
		ChainID:     chainID,
		EntryPoint:  entrypointAddr,
		Batch:       []*stackup_userop.UserOperation{&stackupUserOp},
		Beneficiary: signedUserOp.Sender,
		BaseFee:     gasParams.BaseFee,
		Tip:         gasParams.Tip,
		GasPrice:    gasParams.GasPrice,
		GasLimit:    gasLimit,
		NoSend:      false,
		WaitTimeout: 4 * time.Minute, // Increased timeout for cross-chain
	}
}

func executeUserOperation(opts transaction.Opts) error {
	tx, err := transaction.HandleOps(&opts)
	if err != nil {
		// Try to cast to DataError interface to extract error data
		var dataErr rpc.DataError
		if errors.As(err, &dataErr) {
			errData := dataErr.ErrorData()
			// Determine the type of errData
			switch data := errData.(type) {
			case string:
				dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
				if err != nil {
					return errors.Wrap(err, "failed to decode error data")
				}
				if epErr, decodeErr := DecodeEntryPointError(dataBytes); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			case []byte:
				if epErr, decodeErr := DecodeEntryPointError(data); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			case hexutil.Bytes:
				if epErr, decodeErr := DecodeEntryPointError(data); decodeErr == nil {
					return errors.Wrap(epErr, "EntryPoint error")
				}
			default:
				fmt.Printf("Unknown ErrorData type: %T\n", data)
			}
		}
		// If all else fails, return the original error
		return errors.Wrap(err, "failed to submit user operation on-chain")
	}

	fmt.Printf("UserOperation executed successfully, tx hash: %s\n", tx.Hash().Hex())
	return nil
}
