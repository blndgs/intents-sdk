package cmd

import (
	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/spf13/cobra"
)

// init initializes the sendUserOp command and adds it to the root command.
func init() {
	if err := utils.AddCommonFlags(SendUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// SendUserOpCmd represents the command to send user operations.
var SendUserOpCmd = &cobra.Command{
	Use:   "send",
	Short: "Send userOps with JSON input",
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
			configuration.KernelValidatorAddr, configuration.KernelExecutorAddr, configuration.Signer, hashes,
			chainMonikers, false, false,
		)
		if err != nil {
			return config.NewError("failed to create user operation processor", err)
		}

		if err := processor.ProcessUserOps(userOps, BundlerSubmit); err != nil {
			return config.NewError("failed to process user operations", err)
		}

		return nil
	},
}
