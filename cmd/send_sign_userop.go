// send_sign_userop.go
package cmd

import (
	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/spf13/cobra"
)

func init() {
	if err := utils.AddCommonFlags(SendAndSignUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// SendAndSignUserOpCmd represents the command to sign and send user operations.
var SendAndSignUserOpCmd = &cobra.Command{
	Use:   "sign-send",
	Short: "Sign and send userOps with JSON input",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read configuration and initialize necessary components.
		nodes, bundlerURL, entrypointAddr, eoaSigner, err := config.ReadConf(false)
		if err != nil {
			return config.NewError("failed to read configuration", err)
		}
		userOps, err := utils.GetUserOps(cmd)
		if err != nil {
			return config.NewError("failed to get user operations", err)
		}

		kernelSig, enableSig, err := utils.GetKernelOptions(cmd)
		if err != nil {
			return config.NewError("failed to get kernel options", err)
		}

		hashes, err := utils.GetHashes(cmd)
		if err != nil {
			return config.NewError("failed to get hashes", err)
		}
		chainMonikers, err := utils.GetChainMonikers(cmd, nodes, len(userOps))
		if err != nil {
			return config.NewError("failed to get chain monikers", err)
		}

		processor, err := NewUserOpProcessor(userOps, nodes, bundlerURL, entrypointAddr, eoaSigner, hashes, chainMonikers)
		if err != nil {
			return config.NewError("failed to create user operation processor", err)
		}

		if err := processor.ProcessUserOps(userOps, BundlerSignSubmit); err != nil {
			return config.NewError("failed to process user operations", err)
		}

		return nil
	},
}
