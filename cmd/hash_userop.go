package cmd

import (
	"fmt"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/intents-cli/utils"
	"github.com/spf13/cobra"
)

func init() {
	if err := utils.AddCommonFlags(HashUserOpCmd); err != nil {
		panic(config.NewError("failed to add common flags", err))
	}
}

// HashUserOpCmd represents the command to sign user operations.
var HashUserOpCmd = &cobra.Command{
	Use:   "hash",
	Short: "Print the userOp's hash",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read configuration and initialize the necessary parts.
		conf, err := config.ReadConf(false)
		if err != nil {
			return config.NewError("failed to read configuration", err)
		}

		// Single userOp should be returned
		userOps, err := utils.GetUserOps(cmd)
		if err != nil {
			return config.NewError("failed to get user operations", err)
		}

		if len(userOps) != 1 {
			return config.NewError("invalid number of user operations", fmt.Errorf("expected 1 userOp, got %d", len(userOps)))
		}

		chainMonikers, err := utils.GetChainMonikers(cmd, conf.NodesMap, len(userOps))
		if err != nil {
			return config.NewError("failed to get chain monikers", err)
		}

		providedHashes, err := utils.GetHashes(cmd)
		if err != nil {
			return config.NewError("failed to get hashes", err)
		}

		p, err := NewUserOpProcessor(userOps, conf.NodesMap, "", conf.EntryPointAddr, conf.Signer, providedHashes, chainMonikers, false, false)
		if err != nil {
			return config.NewError("failed to create user operation processor", err)
		}

		if err := p.setXOpHashes(userOps, Offline); err != nil {
			return config.NewError("failed to set operation hashes", err)
		}

		return nil
	},
}
