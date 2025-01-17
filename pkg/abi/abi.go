package abi

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blndgs/intents-cli/pkg/userop"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ABI definition for handleOps function
const handleOpABI = `[
  {
    "inputs": [
      {
        "components": [
          {
            "internalType": "address",
            "name": "sender",
            "type": "address"
          },
          {
            "internalType": "uint256",
            "name": "nonce",
            "type": "uint256"
          },
          {
            "internalType": "bytes",
            "name": "initCode",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "callData",
            "type": "bytes"
          },
          {
            "internalType": "uint256",
            "name": "callGasLimit",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "verificationGasLimit",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "preVerificationGas",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "maxFeePerGas",
            "type": "uint256"
          },
          {
            "internalType": "uint256",
            "name": "maxPriorityFeePerGas",
            "type": "uint256"
          },
          {
            "internalType": "bytes",
            "name": "paymasterAndData",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "signature",
            "type": "bytes"
          }
        ],
        "internalType": "struct UserOperation[]",
        "name": "ops",
        "type": "tuple[]"
      },
      {
        "internalType": "address payable",
        "name": "beneficiary",
        "type": "address"
      }
    ],
    "name": "handleOps",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`

// PrepareHandleOpCalldata moves the IntentJSON to the signature field and
// empties the calldata field to allow an Intent EVM solution to be
// populated. Applies only to cross-chain operations that are not aggregated.
func PrepareHandleOpCalldata(op model.UserOperation, beneficiary common.Address) (string, error) {
	if len(op.CallData) > 0 && op.IsCrossChainOperation() && !userop.IsAggregate(&op) {
		iJSON, err := op.GetIntentJSON()
		if err == nil && bytes.Equal(op.CallData, []byte(iJSON)) {
			// Append the Intent JSON to the signature to prepare it for on-chain execution
			// Cross-chain operations are meaningful only when they have Intent JSON
			if err := op.SetEVMInstructions([]byte{}); err != nil {
				return "", fmt.Errorf("failed to set EVM instructions: %s", err)
			}
		}
	}

	parsedABI, err := abi.JSON(strings.NewReader(handleOpABI))
	if err != nil {
		return "", fmt.Errorf("failed to read abi json: %s", err)
	}

	calldata, err := parsedABI.Pack("handleOps", []model.UserOperation{op}, beneficiary)
	if err != nil {
		return "", fmt.Errorf("failed to pack data: %s", err)
	}

	return "0x" + hex.EncodeToString(calldata), nil
}
