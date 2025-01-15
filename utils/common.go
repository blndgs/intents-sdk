package utils

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blndgs/intents-cli/pkg/config"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
)

type NoncesMap map[string]*big.Int // moniker -> nonce

// AddCommonFlags adds common flags to the provided Cobra command.
func AddCommonFlags(cmd *cobra.Command) error {
	cmd.Flags().String("u", "", "User operation JSON")
	cmd.Flags().String("h", "", "List of other cross-chain user operations hashes")
	cmd.Flags().String("c", "", "List of other user operations' Chains")
	cmd.Flags().String("k", "", "Sign for the Kernel wallet")
	cmd.Flags().String("e", "", "Generate an enable signature for the Kernel wallet")

	// Override the default error handling
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	if err := cmd.MarkFlagRequired("u"); err != nil {
		return config.NewError("failed to mark 'u' flag as required", err)
	}
	return nil
}

// sanitizeUserOpJSON cleans up the input JSON string
func sanitizeUserOpJSON(userOpJSON string) string {
	// Trim leading and trailing whitespace and control characters
	userOpJSON = strings.TrimFunc(userOpJSON, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})

	// This will match quoted strings followed by colon; presumes that whitespace is not allowed in field names
	fieldNameRegex := `"([^"]+)":`

	// To clean up spaces in field names but preserve the values:
	userOpJSON = regexp.MustCompile(fieldNameRegex).ReplaceAllStringFunc(userOpJSON, func(match string) string {
		// Remove spaces from the field name part while preserving the quotes and colon
		cleaned := regexp.MustCompile(`\s+`).ReplaceAllString(match, "")
		return cleaned
	})

	// Remove BOM character if present
	userOpJSON = strings.TrimPrefix(userOpJSON, "\uFEFF")

	if !utf8.ValidString(userOpJSON) {
		userOpJSON = strings.ToValidUTF8(userOpJSON, "")
	}

	return userOpJSON
}

// GetUserOps parses the 'userop' JSON string or file provided in the command flags
// and returns a slice of UserOperation objects. It processes numeric values
// before unmarshaling to ensure proper formatting.
func GetUserOps(cmd *cobra.Command) ([]*model.UserOperation, error) {
	userOpInput, _ := cmd.Flags().GetString("u")
	if userOpInput == "" {
		return nil, config.NewError("user operation JSON is required", nil)
	}
	userOpInput = strings.TrimSpace(userOpInput)

	var jsonContent string
	if strings.HasPrefix(userOpInput, "{") || strings.HasPrefix(userOpInput, "[") {
		jsonContent = userOpInput
	} else if fileExists(userOpInput) {
		fileContent, err := os.ReadFile(userOpInput)
		if err != nil {
			return nil, config.NewError("error reading user operation file", err)
		}
		jsonContent = string(fileContent)
	} else {
		return nil, config.NewError("invalid user operation input", nil)
	}

	sanitizedJSON := sanitizeUserOpJSON(jsonContent)

	// Unmarshal the JSON into an interface{} to process fields
	var data interface{}
	dec := json.NewDecoder(strings.NewReader(sanitizedJSON))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return nil, config.NewError("error parsing user operation JSON", err)
	}

	// Process callData field first
	if err := processCallDataFields(data); err != nil {
		return nil, err
	}

	// Process numeric fields excluding callData
	processNumericFields(data)

	// Marshal the modified data back into JSON
	modifiedJSONBytes, err := json.Marshal(data)
	if err != nil {
		return nil, config.NewError("error marshaling modified user operation JSON", err)
	}
	modifiedJSON := string(modifiedJSONBytes)

	// Unmarshal into model.UserOperation structs
	return unMarshalOps(modifiedJSON)
}

// unMarshalOps unmarshals the modified JSON into UserOperation structs
func unMarshalOps(userOpJSON string) ([]*model.UserOperation, error) {
	var userOps []*model.UserOperation
	// Determine if the input is a single userOp or an array of userOps
	if strings.HasPrefix(userOpJSON, "[") {
		// Input is an array of userOps
		err := json.Unmarshal([]byte(userOpJSON), &userOps)
		if err != nil {
			return nil, config.NewError("error parsing user operations JSON array", err)
		}
	} else {
		// Input is a single userOp
		var userOp model.UserOperation
		err := json.Unmarshal([]byte(userOpJSON), &userOp)
		if err != nil {
			return nil, config.NewError("error parsing single user operation JSON", err)
		}
		userOps = append(userOps, &userOp)
	}
	return userOps, nil
}

func processNumericFields(v interface{}) {
	switch vv := v.(type) {
	case map[string]interface{}:
		for key, val := range vv {
			if key != "callData" && key != "initCode" && key != "paymasterAndData" && key != "signature" {
				switch valTyped := val.(type) {
				case json.Number:
					bigInt, ok := new(big.Int).SetString(valTyped.String(), 10)
					if ok {
						vv[key] = "0x" + bigInt.Text(16)
					}
				case string:
					if valTyped == "" {
						vv[key] = "0x"
					} else if valTyped == "0" {
						vv[key] = "0x0"
					} else if IsNumericString(valTyped) {
						bigInt, ok := new(big.Int).SetString(valTyped, 10)
						if ok {
							vv[key] = "0x" + bigInt.Text(16)
						}
					}
				default:
					// Recursively process nested structures
					processNumericFields(val)
				}
			}
		}
	case []interface{}:
		// Handle arrays by processing each item
		for _, item := range vv {
			processNumericFields(item)
		}
	}
}

// IsNumericString checks if a string represents a numeric value (big.Int)
func IsNumericString(s string) bool {
	_, ok := new(big.Int).SetString(s, 10)
	return ok
}

// processCallDataFields processes the 'callData' field to ensure it is correctly formatted
func processCallDataFields(v interface{}) error {
	const maxCallDataSize = 128 * 1024 // 128KB limit
	if vv, ok := v.(map[string]interface{}); ok {
		for key, val := range vv {
			if key == "callData" {
				// Check size limits
				if jsonStr, ok := val.(string); ok && len(jsonStr) > maxCallDataSize {
					return config.NewError("callData exceeds size limit", nil)
				}
				switch callDataVal := val.(type) {
				case string:
					if err := processCallDataString(vv, key, callDataVal); err != nil {
						return err
					}
				case json.Number:
					if err := processCallDataNumber(vv, key, callDataVal); err != nil {
						return err
					}
				default:
					return config.NewError(fmt.Sprintf("invalid callData type: %T", val), nil)
				}
			} else {
				// Recursively process nested structures
				if err := processCallDataFields(val); err != nil {
					return err
				}
			}
		}
	} else if vv, ok := v.([]interface{}); ok {
		for _, item := range vv {
			if err := processCallDataFields(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func processCallDataString(vv map[string]interface{}, key string, callDataStr string) error {
	if callDataStr == "" || callDataStr == "{}" {
		vv[key] = "0x"
	} else if callDataStr == "0" {
		vv[key] = "0x0"
	} else if IsValidHex(callDataStr) {
		// Already valid hex string, do nothing
	} else {
		// Process callDataStr using ConvJSONNum2ProtoValues
		modifiedCallData, err := ConvJSONNum2ProtoValues(callDataStr)
		if err == nil {
			vv[key] = modifiedCallData
		} else {
			return config.NewError("error processing callData", err)
		}
	}
	return nil
}

func processCallDataNumber(vv map[string]interface{}, key string, callDataNum json.Number) error {
	callDataStr := callDataNum.String()
	if callDataStr == "0" {
		vv[key] = "0x0"
	} else {
		bigInt, ok := new(big.Int).SetString(callDataStr, 10)
		if ok {
			vv[key] = "0x" + bigInt.Text(16)
		} else {
			return config.NewError(fmt.Sprintf("invalid callData number: %v", callDataStr), nil)
		}
	}
	return nil
}

// GetHashes parses the 32-byte hash values from the command line flag 'h' and returns a slice of common.Hash.
func GetHashes(cmd *cobra.Command) ([]common.Hash, error) {
	hashesStr, _ := cmd.Flags().GetString("h")
	if hashesStr == "" {
		return nil, nil
	}

	hashes := strings.Split(hashesStr, " ")
	var parsedHashes []common.Hash

	for _, hashStr := range hashes {
		hashStr = strings.TrimPrefix(hashStr, "0x")
		if len(hashStr) != 64 {
			return nil, config.NewError(fmt.Sprintf("invalid hash length for %s: expected 64 characters", hashStr), nil)
		}

		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil {
			return nil, config.NewError(fmt.Sprintf("invalid hex string for hash %s", hashStr), err)
		}

		var hash common.Hash
		copy(hash[:], hashBytes)
		parsedHashes = append(parsedHashes, hash)
	}

	return parsedHashes, nil
}

// GetKernelOptions parses the command line flag 'k' or command line flag 'e'
// `k`: generate kernel signature
// `e`: generate a kernel enable signature
func GetKernelOptions(cmd *cobra.Command) (kernelSig, enableSig bool, err error) {
	kernelSig = cmd.Flags().Changed("k")
	enableSig = cmd.Flags().Changed("e")

	if kernelSig && enableSig {
		return false, false, config.NewError("both 'k' and 'e' flags cannot be set simultaneously", nil)
	}

	return kernelSig, enableSig, nil
}

// GetChainMonikers parses the network moniker or numeric chain-id value from the command line
// flag 'c' and returns a slice of chain monikers.
func GetChainMonikers(cmd *cobra.Command, nodesMap config.NodesMap, opsCount int) ([]string, error) {
	var parsedChains = []string{config.DefaultRPCURLKey}
	chainsStr, _ := cmd.Flags().GetString("c")
	if chainsStr == "" && opsCount > 1 {
		return nil, config.NewError("chains flag is required when multiple userOps were provided", nil)
	}
	if chainsStr == "" {
		return parsedChains, nil
	}

	chains := strings.Split(chainsStr, " ")
	if len(chains) > opsCount {
		return nil, config.NewError("number of chains provided is more than the number of user operations", nil)
	}
	if len(chains) > len(nodesMap) {
		return nil, config.NewError("number of chains provided is more than the number of nodes in the configuration map", nil)
	}
	if len(chains) < opsCount-1 && opsCount > 1 {
		return nil, config.NewError("number of chains provided is less than the number of user operations", nil)
	}

	for _, chain := range chains {
		if strings.ToLower(chain) == config.DefaultRPCURLKey {
			return nil, config.NewError(fmt.Sprintf("chain %s has already been added in the first position", chain), nil)
		}
		if _, ok := nodesMap[chain]; ok {
			parsedChains = append(parsedChains, chain)
		} else {
			// Check if the chain is a chain ID
			var found bool
			for moniker, node := range nodesMap {
				// Check if the chain ID matches the chain ID of the node
				if node.ChainID.String() == chain {
					parsedChains = append(parsedChains, moniker)
					found = true
					break
				}
			}
			if !found {
				return nil, config.NewError(fmt.Sprintf("chain %s not found in the nodes configuration", chain), nil)
			}
		}
	}

	return parsedChains, nil
}

// UpdateUserOp sets the nonce value and 4337 default gas limits if they are zero.
func UpdateUserOp(userOp *model.UserOperation, nonce *big.Int) *model.UserOperation {
	zero := big.NewInt(0)

	if userOp.CallGasLimit.Cmp(zero) == 0 {
		userOp.CallGasLimit = big.NewInt(65536)
	}
	if userOp.VerificationGasLimit.Cmp(zero) == 0 {
		userOp.VerificationGasLimit = big.NewInt(65536)
	}
	if userOp.PreVerificationGas.Cmp(zero) == 0 {
		userOp.PreVerificationGas = big.NewInt(70000)
	}

	userOp.Nonce = nonce
	return userOp
}

// PrintSignedOpJSON marshals a UserOperation to JSON and prints it.
// If the UserOperation is a cross-chain operation and the signature contains
// cross-chain or aggregate metadata.
func PrintSignedOpJSON(userOp *model.UserOperation) error {
	jsonBytes, err := json.Marshal(userOp)
	if err != nil {
		return config.NewError("failed marshaling signed operations to JSON", err)
	}

	// Print signed Op JSON
	if userOp.IsCrossChainOperation() && len(userOp.Signature) > 65 {
		_, err := model.ParseCrossChainData(userOp.Signature[65:])
		if err != nil {
			// The embedded userOp is appended to the signature value
			fmt.Println("Signed Aggregate XChain UserOp in JSON:", string(jsonBytes))
		} else {
			// xCallData value is appended to the signature value
			fmt.Println(string(jsonBytes))
		}
	} else if userOp.IsCrossChainOperation() {
		fmt.Println("Signed XChain UserOp in JSON:", string(jsonBytes))
	} else {
		fmt.Println("Signed UserOp in JSON:", string(jsonBytes))
	}
	return nil
}

// PrintPostIntentSolutionSignature prints the signature + hex encoded intent JSON (calldata).
func PrintPostIntentSolutionSignature(userOp *model.UserOperation) {
	if len(userOp.Signature) >= 65 {
		fmt.Printf("\nSignature value after solution:\n%s\n",
			hexutil.Encode(userOp.Signature[:65])+hex.EncodeToString(userOp.CallData))
	}
}

// IsValidHex checks if a string is a valid hexadecimal representation.
func IsValidHex(s string) bool {
	re := regexp.MustCompile(`^0x[0-9a-fA-F]*$`)
	return re.MatchString(s)
}

// ConvJSONNum2ProtoValues converts numeric values in a JSON string to base64 encoded BigInt representations.
// It specifically looks for fields named "value" and converts their numeric contents.
func ConvJSONNum2ProtoValues(jsonStr string) (string, error) {
	var data interface{}

	// Create a decoder that preserves number precision
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()

	// Decode the JSON string
	if err := dec.Decode(&data); err != nil {
		return "", err
	}

	// Process all values recursively
	processMapValues(data)

	// Marshal the processed data back to JSON
	outputBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(outputBytes), nil
}

// processMapValues recursively processes a decoded JSON structure, converting numeric "value" fields
// to their base64 encoded BigInt representation.
func processMapValues(v interface{}) {
	switch vv := v.(type) {
	case map[string]interface{}:
		// Process each key-value pair in the map
		for key, val := range vv {
			if key == "value" {
				// Convert numeric values when the key is "value"
				switch num := val.(type) {
				case json.Number:
					vv[key] = convertNumberToBase64(num.String())
				case string:
					// Try to parse the string as a number
					if _, ok := new(big.Int).SetString(num, 10); ok {
						vv[key] = convertNumberToBase64(num)
					} else if num == "" {
						vv[key] = "0x"
					} else if num == "0" {
						vv[key] = "0x0"
					}
				}
			} else {
				// Recursively process nested structures
				processMapValues(val)
			}
		}
	case []interface{}:
		// Process each item in the array
		for _, item := range vv {
			processMapValues(item)
		}
	}
}

// convertNumberToBase64 converts a numeric string to its base64 encoded BigInt representation.
func convertNumberToBase64(numStr string) string {
	// Convert string number to BigInt
	bigInt := new(big.Int)
	bigInt.SetString(numStr, 10)

	// Convert BigInt to bytes and then to base64
	bytes := bigInt.Bytes()
	base64Value := base64.StdEncoding.EncodeToString(bytes)
	return base64Value
}

// fileExists checks if a file exists at the given path.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}
