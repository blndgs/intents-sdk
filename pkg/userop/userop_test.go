package userop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/blndgs/intents-cli/utils"
	"github.com/blndgs/model"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
	"github.com/stretchr/testify/require"

	"github.com/blndgs/intents-cli/pkg/userop"
)

// TestMatchSoliditySignature tests signing of classic and Intent UserOperations.
func TestMatchSoliditySignature(t *testing.T) {
	testCases := []struct {
		name              string
		chainID           *big.Int
		entryPointAddr    common.Address
		signer            *signer.EOA
		userOp            model.UserOperation
		expectedSignature string
	}{
		{
			name:           "Match Solidity Signature with conventional userOp",
			chainID:        big.NewInt(137),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         mustCreateSigner("e8776ff1bf88707b464bda52319a747a71c41a137277161dcabb9f821d6c0bd7"),
			userOp: model.UserOperation{
				Sender:               common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47"),
				Nonce:                big.NewInt(0),
				InitCode:             []byte{},
				CallData:             []byte{},
				CallGasLimit:         big.NewInt(3000000),
				VerificationGasLimit: big.NewInt(3000000),
				PreVerificationGas:   big.NewInt(47984),
				MaxFeePerGas:         big.NewInt(33900000030),
				MaxPriorityFeePerGas: big.NewInt(33900000000),
			},
			expectedSignature: "b85bc0d0d063ec3f9b008da439afc9621d951c01a2535013fa1d8a1f2e804a5676e3bacc27979303701c25332536852b884b3746484e8043bab3964a14f4c9dd1c",
		},
		{
			name:           "Match Solidity Signature with Intent userOp",
			chainID:        big.NewInt(137),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         mustCreateSigner("e8776ff1bf88707b464bda52319a747a71c41a137277161dcabb9f821d6c0bd7"),
			userOp: model.UserOperation{
				Sender:               common.HexToAddress("0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47"),
				Nonce:                big.NewInt(0x0),
				InitCode:             []byte{},
				CallData:             []byte("{\"fromAsset\":{\"address\":\"0x6b175474e89094c44da98b954eedeac495271d0f\",\"amount\":{\"value\":\"1000000000000000000\"},\"chainId\":{\"value\":\"1\"}},\"toAsset\":{\"address\":\"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\",\"amount\":{\"value\":\"1000000\"},\"chainId\":{\"value\":\"1\"}}}"),
				CallGasLimit:         big.NewInt(35000),
				VerificationGasLimit: big.NewInt(70000),
				PreVerificationGas:   big.NewInt(21000),
				MaxFeePerGas:         big.NewInt(90400000032),
				MaxPriorityFeePerGas: big.NewInt(90400000000),
			},
			expectedSignature: "1a68b7ec156022b8ff9403cb3ce5889546e554e00497e6450049fb18638cd6237ecf6827680e53f0c199e673b55838e2d183a7aec7db78c3853505d87c16ac861c",
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				hash := tc.userOp.GetUserOpHash(tc.entryPointAddr, tc.chainID)
				hashes := []common.Hash{hash}
				userOps := []*model.UserOperation{&tc.userOp}
				err := userop.SignUserOperations(tc.signer, hashes, userOps, false, false)
				require.NoError(t, err)
				isValid, err := userop.VerifySignature(tc.signer.PublicKey, userOps, hashes)
				require.NoError(t, err, "error verifying signature for %s", tc.userOp)
				require.True(t, isValid, "signature is invalid for %s", tc.userOp)
				actualSig := fmt.Sprintf("%x", tc.userOp.Signature)
				require.Equal(t, tc.expectedSignature, actualSig)
				genSig, err := userop.GenerateSignature(hash, tc.signer.PrivateKey)
				genSigSigned := fmt.Sprintf("%x", genSig)
				require.NoError(t, err)
				require.Equal(t, tc.expectedSignature, genSigSigned)
			},
		)
	}
}

// TestSignConventionalUserOps tests signing of non-Intent UserOperations.
func TestSignConventionalUserOps(t *testing.T) {
	testCases := []struct {
		name           string
		chainID        *big.Int
		entryPointAddr common.Address
		signer         *signer.EOA
		userOp         string
		wantErr        bool
	}{
		{
			name:           "Successful Signing with conventional userOp",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         validPrivateKey(),
			userOp: `{
                "sender": "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
                "nonce": "0xf",
                "initCode": "0x",
                "callData": "0x7b22636861696e4964223a38303030312c202273656e646572223a22307830413731393961393666646630323532453039463736353435633145663262653336393246343662222c20226b696e64223a2273776170222c202268617368223a22222c202273656c6c546f6b656e223a22546f6b656e41222c2022627579546f6b656e223a22546f6b656e42222c202273656c6c416d6f756e74223a31302c2022627579416d6f756e74223a352c20227061727469616c6c7946696c6c61626c65223a66616c73652c2022737461747573223a225265636569766564222c2022637265617465644174223a302c202265787069726174696f6e4174223a307d",
                "callGasLimit": "0x0",
                "verificationGasLimit": "0x11170",
                "preVerificationGas": "0x0",
                "maxFeePerGas": "0x0",
                "maxPriorityFeePerGas": "0x0",
                "paymasterAndData": "0x",
                "signature": "0x8e8a12900df61d02ad6907c15315564f55ae38323c82bb44e673a52c6230bc8455a85e6721575f8b139e0d191d24557d46c6670999552a0ad9d3167e25ad3f0b1b"
            }`,
			wantErr: false,
		},
		{
			name:           "Unsuccessful Signing",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         invalidPrivateKey(),
			userOp: `{
                "sender": "0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47",
                "nonce": "0xf",
                "initCode": "0x",
                "callData": "0x7b22636861696e4964223a38303030312c202273656e646572223a22307830413731393961393666646630323532453039463736353435633145663262653336393246343662222c20226b696e64223a2273776170222c202268617368223a22222c202273656c6c546f6b656e223a22546f6b656e41222c2022627579546f6b656e223a22546f6b656e42222c202273656c6c416d6f756e74223a31302c2022627579416d6f756e74223a352c20227061727469616c6c7946696c6c61626c65223a66616c73652c2022737461747573223a225265636569766564222c2022637265617465644174223a302c202265787069726174696f6e4174223a307d",
                "callGasLimit": "0x0",
                "verificationGasLimit": "0x11170",
                "preVerificationGas": "0x0",
                "maxFeePerGas": "0x0",
                "maxPriorityFeePerGas": "0x0",
                "paymasterAndData": "0x",
                "signature": "0x8e8a12900df61d02ad6907c15315564f55ae38323c82bb44e673a52c6230bc8455a85e6721575f8b139e0d191d24557d46c6670999552a0ad9d3167e25ad3f0b1b"
            }`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				var userOp model.UserOperation
				err := json.Unmarshal([]byte(tc.userOp), &userOp)
				require.NoError(t, err)

				hash := userOp.GetUserOpHash(tc.entryPointAddr, tc.chainID)
				hashes := []common.Hash{hash}
				userOps := []*model.UserOperation{&userOp}
				err = userop.SignUserOperations(tc.signer, hashes, userOps, false, false)
				if tc.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					valid, err := userop.VerifySignature(tc.signer.PublicKey, userOps, hashes)
					require.NoError(t, err, "error verifying signature for %s", tc.userOp)
					require.True(t, valid, "signature is invalid for %s", tc.userOp)
				}
			},
		)
	}
}

// Helper function to process callData
func processCallData(callData string) (string, error) {
	if callData == "" || callData == "{}" || callData == "0x" {
		return callData, nil
	}
	if !utils.IsValidHex(callData) {
		return utils.ConvJSONNum2ProtoValues(callData)
	}
	return callData, nil
}

func TestIntentUserOpSign(t *testing.T) {
	testCases := []struct {
		name           string
		chainID        *big.Int
		entryPointAddr common.Address
		signer         *signer.EOA
		userOp         string
		wantErr        bool
	}{
		{
			name:           "Successful Signing with Proto Intent userOp from sample.json",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         validPrivateKey(),
			userOp: `{
              "sender":"0xff6f893437e88040ffb70ce6aeff4ccbf8dc19a4",
              "nonce":"0xf",
              "initCode":"0x",
              "callData":"{\"fromAsset\":{\"address\":\"0x6b175474e89094c44da98b954eedeac495271d0f\",\"amount\":{\"value\":\"1000000000000000000\"},\"chainId\":{\"value\":\"1\"}},\"toAsset\":{\"address\":\"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\",\"amount\":{\"value\":\"1000000\"},\"chainId\":{\"value\":\"1\"}}}",
              "callGasLimit":"0xc3500",
              "verificationGasLimit":"0x996a0",
              "preVerificationGas":"0x99000",
              "maxFeePerGas":"0x0",
              "maxPriorityFeePerGas":"0x0",
              "paymasterAndData":"0x",
              "signature":"0x"
            }`,
			wantErr: false,
		},
		{
			name:           "Successful Signing with Proto Intent userOp",
			chainID:        big.NewInt(1),
			entryPointAddr: common.HexToAddress("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"),
			signer:         validPrivateKey(),
			userOp: `{
              "sender":"0xff6f893437e88040ffb70ce6aeff4ccbf8dc19a4",
              "nonce":"0xf",
              "initCode":"0x",
              "callData":"{\"fromAsset\":{\"address\":\"0xdAC17F958D2ee523a2206206994597C13D831ec7\"},\"toAsset\":{\"address\":\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\",\"amount\":{\"value\":\"1000000000000000000\"},\"chainId\":{\"value\":\"1\"}}}",
              "callGasLimit":"0xc3500",
              "verificationGasLimit":"0x996a0",
              "preVerificationGas":"0x99000",
              "maxFeePerGas":"0x0",
              "maxPriorityFeePerGas":"0x0",
              "paymasterAndData":"0x",
              "signature":"0x"
            }`,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				// Parse the userOp JSON string into a map
				var userOpMap map[string]interface{}
				dec := json.NewDecoder(strings.NewReader(tc.userOp))
				dec.UseNumber()
				err := dec.Decode(&userOpMap)
				require.NoError(t, err, "error parsing user operation JSON")

				// Process the callData field using the helper function
				if callData, ok := userOpMap["callData"].(string); ok {
					modifiedCallData, err := processCallData(callData)
					require.NoError(t, err, "error processing callData")
					userOpMap["callData"] = modifiedCallData
				}

				// Marshal the modified userOpMap back to JSON
				modifiedUserOpJSON, err := json.Marshal(userOpMap)
				require.NoError(t, err, "error marshaling modified user operation JSON")

				// Unmarshal into userOp struct
				var userOp model.UserOperation
				err = json.Unmarshal(modifiedUserOpJSON, &userOp)
				require.NoError(t, err)
				hashes := []common.Hash{userOp.GetUserOpHash(tc.entryPointAddr, tc.chainID)}
				userOps := []*model.UserOperation{&userOp}
				err = userop.SignUserOperations(tc.signer, hashes, userOps, false, false)
				if tc.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					valid, err := userop.VerifySignature(tc.signer.PublicKey, userOps, hashes)
					require.NoError(t, err, "error verifying signature for %s", tc.userOp)
					require.True(t, valid, "signature is invalid for %s", tc.userOp)
				}
			},
		)
	}
}

func mustCreateSigner(pk string) *signer.EOA {
	account, err := signer.New(pk)
	if err != nil {
		panic(err)
	}

	return account
}

// validPrivateKey is a valid signer keys.
func validPrivateKey() *signer.EOA {
	privateKey, _ := crypto.GenerateKey()
	publicKey := &privateKey.PublicKey
	return &signer.EOA{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// invalidPrivateKey generates an invalid signer key.
func invalidPrivateKey() *signer.EOA {
	return &signer.EOA{
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(), // Using a curve different from the one expected by Ethereum (secp256k1)
				X:     nil,
				Y:     nil,
			},
			D: big.NewInt(0),
		},
	}
}
