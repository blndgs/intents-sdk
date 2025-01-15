package config

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/blndgs/intents-cli/pkg/ethclient"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/viper"
	"github.com/stackup-wallet/stackup-bundler/pkg/signer"
)

type GasParams struct {
	BaseFee  *big.Int
	Tip      *big.Int
	GasPrice *big.Int
}

type ChainNode struct {
	Node      *ethclient.Client
	RPCClient *rpc.Client
	ChainID   *big.Int
	URLStr    string
}

type Config struct {
	NodesMap            NodesMap
	BundlerURL          string
	EntryPointAddr      common.Address
	KernelFactoryAddr   common.Address
	KernelValidatorAddr common.Address
	KernelExecutorAddr  common.Address
	Signer              *signer.EOA
}

type NodesMap map[string]ChainNode // moniker -> chainID -> node

const ethNodeUrlPrefix = "eth_node_url_"

// DefaultRPCURLKey Any RPC URL with 'default' in each key is considered as
// the default RPC URL, e.g. ETH_NODE_URL_BSC DEFAULT
const DefaultRPCURLKey = "default"

// ReadConf reads configuration from a .env file and initializes
// necessary variables like node URLs, signer, bundler URL, and entry point address.
// It returns these values and logs configuration details.
func ReadConf(quiet bool) (*Config, error) {
	const signerPrvKey = "SIGNER_PRIVATE_KEY"
	const bundlerUrl = "BUNDLER_URL"
	const epAddr = "ENTRYPOINT_ADDR"

	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return nil, NewError("fatal error config file", err)
	}

	foundDefaultRPCURL := false
	nodeURLs := make(NodesMap)
	for _, key := range viper.AllKeys() {
		// viper.AllKeys() returns all keys in lowercase
		if strings.HasPrefix(key, ethNodeUrlPrefix) {
			if strings.Contains(key, DefaultRPCURLKey) {
				if foundDefaultRPCURL {
					return nil, NewError("multiple default RPC URLs found: Add only one environment variable with 'default' in the key, e.g. ETH_NODE_URL_DEFAULT", nil)
				}
				foundDefaultRPCURL = true
				// save the default RPC URL with 'default' as the key
				var err error
				nodeURLs[DefaultRPCURLKey], err = initNode(key)
				if err != nil {
					return nil, NewError("failed to initialize default node", err)
				}
				continue
			}
			moniker := strings.TrimPrefix(key, ethNodeUrlPrefix)
			var err error
			nodeURLs[moniker], err = initNode(key)
			if err != nil {
				return nil, NewError("failed to initialize node", err)
			}
		}
	}

	if !foundDefaultRPCURL {
		return nil, NewError("no default RPC URL found: Add an environment variable with 'default' in the key, e.g. ETH_NODE_URL_DEFAULT", nil)
	}

	prvKeyHex := viper.GetString(signerPrvKey)
	s, err := signer.New(prvKeyHex)
	if err != nil {
		return nil, NewError("fatal signer error", err)
	}
	bundlerURL := viper.GetString(bundlerUrl)
	entryPointAddr := common.HexToAddress(viper.GetString(epAddr))

	if !quiet {
		fmt.Printf("Signer private key: %s\n", hexutil.Encode(crypto.FromECDSA(s.PrivateKey)))
		fmt.Printf("Public key: %s\n", hexutil.Encode(crypto.FromECDSAPub(s.PublicKey))[4:])
		fmt.Printf("Address: %s\n", s.Address)
		fmt.Printf("Entrypoint Address: %s\n", entryPointAddr)
		for moniker := range nodeURLs {
			fmt.Printf("Node moniker: %s url: %s\n", moniker, nodeURLs[moniker].URLStr)
		}
	}

	return &Config{
		NodesMap:            nodeURLs,
		BundlerURL:          bundlerURL,
		EntryPointAddr:      entryPointAddr,
		KernelFactoryAddr:   kernelFactoryAddr,
		KernelValidatorAddr: kernelValidatorAddr,
		KernelExecutorAddr:  kernelExecutorAddr,
		Signer:              s,
	}, nil
}

func initNode(key string) (ChainNode, error) {
	urlString := viper.GetString(key)
	node := ethclient.NewClient(urlString)
	chainID, err := node.EthClient.ChainID(context.Background())
	if err != nil {
		return ChainNode{}, NewError("failed getting chain ID", err)
	}

	rpcClient, err := rpc.Dial(urlString)
	if err != nil {
		return ChainNode{}, NewError("failed dialing the RPC client", err)
	}

	return ChainNode{URLStr: urlString, RPCClient: rpcClient, Node: node, ChainID: chainID}, nil
}
