package ethclient

import (
	"context"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client wraps the Ethereum client.
type Client struct {
	nodeURL   string
	EthClient *ethclient.Client
}

// NewClient creates a new Ethereum client.
func NewClient(nodeURL string) *Client {
	client, err := ethclient.Dial(nodeURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	return &Client{nodeURL: nodeURL, EthClient: client}
}

// GetNonce returns the next on-chain nonce.
func (c *Client) GetNonce(address common.Address) (*big.Int, error) {
	// Get the Keccak-256 hash of the function signature "getNonce()"
	funcSigBytes := crypto.Keccak256([]byte("getNonce()"))
	// Use only the first 4 bytes
	funcSig := funcSigBytes[:4]
	// Create a new RPC client (for low-level calls)
	rpcClient, err := rpc.Dial(c.nodeURL)
	if err != nil {
		log.Fatalf("Failed to create RPC client: %v", err)
	}
	var result string
	err = rpcClient.CallContext(context.Background(), &result, "eth_call", map[string]interface{}{
		"to":   address.String(),
		"data": "0x" + common.Bytes2Hex(funcSig),
	}, "latest")
	if err != nil {
		log.Fatalf("Failed to call contract: %v", err)
	}
	nonce := new(big.Int)
	nonce.SetString(result[2:], 16)
	return nonce, nil
}
