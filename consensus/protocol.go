// Quorum
package consensus

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Broadcaster defines the interface to enqueue blocks to fetcher and find peer
type Broadcaster interface {
	// Enqueue add a block into fetcher queue
	Enqueue(id string, block *types.Block)
	// FindPeers retrives peers by addresses
	FindPeers(map[common.Address]bool) map[common.Address]Peer
}

// Peer defines the interface to communicate with peer
type Peer interface {
	// Send sends the message to this peer
	Send(msgcode uint64, data interface{}) error

	// SendConsensus sends the message to this p2p peer using the consensus specific devp2p subprotocol
	SendConsensus(msgcode uint64, data interface{}) error

	// SendQBFTConsensus is used to send consensus subprotocol messages from an "eth" peer without encoding the payload
	SendQBFTConsensus(msgcode uint64, payload []byte) error
}
