package mps

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// chainReader contains methods to access local blockchain
type chainReader interface {
	consensus.ChainReader
	CurrentBlock() *types.Block
	GetReceiptsByHash(hash common.Hash) types.Receipts
}

// UpgradeDB performs the following database operations to enable MPS support
// 1. Construct and persist Empty Private State with empty accounts
// 2. Construct and persist trie of root hashes of existing private states
// 3. Update new mapping: block header root -> trie of private states root
// 4. Once upgrade is complete update the ChainConfig.isMPS to true
func UpgradeDB(db ethdb.Database, chain chainReader) error {
	currentBlockNumber := uint64(chain.CurrentBlock().Number().Int64())
	genesisHeader := chain.GetHeaderByNumber(0)

	privateStatesTrieRoot := rawdb.GetPrivateStatesTrieRoot(db, genesisHeader.Root)
	mpsRepo, err := NewMultiplePrivateStateRepository(db, state.NewDatabase(db), privateStatesTrieRoot)
	if err != nil {
		return err
	}
	// pre-populate with dummy one as the state root is derived from block root hash
	privateState := &managedState{}
	mpsRepo.managedStates[types.DefaultPrivateStateIdentifier] = privateState
	for idx := uint64(1); idx <= currentBlockNumber; idx++ {
		header := chain.GetHeaderByNumber(idx)
		// TODO consider periodic reports instead of logging about each block
		fmt.Printf("Processing block %v with hash %v\n", idx, header.Hash().Hex())
		block := chain.GetBlock(header.Hash(), header.Number.Uint64())
		// update trie of private state roots and new mapping with block root hash
		privateState.stateRootProviderFunc = func(_ bool) (common.Hash, error) {
			return rawdb.GetPrivateStateRoot(db, header.Root), nil
		}
		err = mpsRepo.CommitAndWrite(chain.Config().IsEIP158(block.Number()), block)
		if err != nil {
			return err
		}
	}
	// update isMPS in the chain config
	config := chain.Config()
	config.IsMPS = true
	rawdb.WriteChainConfig(db, rawdb.ReadCanonicalHash(db, 0), config)
	fmt.Printf("MPS DB upgrade finished successfully.\n")
	return nil
}
