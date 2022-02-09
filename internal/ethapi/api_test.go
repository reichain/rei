package ethapi

import (
	"context"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/stretchr/testify/assert"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/mps"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/multitenancy"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/private"
	"github.com/ethereum/go-ethereum/private/engine"
	"github.com/ethereum/go-ethereum/private/engine/notinuse"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	arbitraryCtx          = context.Background()
	arbitraryPrivateFrom  = "arbitrary private from"
	arbitraryPrivateFor   = []string{"arbitrary party 1", "arbitrary party 2"}
	arbitraryMandatoryFor = []string{"arbitrary party 2"}
	privateTxArgs         = &PrivateTxArgs{
		PrivateFrom: arbitraryPrivateFrom,
		PrivateFor:  arbitraryPrivateFor,
	}
	arbitraryFrom         = common.BytesToAddress([]byte("arbitrary address"))
	arbitraryTo           = common.BytesToAddress([]byte("arbitrary address to"))
	arbitraryGas          = uint64(200000)
	arbitraryZeroGasPrice = big.NewInt(0)
	arbitraryZeroValue    = big.NewInt(0)
	arbitraryEmptyData    = new([]byte)
	arbitraryAccessList   = types.AccessList{}
	callTxArgs            = CallArgs{
		From:       &arbitraryFrom,
		To:         &arbitraryTo,
		Gas:        (*hexutil.Uint64)(&arbitraryGas),
		GasPrice:   (*hexutil.Big)(arbitraryZeroGasPrice),
		Value:      (*hexutil.Big)(arbitraryZeroValue),
		Data:       (*hexutil.Bytes)(arbitraryEmptyData),
		AccessList: &arbitraryAccessList,
	}

	arbitrarySimpleStorageContractEncryptedPayloadHash       = common.BytesToEncryptedPayloadHash([]byte("arbitrary payload hash"))
	arbitraryMandatoryRecipientsContractEncryptedPayloadHash = common.BytesToEncryptedPayloadHash([]byte("arbitrary payload hash of tx with mr"))

	simpleStorageContractCreationTx = types.NewContractCreation(
		0,
		big.NewInt(0),
		hexutil.MustDecodeUint64("0x47b760"),
		big.NewInt(0),
		hexutil.MustDecode("0x6060604052341561000f57600080fd5b604051602080610149833981016040528080519060200190919050505b806000819055505b505b610104806100456000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632a1afcd914605157806360fe47b11460775780636d4ce63c146097575b600080fd5b3415605b57600080fd5b606160bd565b6040518082815260200191505060405180910390f35b3415608157600080fd5b6095600480803590602001909190505060c3565b005b341560a157600080fd5b60a760ce565b6040518082815260200191505060405180910390f35b60005481565b806000819055505b50565b6000805490505b905600a165627a7a72305820d5851baab720bba574474de3d09dbeaabc674a15f4dd93b974908476542c23f00029"))

	rawSimpleStorageContractCreationTx = types.NewContractCreation(
		0,
		big.NewInt(0),
		hexutil.MustDecodeUint64("0x47b760"),
		big.NewInt(0),
		arbitrarySimpleStorageContractEncryptedPayloadHash.Bytes())

	arbitrarySimpleStorageContractAddress                    common.Address
	arbitraryStandardPrivateSimpleStorageContractAddress     common.Address
	arbitraryMandatoryRecipientsSimpleStorageContractAddress common.Address

	simpleStorageContractMessageCallTx                   *types.Transaction
	standardPrivateSimpleStorageContractMessageCallTx    *types.Transaction
	rawStandardPrivateSimpleStorageContractMessageCallTx *types.Transaction

	arbitraryCurrentBlockNumber = big.NewInt(1)

	publicStateDB  *state.StateDB
	privateStateDB *state.StateDB

	workdir string
)

func TestMain(m *testing.M) {
	setup()
	retCode := m.Run()
	teardown()
	os.Exit(retCode)
}

func setup() {
	log.Root().SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(true)))
	var err error

	memdb := rawdb.NewMemoryDatabase()
	db := state.NewDatabase(memdb)

	publicStateDB, err = state.New(common.Hash{}, db, nil)
	if err != nil {
		panic(err)
	}
	privateStateDB, err = state.New(common.Hash{}, db, nil)
	if err != nil {
		panic(err)
	}

	private.P = &StubPrivateTransactionManager{}

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)

	arbitrarySimpleStorageContractAddress = crypto.CreateAddress(from, 0)

	simpleStorageContractMessageCallTx = types.NewTransaction(
		0,
		arbitrarySimpleStorageContractAddress,
		big.NewInt(0),
		hexutil.MustDecodeUint64("0x47b760"),
		big.NewInt(0),
		hexutil.MustDecode("0x60fe47b1000000000000000000000000000000000000000000000000000000000000000d"))

	arbitraryStandardPrivateSimpleStorageContractAddress = crypto.CreateAddress(from, 1)

	standardPrivateSimpleStorageContractMessageCallTx = types.NewTransaction(
		0,
		arbitraryStandardPrivateSimpleStorageContractAddress,
		big.NewInt(0),
		hexutil.MustDecodeUint64("0x47b760"),
		big.NewInt(0),
		hexutil.MustDecode("0x60fe47b1000000000000000000000000000000000000000000000000000000000000000e"))

	rawStandardPrivateSimpleStorageContractMessageCallTx = types.NewTransaction(
		0,
		arbitraryStandardPrivateSimpleStorageContractAddress,
		big.NewInt(0),
		hexutil.MustDecodeUint64("0x47b760"),
		big.NewInt(0),
		arbitrarySimpleStorageContractEncryptedPayloadHash.Bytes())

	workdir, err = ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
}

func teardown() {
	log.Root().SetHandler(log.DiscardHandler())
	os.RemoveAll(workdir)
}

func TestDoEstimateGas_whenNoValueTx_Pre_Istanbul(t *testing.T) {
	assert := assert.New(t)

	estimation, err := DoEstimateGas(arbitraryCtx, &StubBackend{CurrentHeadNumber: big.NewInt(10)}, callTxArgs, rpc.BlockNumberOrHashWithNumber(10), math.MaxInt64)

	assert.NoError(err, "gas estimation")
	assert.Equal(hexutil.Uint64(25352), estimation, "estimation for a public or private tx")
}

func TestDoEstimateGas_whenNoValueTx_Istanbul(t *testing.T) {
	assert := assert.New(t)

	estimation, err := DoEstimateGas(arbitraryCtx, &StubBackend{IstanbulBlock: big.NewInt(0), CurrentHeadNumber: big.NewInt(10)}, callTxArgs, rpc.BlockNumberOrHashWithNumber(10), math.MaxInt64)

	assert.NoError(err, "gas estimation")
	assert.Equal(hexutil.Uint64(22024), estimation, "estimation for a public or private tx")
}

func createKeystore(t *testing.T) (*keystore.KeyStore, accounts.Account, accounts.Account) {
	assert := assert.New(t)

	keystore := keystore.NewKeyStore(filepath.Join(workdir, "keystore"), keystore.StandardScryptN, keystore.StandardScryptP)
	fromAcct, err := keystore.NewAccount("")
	assert.NoError(err)
	toAcct, err := keystore.NewAccount("")
	assert.NoError(err)

	return keystore, fromAcct, toAcct
}

type StubBackend struct {
	getEVMCalled                    bool
	sendTxCalled                    bool
	txThatWasSent                   *types.Transaction
	mockAccountExtraDataStateGetter *vm.MockAccountExtraDataStateGetter
	multitenancySupported           bool
	accountManager                  *accounts.Manager
	ks                              *keystore.KeyStore
	poolNonce                       uint64
	allowUnprotectedTxs             bool

	IstanbulBlock     *big.Int
	CurrentHeadNumber *big.Int
}

func (sb *StubBackend) UnprotectedAllowed() bool {
	return sb.allowUnprotectedTxs
}

func (sb *StubBackend) CurrentHeader() *types.Header {
	return &types.Header{Number: sb.CurrentHeadNumber}
}

func (sb *StubBackend) Engine() consensus.Engine {
	panic("implement me")
}

func (sb *StubBackend) IsAuthorized(authToken *proto.PreAuthenticatedAuthenticationToken, attributes ...*multitenancy.PrivateStateSecurityAttribute) (bool, error) {
	panic("implement me")
}

func (sb *StubBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	sb.getEVMCalled = true
	vmCtx := core.NewEVMBlockContext(&types.Header{
		Coinbase:   arbitraryFrom,
		Number:     arbitraryCurrentBlockNumber,
		Time:       0,
		Difficulty: big.NewInt(0),
		GasLimit:   0,
	}, nil, &arbitraryFrom)
	txCtx := core.NewEVMTxContext(msg)
	vmError := func() error {
		return nil
	}
	config := params.QuorumTestChainConfig
	config.IstanbulBlock = sb.IstanbulBlock
	return vm.NewEVM(vmCtx, txCtx, publicStateDB, config, vm.Config{}), vmError, nil
}

func (sb *StubBackend) CurrentBlock() *types.Block {
	return types.NewBlock(&types.Header{
		Number: arbitraryCurrentBlockNumber,
	}, nil, nil, nil, new(trie.Trie))
}

func (sb *StubBackend) Downloader() *downloader.Downloader {
	panic("implement me")
}

func (sb *StubBackend) ProtocolVersion() int {
	panic("implement me")
}

func (sb *StubBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(0), nil
}

func (sb *StubBackend) ChainDb() ethdb.Database {
	panic("implement me")
}

func (sb *StubBackend) EventMux() *event.TypeMux {
	panic("implement me")
}

func (sb *StubBackend) Wallets() []accounts.Wallet {
	return sb.ks.Wallets()
}

func (sb *StubBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return nil
}

func (sb *StubBackend) AccountManager() *accounts.Manager {
	return sb.accountManager
}

func (sb *StubBackend) ExtRPCEnabled() bool {
	panic("implement me")
}

func (sb *StubBackend) CallTimeOut() time.Duration {
	panic("implement me")
}

func (sb *StubBackend) RPCTxFeeCap() float64 {
	return 25000000
}

func (sb *StubBackend) RPCGasCap() uint64 {
	return 25000000
}

func (sb *StubBackend) SetHead(number uint64) {
	panic("implement me")
}

func (sb *StubBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	panic("implement me")
}

func (sb *StubBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	panic("implement me")
}

func (sb *StubBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	panic("implement me")
}

func (sb *StubBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	panic("implement me")
}

func (sb *StubBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	panic("implement me")
}

func (sb *StubBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return sb.CurrentBlock(), nil
}

func (sb *StubBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return &StubMinimalApiState{}, nil, nil
}

func (sb *StubBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return &StubMinimalApiState{}, nil, nil
}

func (sb *StubBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	panic("implement me")
}

func (sb *StubBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	panic("implement me")
}

func (sb *StubBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	sb.sendTxCalled = true
	sb.txThatWasSent = signedTx
	return nil
}

func (sb *StubBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	panic("implement me")
}

func (sb *StubBackend) GetPoolTransactions() (types.Transactions, error) {
	panic("implement me")
}

func (sb *StubBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	panic("implement me")
}

func (sb *StubBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return sb.poolNonce, nil
}

func (sb *StubBackend) Stats() (pending int, queued int) {
	panic("implement me")
}

func (sb *StubBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	panic("implement me")
}

func (sb *StubBackend) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) BloomStatus() (uint64, uint64) {
	panic("implement me")
}

func (sb *StubBackend) GetLogs(ctx context.Context, blockHash common.Hash) ([][]*types.Log, error) {
	panic("implement me")
}

func (sb *StubBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	panic("implement me")
}

func (sb *StubBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) ChainConfig() *params.ChainConfig {
	return params.QuorumTestChainConfig
}

func (sb *StubBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) PSMR() mps.PrivateStateMetadataResolver {
	panic("implement me")
}

type MPSStubBackend struct {
	StubBackend
	psmr mps.PrivateStateMetadataResolver
}

func (msb *MPSStubBackend) ChainConfig() *params.ChainConfig {
	return params.QuorumMPSTestChainConfig
}

func (sb *MPSStubBackend) PSMR() mps.PrivateStateMetadataResolver {
	return sb.psmr
}

type StubMinimalApiState struct {
}

func (StubMinimalApiState) GetBalance(addr common.Address) *big.Int {
	panic("implement me")
}

func (StubMinimalApiState) SetBalance(addr common.Address, balance *big.Int) {
	panic("implement me")
}

func (StubMinimalApiState) GetCode(addr common.Address) []byte {
	return nil
}

func (StubMinimalApiState) GetState(a common.Address, b common.Hash) common.Hash {
	panic("implement me")
}

func (StubMinimalApiState) GetNonce(addr common.Address) uint64 {
	panic("implement me")
}

func (StubMinimalApiState) SetNonce(addr common.Address, nonce uint64) {
	panic("implement me")
}

func (StubMinimalApiState) SetCode(common.Address, []byte) {
	panic("implement me")
}

func (StubMinimalApiState) GetPrivacyMetadata(addr common.Address) (*state.PrivacyMetadata, error) {
	if addr == arbitraryMandatoryRecipientsSimpleStorageContractAddress {
		return &state.PrivacyMetadata{
			CreationTxHash: arbitraryMandatoryRecipientsContractEncryptedPayloadHash,
			PrivacyFlag:    2,
		}, nil
	}
	return &state.PrivacyMetadata{
		CreationTxHash: arbitrarySimpleStorageContractEncryptedPayloadHash,
		PrivacyFlag:    1,
	}, nil
}

func (StubMinimalApiState) GetManagedParties(addr common.Address) ([]string, error) {
	panic("implement me")
}

func (StubMinimalApiState) GetRLPEncodedStateObject(addr common.Address) ([]byte, error) {
	panic("implement me")
}

func (StubMinimalApiState) GetProof(common.Address) ([][]byte, error) {
	panic("implement me")
}

func (StubMinimalApiState) GetStorageProof(common.Address, common.Hash) ([][]byte, error) {
	panic("implement me")
}

func (StubMinimalApiState) StorageTrie(addr common.Address) state.Trie {
	panic("implement me")
}

func (StubMinimalApiState) Error() error {
	panic("implement me")
}

func (StubMinimalApiState) GetCodeHash(common.Address) common.Hash {
	panic("implement me")
}

func (StubMinimalApiState) SetState(common.Address, common.Hash, common.Hash) {
	panic("implement me")
}

func (StubMinimalApiState) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	panic("implement me")
}

type StubPrivateTransactionManager struct {
	notinuse.PrivateTransactionManager
	creation bool
}

func (sptm *StubPrivateTransactionManager) Send(data []byte, from string, to []string, extra *engine.ExtraMetadata) (string, []string, common.EncryptedPayloadHash, error) {
	return "", nil, arbitrarySimpleStorageContractEncryptedPayloadHash, nil
}

func (sptm *StubPrivateTransactionManager) EncryptPayload(data []byte, from string, to []string, extra *engine.ExtraMetadata) ([]byte, error) {
	return nil, engine.ErrPrivateTxManagerNotSupported
}

func (sptm *StubPrivateTransactionManager) DecryptPayload(payload common.DecryptRequest) ([]byte, *engine.ExtraMetadata, error) {
	return nil, nil, engine.ErrPrivateTxManagerNotSupported
}

func (sptm *StubPrivateTransactionManager) StoreRaw(data []byte, from string) (common.EncryptedPayloadHash, error) {
	return arbitrarySimpleStorageContractEncryptedPayloadHash, nil
}

func (sptm *StubPrivateTransactionManager) SendSignedTx(data common.EncryptedPayloadHash, to []string, extra *engine.ExtraMetadata) (string, []string, []byte, error) {
	return "", nil, arbitrarySimpleStorageContractEncryptedPayloadHash.Bytes(), nil
}

func (sptm *StubPrivateTransactionManager) ReceiveRaw(data common.EncryptedPayloadHash) ([]byte, string, *engine.ExtraMetadata, error) {
	if sptm.creation {
		return hexutil.MustDecode("0x6060604052341561000f57600080fd5b604051602080610149833981016040528080519060200190919050505b806000819055505b505b610104806100456000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632a1afcd914605157806360fe47b11460775780636d4ce63c146097575b600080fd5b3415605b57600080fd5b606160bd565b6040518082815260200191505060405180910390f35b3415608157600080fd5b6095600480803590602001909190505060c3565b005b341560a157600080fd5b60a760ce565b6040518082815260200191505060405180910390f35b60005481565b806000819055505b50565b6000805490505b905600a165627a7a72305820d5851baab720bba574474de3d09dbeaabc674a15f4dd93b974908476542c23f00029"), "", nil, nil
	} else {
		return hexutil.MustDecode("0x60fe47b1000000000000000000000000000000000000000000000000000000000000000e"), "", nil, nil
	}
}

func (sptm *StubPrivateTransactionManager) HasFeature(f engine.PrivateTransactionManagerFeature) bool {
	return true
}
