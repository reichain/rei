// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package graphql

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/stretchr/testify/assert"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/mps"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/multitenancy"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/private/engine"
	"github.com/ethereum/go-ethereum/private/engine/notinuse"
	"github.com/ethereum/go-ethereum/rpc"
)

func TestBuildSchema(t *testing.T) {
	ddir, err := ioutil.TempDir("", "graphql-buildschema")
	if err != nil {
		t.Fatalf("failed to create temporary datadir: %v", err)
	}
	// Copy config
	conf := node.DefaultConfig
	conf.DataDir = ddir
	stack, err := node.New(&conf)
	if err != nil {
		t.Fatalf("could not create new node: %v", err)
	}
	// Make sure the schema can be parsed and matched up to the object model.
	if err := newHandler(stack, nil, []string{}, []string{}); err != nil {
		t.Errorf("Could not construct GraphQL handler: %v", err)
	}
}

// Tests that a graphQL request is successfully handled when graphql is enabled on the specified endpoint
func TestGraphQLBlockSerialization(t *testing.T) {
	stack := createNode(t, true)
	defer stack.Close()
	// start node
	if err := stack.Start(); err != nil {
		t.Fatalf("could not start node: %v", err)
	}

	for i, tt := range []struct {
		body string
		want string
		code int
	}{
		{ // Should return latest block
			body: `{"query": "{block{number}}","variables": null}`,
			want: `{"data":{"block":{"number":10}}}`,
			code: 200,
		},
		{ // Should return info about latest block
			body: `{"query": "{block{number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":{"number":10,"gasUsed":0,"gasLimit":11500000}}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:0){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":{"number":0,"gasUsed":0,"gasLimit":11500000}}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:-1){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":null}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:-500){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":null}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:\"0\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":{"number":0,"gasUsed":0,"gasLimit":11500000}}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:\"-33\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":null}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:\"1337\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"data":{"block":null}}`,
			code: 200,
		},
		{
			body: `{"query": "{block(number:\"0xbad\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"errors":[{"message":"strconv.ParseInt: parsing \"0xbad\": invalid syntax"}],"data":{}}`,
			code: 400,
		},
		{ // hex strings are currently not supported. If that's added to the spec, this test will need to change
			body: `{"query": "{block(number:\"0x0\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"errors":[{"message":"strconv.ParseInt: parsing \"0x0\": invalid syntax"}],"data":{}}`,
			code: 400,
		},
		{
			body: `{"query": "{block(number:\"a\"){number,gasUsed,gasLimit}}","variables": null}`,
			want: `{"errors":[{"message":"strconv.ParseInt: parsing \"a\": invalid syntax"}],"data":{}}`,
			code: 400,
		},
		{
			body: `{"query": "{bleh{number}}","variables": null}"`,
			want: `{"errors":[{"message":"Cannot query field \"bleh\" on type \"Query\".","locations":[{"line":1,"column":2}]}]}`,
			code: 400,
		},
		// should return `estimateGas` as decimal
		{
			body: `{"query": "{block{ estimateGas(data:{}) }}"}`,
			want: `{"data":{"block":{"estimateGas":53000}}}`,
			code: 200,
		},
		// should return `status` as decimal
		{
			body: `{"query": "{block {number call (data : {from : \"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\", to: \"0x6295ee1b4f6dd65047762f924ecd367c17eabf8f\", data :\"0x12a7b914\"}){data status}}}"}`,
			want: `{"data":{"block":{"number":10,"call":{"data":"0x","status":1}}}}`,
			code: 200,
		},
	} {
		resp, err := http.Post(fmt.Sprintf("%s/graphql", stack.HTTPEndpoint()), "application/json", strings.NewReader(tt.body))
		if err != nil {
			t.Fatalf("could not post: %v", err)
		}
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("could not read from response body: %v", err)
		}
		if have := string(bodyBytes); have != tt.want {
			t.Errorf("testcase %d %s,\nhave:\n%v\nwant:\n%v", i, tt.body, have, tt.want)
		}
		if tt.code != resp.StatusCode {
			t.Errorf("testcase %d %s,\nwrong statuscode, have: %v, want: %v", i, tt.body, resp.StatusCode, tt.code)
		}
	}
}

// Tests that a graphQL request is not handled successfully when graphql is not enabled on the specified endpoint
func TestGraphQLHTTPOnSamePort_GQLRequest_Unsuccessful(t *testing.T) {
	stack := createNode(t, false)
	defer stack.Close()
	if err := stack.Start(); err != nil {
		t.Fatalf("could not start node: %v", err)
	}
	body := strings.NewReader(`{"query": "{block{number}}","variables": null}`)
	resp, err := http.Post(fmt.Sprintf("%s/graphql", stack.HTTPEndpoint()), "application/json", body)
	if err != nil {
		t.Fatalf("could not post: %v", err)
	}
	// make sure the request is not handled successfully
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Tests that 400 is returned when an invalid RPC request is made.
func TestGraphQL_BadRequest(t *testing.T) {
	stack := createNode(t, true)
	defer stack.Close()
	// start node
	if err := stack.Start(); err != nil {
		t.Fatalf("could not start node: %v", err)
	}
	// create http request
	body := strings.NewReader("{\"query\": \"{bleh{number}}\",\"variables\": null}")
	gqlReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/graphql", stack.HTTPEndpoint()), body)
	if err != nil {
		t.Error("could not issue new http request ", err)
	}
	gqlReq.Header.Set("Content-Type", "application/json")
	// read from response
	resp := doHTTPRequest(t, gqlReq)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read from response body: %v", err)
	}
	expected := "{\"errors\":[{\"message\":\"Cannot query field \\\"bleh\\\" on type \\\"Query\\\".\",\"locations\":[{\"line\":1,\"column\":2}]}]}"
	assert.Equal(t, expected, string(bodyBytes))
	assert.Equal(t, 400, resp.StatusCode)
}

func createNode(t *testing.T, gqlEnabled bool) *node.Node {
	stack, err := node.New(&node.Config{
		HTTPHost: "127.0.0.1",
		HTTPPort: 0,
		WSHost:   "127.0.0.1",
		WSPort:   0,
	})
	if err != nil {
		t.Fatalf("could not create node: %v", err)
	}
	if !gqlEnabled {
		return stack
	}
	createGQLService(t, stack)
	return stack
}

func createGQLService(t *testing.T, stack *node.Node) {
	// create backend
	ethConf := &ethconfig.Config{
		Genesis: &core.Genesis{
			Config:     params.AllEthashProtocolChanges,
			GasLimit:   11500000,
			Difficulty: big.NewInt(1048576),
		},
		Ethash: ethash.Config{
			PowMode: ethash.ModeFake,
		},
		NetworkId:               1337,
		TrieCleanCache:          5,
		TrieCleanCacheJournal:   "triecache",
		TrieCleanCacheRejournal: 60 * time.Minute,
		TrieDirtyCache:          5,
		TrieTimeout:             60 * time.Minute,
		SnapshotCache:           5,
	}
	ethBackend, err := eth.New(stack, ethConf)
	if err != nil {
		t.Fatalf("could not create eth backend: %v", err)
	}
	// Create some blocks and import them
	chain, _ := core.GenerateChain(params.AllEthashProtocolChanges, ethBackend.BlockChain().Genesis(),
		ethash.NewFaker(), ethBackend.ChainDb(), 10, func(i int, gen *core.BlockGen) {})
	_, err = ethBackend.BlockChain().InsertChain(chain)
	if err != nil {
		t.Fatalf("could not create import blocks: %v", err)
	}
	// create gql service
	err = New(stack, ethBackend.APIBackend, []string{}, []string{})
	if err != nil {
		t.Fatalf("could not create graphql service: %v", err)
	}
}

func doHTTPRequest(t *testing.T, req *http.Request) *http.Response {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("could not issue a GET request to the given endpoint", err)

	}
	return resp
}

func TestQuorumTransaction_getReceipt_defaultReceiptGetter(t *testing.T) {
	graphqlTx := &Transaction{tx: &types.Transaction{}, backend: &StubBackend{}}

	if graphqlTx.receiptGetter != nil {
		t.Fatalf("Expect nil receiptGetter: actual %v", graphqlTx.receiptGetter)
	}

	_, _ = graphqlTx.getReceipt(context.Background())

	if graphqlTx.receiptGetter == nil {
		t.Fatalf("Expect default receiptGetter to have been set: actual nil")
	}

	if _, ok := graphqlTx.receiptGetter.(*transactionReceiptGetter); !ok {
		t.Fatalf("Expect default receiptGetter to be of type *graphql.transactionReceiptGetter: actual %T", graphqlTx.receiptGetter)
	}
}

type ptmResponse struct {
	body []byte
	err  error
}

type stubPrivateTransactionManager struct {
	notinuse.PrivateTransactionManager
	responses map[common.EncryptedPayloadHash]ptmResponse
}

func (spm *stubPrivateTransactionManager) HasFeature(f engine.PrivateTransactionManagerFeature) bool {
	return true
}

func (spm *stubPrivateTransactionManager) Receive(txHash common.EncryptedPayloadHash) (string, []string, []byte, *engine.ExtraMetadata, error) {
	res, ok := spm.responses[txHash]
	if !ok {
		return "", nil, nil, nil, nil
	}
	if res.err != nil {
		return "", nil, nil, nil, res.err
	}
	meta := &engine.ExtraMetadata{PrivacyFlag: engine.PrivacyFlagStandardPrivate}
	return "", nil, res.body, meta, nil
}

func (spm *stubPrivateTransactionManager) ReceiveRaw(hash common.EncryptedPayloadHash) ([]byte, string, *engine.ExtraMetadata, error) {
	_, sender, data, metadata, err := spm.Receive(hash)
	return data, sender[0], metadata, err
}

type StubBackend struct{}

func (sb *StubBackend) CurrentHeader() *types.Header {
	panic("implement me")
}

func (sb *StubBackend) Engine() consensus.Engine {
	panic("implement me")
}

func (sb *StubBackend) IsAuthorized(authToken *proto.PreAuthenticatedAuthenticationToken, attributes ...*multitenancy.PrivateStateSecurityAttribute) (bool, error) {
	panic("implement me")
}

func (sb *StubBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	panic("implement me")
}

func (sb *StubBackend) CurrentBlock() *types.Block {
	panic("implement me")
}

func (sb *StubBackend) Downloader() *downloader.Downloader {
	panic("implement me")
}

func (sb *StubBackend) ProtocolVersion() int {
	panic("implement me")
}

func (sb *StubBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	panic("implement me")
}

func (sb *StubBackend) ChainDb() ethdb.Database {
	panic("implement me")
}

func (sb *StubBackend) EventMux() *event.TypeMux {
	panic("implement me")
}

func (sb *StubBackend) AccountManager() *accounts.Manager {
	panic("implement me")
}

func (sb *StubBackend) ExtRPCEnabled() bool {
	panic("implement me")
}

func (sb *StubBackend) CallTimeOut() time.Duration {
	panic("implement me")
}

func (sb *StubBackend) RPCTxFeeCap() float64 {
	panic("implement me")
}

func (sb *StubBackend) RPCGasCap() uint64 {
	panic("implement me")
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
	panic("implement me")
}

func (sb *StubBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	panic("implement me")
}

func (sb *StubBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	panic("implement me")
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
	panic("implement me")
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
	panic("implement me")
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
	panic("implement me")
}

func (sb *StubBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (sb *StubBackend) PSMR() mps.PrivateStateMetadataResolver {
	return &StubPSMR{}
}

func (sb *StubBackend) UnprotectedAllowed() bool {
	panic("implement me")
}

type StubPSMR struct {
}

func (psmr *StubPSMR) ResolveForManagedParty(managedParty string) (*mps.PrivateStateMetadata, error) {
	panic("implement me")
}
func (psmr *StubPSMR) ResolveForUserContext(ctx context.Context) (*mps.PrivateStateMetadata, error) {
	return mps.DefaultPrivateStateMetadata, nil
}
func (psmr *StubPSMR) PSIs() []types.PrivateStateIdentifier {
	panic("implement me")
}
func (psmr *StubPSMR) NotIncludeAny(psm *mps.PrivateStateMetadata, managedParties ...string) bool {
	return false
}
