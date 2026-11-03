package node_test

import (
	"context"
	"fmt"
	"github.com/multiversx/mx-chain-go/api/groups"
	"github.com/multiversx/mx-chain-go/api/middleware"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ginFramework "github.com/gin-gonic/gin"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/facade"
	facadeMock "github.com/multiversx/mx-chain-go/facade/mock"
	"github.com/multiversx/mx-chain-go/node"
	nodefactory "github.com/multiversx/mx-chain-go/node/mock/factory"
	"github.com/multiversx/mx-chain-go/state/parsers"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	factoryMock "github.com/multiversx/mx-chain-go/testscommon/factory"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	"github.com/multiversx/mx-chain-go/trie/leavesRetriever"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualG12Account struct {
	stateMock.StateUserAccountHandlerStub
}

func (*qualG12Account) GetLeavesParser() common.TrieLeafParser {
	return parsers.NewMainTrieLeafParser()
}

// Experimental in-memory fixtures; actual local router, facade, Node entrypoint,
// collection and trie producer, with repository/account collaborators only.
func TestQualPartialsG12CancellationAndPagination(t *testing.T) {
	for _, antiflood := range []bool{false, true} {
		for _, pagination := range []bool{false, true} {
			t.Run(fmt.Sprintf("antiflood_%t/pagination_%t", antiflood, pagination), func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				var entered, exited atomic.Int32
				observed := make(chan error, 1)
				var sourceCtx context.Context
				var mu sync.Mutex
				db := map[string][]byte{}
				storage := &storageManager.StorageManagerStub{PutCalled: func(k, v []byte) error {
					mu.Lock()
					defer mu.Unlock()
					db[string(k)] = append([]byte(nil), v...)
					return nil
				}, GetCalled: func(k []byte) ([]byte, error) {
					mu.Lock()
					defer mu.Unlock()
					v, exists := db[string(k)]
					if !exists {
						return nil, fmt.Errorf("experimental missing node")
					}
					return append([]byte(nil), v...), nil
				}}
				storage.EnterPruningBufferingModeCalled = func() {
					entered.Add(1)
					if !pagination {
						cancel()
						observed <- sourceCtx.Err()
					}
				}
				storage.ExitPruningBufferingModeCalled = func() { exited.Add(1) }
				tr, e := trie.NewTrie(storage, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), enableEpochsHandlerMock.NewEnableEpochsHandlerStub(), 10)
				require.NoError(t, e)
				for i := 0; i < 5; i++ {
					require.NoError(t, tr.Update([]byte(fmt.Sprint(i)), []byte("value")))
				}
				require.NoError(t, tr.Commit())
				root, e := tr.RootHash()
				require.NoError(t, e)
				account := &qualG12Account{}
				account.DataTrieCalled = func() common.DataTrieHandler { return tr }
				account.GetRootHashCalled = func() []byte { return root }
				account.GetAllLeavesCalled = func(ch *common.TrieIteratorChannels, ctx context.Context) error {
					sourceCtx = ctx
					return tr.GetAllLeavesOnChannel(ch, ctx, root, keyBuilder.NewKeyBuilder(), parsers.NewMainTrieLeafParser())
				}
				repo := &stateMock.AccountsRepositoryStub{GetAccountWithBlockInfoCalled: func([]byte, api.AccountQueryOptions) (vmcommon.AccountHandler, common.BlockInfo, error) {
					return account, nil, nil
				}}
				n, e := node.NewNode(node.WithCoreComponents(&nodefactory.CoreComponentsMock{AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32)}), node.WithStateComponents(&factoryMock.StateComponentsMock{AccountsRepo: repo, LeavesRetriever: leavesRetriever.NewDisabledLeavesRetriever()}))
				require.NoError(t, e)
				args := struct {
					ApiConfig       config.ApiRoutesConfig
					AntiFloodConfig config.WebServerAntifloodConfig
					TrieOperations  config.TrieOperationsConfig
				}{}
				args.ApiConfig.Logging.LoggingEnabled = false
				args.ApiConfig.APIPackages = map[string]config.APIPackageConfig{"address": {Routes: []config.RouteConfig{{Name: "/:address/keys", Open: true}, {Name: "/iterate-keys", Open: true}}}}
				args.AntiFloodConfig.WebServerAntifloodEnabled = antiflood
				args.AntiFloodConfig.SameSourceRequests = 100
				args.AntiFloodConfig.SimultaneousRequests = 100
				args.AntiFloodConfig.SameSourceResetIntervalInSec = 3600
				args.AntiFloodConfig.TrieOperationsDeadlineMilliseconds = 1000
				args.TrieOperations.HTTPTimeoutMilliseconds = 1000
				var callErr error
				bridge := &facadeMock.NodeStub{GetKeyValuePairsCalled: func(a string, o api.AccountQueryOptions, ctx context.Context) (map[string]string, api.BlockInfo, error) {
					m, b, e := n.GetKeyValuePairs(a, o, ctx)
					callErr = e
					return m, b, e
				}, IterateKeysCalled: func(a string, num uint, st [][]byte, o api.AccountQueryOptions, ctx context.Context) (map[string]string, [][]byte, api.BlockInfo, error) {
					m, s, b, e := n.IterateKeys(a, num, st, o, ctx)
					callErr = e
					return m, s, b, e
				}}
				fac, e := facade.NewNodeFacade(facade.ArgNodeFacade{Node: bridge, ApiResolver: &facadeMock.ApiResolverStub{}, ApiRoutesConfig: args.ApiConfig, WsAntifloodConfig: args.AntiFloodConfig, AccountsStateAPI: &stateMock.AccountsStub{}, Blockchain: &testscommon.ChainHandlerStub{}})
				require.NoError(t, e)
				r := ginFramework.New()
				r.Use(middleware.NewTrieOperationsTransport(args.TrieOperations).MiddlewareHandlerFunc())
				if antiflood {
					source, err := middleware.NewSourceThrottler(args.AntiFloodConfig.SameSourceRequests)
					require.NoError(t, err)
					r.Use(source.MiddlewareHandlerFunc())
					global, err := middleware.NewGlobalThrottler(args.AntiFloodConfig.SimultaneousRequests)
					require.NoError(t, err)
					r.Use(global.MiddlewareHandlerFunc())
				}
				r.Use(middleware.NewTrieOperationsThrottler(args.TrieOperations).MiddlewareHandlerFunc())
				group, err := groups.NewAddressGroup(fac)
				require.NoError(t, err)
				group.RegisterRoutes(r.Group("/address"), args.ApiConfig)
				method, path, body := http.MethodGet, "/address/00/keys", ""
				if pagination {
					method, path, body = http.MethodPost, "/address/iterate-keys", `{"address":"00","numKeys":1}`
				}
				req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(parent)
				w := &qualG12DeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				r.ServeHTTP(w, req)
				if pagination {
					require.ErrorIs(t, callErr, common.ErrTrieLeavesRetrieverDisabled, "real disabled pagination error")
				}
				require.Equal(t, http.StatusInternalServerError, w.Code, "real node entrypoint error HTTP shape")
				require.Contains(t, w.Body.String(), `"code":"internal_issue"`)
				if pagination {
					require.Contains(t, w.Body.String(), common.ErrTrieLeavesRetrieverDisabled.Error())
					require.Zero(t, entered.Load())
				} else {
					require.ErrorIs(t, callErr, node.ErrTrieOperationsTimeout, "actual leaf cancellation error")
					select {
					case e := <-observed:
						require.ErrorIs(t, e, context.Canceled, "actual producer inherits request cancellation")
					default:
						t.Fatal("real leaf producer did not enter")
					}
					require.Equal(t, int32(1), entered.Load())
					require.Equal(t, entered.Load(), exited.Load(), "actual producer releases pruning buffer")
				}
			})
		}
	}
}

type qualG12DeadlineRecorder struct{ *httptest.ResponseRecorder }

func (*qualG12DeadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*qualG12DeadlineRecorder) SetWriteDeadline(time.Time) error { return nil }
