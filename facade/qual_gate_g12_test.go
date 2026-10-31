package facade

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-go/facade/mock"
	"github.com/stretchr/testify/require"
)

func TestQualGateG12ParentContext(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			args := createMockArguments()
			args.WsAntifloodConfig.WebServerAntifloodEnabled = enabled
			args.WsAntifloodConfig.TrieOperationsDeadlineMilliseconds = 10000
			type requestKey struct{}
			parent, cancel := context.WithCancel(context.WithValue(context.Background(), requestKey{}, "request-marker"))
			defer cancel()
			var observed context.Context
			args.Node = &mock.NodeStub{GetKeyValuePairsCalled: func(address string, _ api.AccountQueryOptions, ctx context.Context) (map[string]string, api.BlockInfo, error) {
				require.Equal(t, "alice", address)
				observed = ctx
				require.Equal(t, "request-marker", ctx.Value(requestKey{}))
				deadline, hasDeadline := ctx.Deadline()
				require.Equal(t, enabled, hasDeadline)
				if enabled {
					require.WithinDuration(t, time.Now().Add(10*time.Second), deadline, time.Second)
				}
				require.NoError(t, ctx.Err())
				return map[string]string{"k": "v"}, api.BlockInfo{}, nil
			}}
			nf, err := NewNodeFacade(args)
			require.NoError(t, err)
			pairs, _, err := nf.GetKeyValuePairs(parent, "alice", api.AccountQueryOptions{})
			require.NoError(t, err)
			require.Equal(t, map[string]string{"k": "v"}, pairs)
			require.NotNil(t, observed)
			require.ErrorIs(t, observed.Err(), context.Canceled, "return cancels child")
			require.NoError(t, parent.Err(), "child cleanup preserves parent")
			cancel()
			args.Node = &mock.NodeStub{GetKeyValuePairsCalled: func(_ string, _ api.AccountQueryOptions, ctx context.Context) (map[string]string, api.BlockInfo, error) {
				require.ErrorIs(t, ctx.Err(), context.Canceled, "incoming cancellation survives derivation")
				return nil, api.BlockInfo{}, ctx.Err()
			}}
			nf, err = NewNodeFacade(args)
			require.NoError(t, err)
			_, _, err = nf.GetKeyValuePairs(parent, "alice", api.AccountQueryOptions{})
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}
