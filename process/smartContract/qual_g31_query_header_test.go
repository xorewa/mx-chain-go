package smartContract

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualG31QueryRootHeaderSelection(t *testing.T) {
	var typedNil *testscommon.HeaderHandlerStub
	for _, tc := range []struct {
		name   string
		header data.HeaderHandler
		v3     bool
	}{
		{"nil", nil, false},
		{"typed nil", typedNil, false},
		{"v1", &testscommon.HeaderHandlerStub{IsHeaderV3Called: func() bool { return false }}, false},
		{"v3", &testscommon.HeaderHandlerStub{IsHeaderV3Called: func() bool { return true }}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current, executed := 0, 0
			service := &SCQueryService{apiBlockChain: &testscommon.ChainHandlerStub{
				GetCurrentBlockRootHashCalled:  func() []byte { current++; return []byte("current") },
				GetLastExecutedBlockInfoCalled: func() (uint64, []byte, []byte) { executed++; return 7, []byte("header"), []byte("executed") },
			}}
			var root []byte
			require.NotPanics(t, func() { root = service.getCurrentBlockRootHash(tc.header) })
			if tc.v3 {
				require.Equal(t, []byte("executed"), root)
				require.Equal(t, 1, executed)
				require.Zero(t, current)
			} else {
				require.Equal(t, []byte("current"), root)
				require.Equal(t, 1, current)
				require.Zero(t, executed)
			}
		})
	}
}
