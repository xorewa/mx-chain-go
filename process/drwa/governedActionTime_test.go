package drwa

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGovernedActionWindow_ProjectionExpiry(t *testing.T) {
	p := qualHeaderTimeOwner(t)
	calls := 0
	sentinel := errors.New("native lease lost before expiry derivation")
	context, err := p.BeginBound(&block.MetaBlockV3{Epoch: 10, TimestampMs: 105}, func() (func(), error) {
		calls++
		if calls == 2 {
			return nil, sentinel
		}
		return func() {}, nil
	}, func() error { return nil })
	require.NoError(t, err)
	expiry, err := (&governedActionWindow{100, 105, 120}).projectionExpiry(context, 7)
	require.ErrorIs(t, err, sentinel)
	require.Zero(t, expiry)
	require.Equal(t, 2, calls)
}
