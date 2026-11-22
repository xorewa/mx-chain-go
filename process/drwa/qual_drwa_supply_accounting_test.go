package drwa

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// These are synthetic numeric controls, not canonical state/provider admission,
// journal sequencing, native supply/position root or real-network evidence.
func TestQualDRWASupplyAccountingSequence(t *testing.T) {
	zero := newSupplyAccounting()
	issued, err := zero.advance(0, true, big.NewInt(100), big.NewInt(100), 32)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(100), issued.cumulativeIssued)
	require.Equal(t, big.NewInt(100), issued.liveSupply)
	require.Equal(t, uint64(1), issued.nextSupplyNonce)
	require.Zero(t, zero.cumulativeIssued.Sign())
	require.Zero(t, zero.liveSupply.Sign())
	require.Zero(t, zero.nextSupplyNonce)

	burned, err := issued.advance(1, false, big.NewInt(40), big.NewInt(100), 32)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(100), burned.cumulativeIssued)
	require.Equal(t, big.NewInt(60), burned.liveSupply)
	require.Equal(t, uint64(2), burned.nextSupplyNonce)
	refused, err := burned.advance(2, true, big.NewInt(1), big.NewInt(100), 32)
	require.ErrorIs(t, err, errSupplyAccounting)
	require.Nil(t, refused) // Burning never replenishes cumulative issuance cap.
	refused, err = burned.advance(1, false, big.NewInt(1), nil, 32)
	require.ErrorIs(t, err, errSupplyAccounting)
	require.Nil(t, refused)
	refused, err = burned.advance(2, false, big.NewInt(61), nil, 32)
	require.ErrorIs(t, err, errSupplyAccounting)
	require.Nil(t, refused)
	all, err := burned.advance(2, false, big.NewInt(60), nil, 32)
	require.NoError(t, err)
	require.Zero(t, all.liveSupply.Sign())
	require.Equal(t, big.NewInt(100), all.cumulativeIssued)
	require.Equal(t, uint64(3), all.nextSupplyNonce)
	require.Equal(t, big.NewInt(60), burned.liveSupply)
	require.Equal(t, big.NewInt(100), issued.liveSupply)
}

func TestQualDRWASupplyAccountingInvalidStateAndBounds(t *testing.T) {
	for _, name := range []string{"absent", "nil issued", "nil live", "negative issued", "negative live", "live exceeds issued", "nil quantity", "zero quantity", "negative quantity", "negative cap", "nonce exhausted", "zero width", "wide quantity", "wide issued", "wide live", "wide cap", "sum overflow"} {
		t.Run(name, func(t *testing.T) {
			s := &supplyAccounting{big.NewInt(10), big.NewInt(5), 0}
			quantity, cap, width := big.NewInt(1), big.NewInt(100), 1
			switch name {
			case "absent":
				s = nil
			case "nil issued":
				s.cumulativeIssued = nil
			case "nil live":
				s.liveSupply = nil
			case "negative issued":
				s.cumulativeIssued.SetInt64(-1)
			case "negative live":
				s.liveSupply.SetInt64(-1)
			case "live exceeds issued":
				s.liveSupply.SetInt64(11)
			case "nil quantity":
				quantity = nil
			case "zero quantity":
				quantity.SetInt64(0)
			case "negative quantity":
				quantity.SetInt64(-1)
			case "negative cap":
				cap.SetInt64(-1)
			case "nonce exhausted":
				s.nextSupplyNonce = math.MaxUint64
			case "zero width":
				width = 0
			case "wide quantity":
				quantity.SetInt64(256)
			case "wide issued":
				s.cumulativeIssued.SetInt64(256)
			case "wide live":
				s.cumulativeIssued.SetInt64(256)
				s.liveSupply.SetInt64(256)
			case "wide cap":
				cap.SetInt64(256)
			case "sum overflow":
				s.cumulativeIssued.SetInt64(255)
				cap = nil
			}
			nonce := uint64(0)
			if s != nil {
				nonce = s.nextSupplyNonce
			}
			next, err := s.advance(nonce, true, quantity, cap, width)
			require.ErrorIs(t, err, errSupplyAccounting)
			require.Nil(t, next)
		})
	}
}

func TestQualDRWASupplyAccountingArbitraryPrecisionAndDetached(t *testing.T) {
	quantity := new(big.Int).Lsh(big.NewInt(1), 120)
	cap := new(big.Int).Mul(quantity, big.NewInt(2))
	s := newSupplyAccounting()
	next, err := s.advance(0, true, quantity, cap, 32)
	require.NoError(t, err)
	require.Equal(t, quantity, next.cumulativeIssued)
	require.Equal(t, quantity, next.liveSupply)
	quantity.SetInt64(1)
	cap.SetInt64(0)
	require.Equal(t, 121, next.liveSupply.BitLen())
	next.liveSupply.SetInt64(0)
	require.Equal(t, 121, next.cumulativeIssued.BitLen())
	require.Zero(t, s.cumulativeIssued.Sign())
	require.Zero(t, s.liveSupply.Sign())
}
