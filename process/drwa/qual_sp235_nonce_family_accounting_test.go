package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

type qualSP235NonceFamily struct {
	name   string
	family core.ESDTType
	unique bool
}

var qualSP235NonceFamilies = []qualSP235NonceFamily{
	{"NFTv2", core.NonFungibleV2, true},
	{"SFT", core.SemiFungible, false},
	{"Meta", core.MetaFungible, false},
	{"DynamicNFT", core.DynamicNFT, true},
	{"DynamicSFT", core.DynamicSFT, false},
	{"DynamicMeta", core.DynamicMeta, false},
}

func TestQualSP235IdentifierScopeAndNonceCoordinates(t *testing.T) {
	for _, family := range qualSP235NonceFamilies {
		t.Run(family.name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			codec := qualRootLeafCodec(t)
			holder := bytes.Repeat([]byte{0x31}, len(core.SystemAccountAddress))
			journal := f.store.JournalLen()
			root, err := f.store.RootHash()
			require.NoError(t, err)
			var firstNonceKey, firstPositionKey []byte
			var firstView *currentLocalView
			for _, nonce := range []uint64{1, 2} {
				nonceKey, err := codec.nonceKey(f.token, family.family, nonce)
				require.NoError(t, err)
				positionKey, err := codec.positionKey(f.token, family.family, nonce, holder)
				require.NoError(t, err)
				decodedNonce, err := codec.decodeNonceKey(nonceKey, f.token, family.family)
				require.NoError(t, err)
				require.Equal(t, nonce, decodedNonce)
				decodedNonce, decodedHolder, err := codec.decodePositionKey(positionKey, f.token, family.family)
				require.NoError(t, err)
				require.Equal(t, nonce, decodedNonce)
				require.Equal(t, holder, decodedHolder)

				// The established fixture reader has only the token-wide policy
				// coordinate. The nonce appears in numeric keys, never its lookup.
				// The fixture body is synthetic, not actual family admission.
				view, err := f.resolve()
				require.NoError(t, err)
				require.Equal(t, f.token, view.token)
				require.Equal(t, uint64(7), view.epoch)
				require.Equal(t, f.pointer, view.pointer)
				require.Equal(t, f.hash, view.hash)
				require.Equal(t, f.body, view.body)
				require.Equal(t, f.host.refs, view.references)
				require.NoError(t, f.r.revalidate(view))
				if firstView == nil {
					firstView, firstNonceKey, firstPositionKey = view, nonceKey, positionKey
				} else {
					require.NotEqual(t, firstNonceKey, nonceKey)
					require.NotEqual(t, firstPositionKey, positionKey)
					require.Equal(t, firstView.keys, view.keys)
					require.Equal(t, firstView.materials, view.materials)
					require.Equal(t, firstView.hash, view.hash)
					require.Equal(t, firstView.references, view.references)
				}
			}
			actualRoot, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, actualRoot)
			require.Equal(t, journal, f.store.JournalLen())
		})
	}
}

func TestQualSP235MultiNonceAccountingComposition(t *testing.T) {
	type step struct {
		fn                   string
		nonce                uint64
		amount               int64
		increase             bool
		issued, live         int64
		leafIssued, leafLive int64
	}
	unique := []step{
		{core.BuiltInFunctionESDTNFTCreate, 1, 1, true, 1, 1, 1, 1},
		{core.BuiltInFunctionESDTNFTCreate, 2, 1, true, 2, 2, 1, 1},
		{core.BuiltInFunctionESDTNFTBurn, 1, 1, false, 2, 1, 1, 0},
	}
	quantity := []step{
		{core.BuiltInFunctionESDTNFTCreate, 1, 5, true, 5, 5, 5, 5},
		{core.BuiltInFunctionESDTNFTCreate, 2, 3, true, 8, 8, 3, 3},
		{core.BuiltInFunctionESDTNFTAddQuantity, 1, 2, true, 10, 10, 7, 7},
		{core.BuiltInFunctionESDTNFTBurn, 2, 2, false, 10, 8, 3, 1},
		{core.BuiltInFunctionESDTNFTBurn, 2, 1, false, 10, 7, 3, 0},
	}
	for _, family := range qualSP235NonceFamilies {
		t.Run(family.name, func(t *testing.T) {
			steps := quantity
			if family.unique {
				steps = unique
			}
			codec := qualRootLeafCodec(t)
			account := newSupplyAccounting()
			leaves := map[uint64]nonceSupply{}
			for n, s := range steps {
				prior, present := leaves[s.nonce]
				var predecessor *nonceSupply
				if present {
					predecessor = &prior
				}
				var otherKey uint64 = 1
				if s.nonce == 1 {
					otherKey = 2
				}
				other, hadOther := leaves[otherKey]
				var otherIssued, otherLive *big.Int
				if hadOther {
					otherIssued = new(big.Int).Set(other.issued)
					otherLive = new(big.Int).Set(other.live)
				}
				beforeIssued := new(big.Int).Set(account.cumulativeIssued)
				beforeLive := new(big.Int).Set(account.liveSupply)
				amount := big.NewInt(s.amount)
				// These are independent numeric projections, not executed native
				// create, add, transfer or burn operations. The fixture enumerates
				// only two known leaves, not a proposed global hot-path scan.
				next, err := account.advance(uint64(n), s.increase, amount, nil, 32)
				require.NoError(t, err)
				leaf, err := codec.nonceSupplyAfter(family.family, s.fn, predecessor, amount, nil)
				require.NoError(t, err)
				require.Equal(t, s.leafIssued, leaf.issued.Int64())
				require.Equal(t, s.leafLive, leaf.live.Int64())
				raw, err := codec.nonceValue(family.family, leaf)
				require.NoError(t, err)
				decoded, err := codec.decodeNonceValue(family.family, raw)
				require.NoError(t, err)
				require.Zero(t, leaf.issued.Cmp(decoded.issued))
				require.Zero(t, leaf.live.Cmp(decoded.live))
				canonical, err := codec.nonceValue(family.family, decoded)
				require.NoError(t, err)
				require.Equal(t, raw, canonical, "canonical representation survives the roundtrip")
				leaves[s.nonce] = decoded
				if hadOther {
					require.Zero(t, otherIssued.Cmp(leaves[otherKey].issued))
					require.Zero(t, otherLive.Cmp(leaves[otherKey].live))
				}
				issuedSum, liveSum := new(big.Int), new(big.Int)
				for _, value := range leaves {
					issuedSum.Add(issuedSum, value.issued)
					liveSum.Add(liveSum, value.live)
				}
				require.Equal(t, s.issued, issuedSum.Int64())
				require.Equal(t, s.live, liveSum.Int64())
				require.Zero(t, issuedSum.Cmp(next.cumulativeIssued))
				require.Zero(t, liveSum.Cmp(next.liveSupply))
				require.Equal(t, uint64(n+1), next.nextSupplyNonce)
				require.Zero(t, beforeIssued.Cmp(account.cumulativeIssued))
				require.Zero(t, beforeLive.Cmp(account.liveSupply))
				require.Equal(t, s.amount, amount.Int64())
				account = next
			}
			require.Len(t, leaves, 2)
		})
	}
}
