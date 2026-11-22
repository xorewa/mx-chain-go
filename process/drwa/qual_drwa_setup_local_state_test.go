package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Actual native current/journal/storage are used; local canonical application,
// root grammar and complete CEB interpretation remain synthetic providers.
type qualLocalSetupHost struct {
	t                 *testing.T
	f                 *qualLifecycleFixture
	supply, positions []byte
	calls             int
	err               error
	hook              func()
}

func (h *qualLocalSetupHost) IsInterfaceNil() bool { return h == nil }
func (h *qualLocalSetupHost) VerifyLocalSetupState(context *HeaderTimeContext, view lifecycleReadView, supply, positions []byte) error {
	h.calls++
	require.Same(h.t, h.f.context, context)
	require.Equal(h.t, []byte("TOKEN-abcdef"), view.token)
	require.Equal(h.t, h.f.hash, view.cebHash)
	require.Equal(h.t, h.supply, supply)
	require.Equal(h.t, h.positions, positions)
	view.token[0] ^= 1
	view.cebHash[0] ^= 1
	if len(supply) > 0 {
		supply[0] ^= 1
	}
	if len(positions) > 0 {
		positions[0] ^= 1
	}
	if h.hook != nil {
		h.hook()
	}
	return h.err
}

func qualLocalSetupNew(t *testing.T, family uint32, preserve, origin bool) (*qualLifecycleFixture, *setupLocalStateReader, *qualLocalSetupHost) {
	t.Helper()
	f, s, _ := qualSetupNew(t, family, preserve, origin)
	require.NoError(t, qualSetupExecute(f, s))
	h := &qualLocalSetupHost{t: t, f: f}
	if origin {
		h.supply = qualRecordFrame(qualLocalSupplyFields(f)...)
	}
	if preserve {
		h.positions = qualRecordFrame(qualLocalPositionFields(f)...)
	}
	r, err := newSetupLocalStateReader(f.r, h, 32)
	require.NoError(t, err)
	return f, r, h
}
func qualLocalSupplyFields(f *qualLifecycleFixture) [][]byte {
	var root []byte
	if f.h.fields.tokenType != uint32(core.Fungible) {
		root = qualSetupRoot()
	}
	return [][]byte{{0, 0, 0, 1}, []byte("TOKEN-abcdef"), binary.BigEndian.AppendUint32(nil, f.h.fields.tokenType), bytes.Clone(f.h.fields.supplyOrigin), binary.BigEndian.AppendUint32(nil, f.h.fields.supplyOriginShard), nil, nil, root, make([]byte, 8)}
}
func qualLocalPositionFields(f *qualLifecycleFixture) [][]byte {
	return [][]byte{{0, 0, 0, 1}, []byte("TOKEN-abcdef"), binary.BigEndian.AppendUint32(nil, f.h.fields.tokenType), {1}, qualSetupRoot(), nil, make([]byte, 8)}
}
func qualLocalSetupRead(f *qualLifecycleFixture, r *setupLocalStateReader, execute func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error)) error {
	return f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return r.withInitializedState(f.context, []byte("TOKEN-abcdef"), 1, f.hash, execute)
	})
}

func TestQualDRWASetupLocalStateRejectsExperimentalTuples(t *testing.T) {
	for _, supply := range []bool{true, false} {
		t.Run(fmt.Sprintf("supply-%t", supply), func(t *testing.T) {
			f, r, h := qualLocalSetupNew(t, uint32(core.Fungible), true, true)
			supplyKey, positionKey := qualSetupKeys()
			if supply {
				h.supply = qualRecordFrame([]byte("TOKEN-abcdef"), f.h.fields.supplyOrigin,
					binary.BigEndian.AppendUint32(nil, f.h.fields.supplyOriginShard), nil, nil, nil, make([]byte, 8))
				qualRecordPut(t, f.x.f.store, supplyKey, h.supply)
			} else {
				legacyRoot := blake2b.NewBlake2b().Compute(fmt.Sprintf("SYNTHETIC empty root/%d/%t", core.Fungible, true))
				h.positions = qualRecordFrame([]byte("TOKEN-abcdef"), []byte{1}, legacyRoot, nil, make([]byte, 8))
				qualRecordPut(t, f.x.f.store, positionKey, h.positions)
			}
			calls := 0
			err := qualLocalSetupRead(f, r, func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) {
				calls++
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
			require.ErrorIs(t, err, errSetupLocalState)
			require.Zero(t, h.calls)
			require.Zero(t, calls)
		})
	}
}

func TestQualDRWASetupLocalStateExactFamiliesPlansAndLoci(t *testing.T) {
	for _, family := range []core.ESDTType{core.Fungible, core.NonFungibleV2, core.SemiFungible, core.MetaFungible, core.DynamicNFT, core.DynamicSFT, core.DynamicMeta} {
		for _, preserve := range []bool{false, true} {
			for _, origin := range []bool{false, true} {
				t.Run(fmt.Sprintf("family%d/preserve%t/origin%t", family, preserve, origin), func(t *testing.T) {
					f, r, h := qualLocalSetupNew(t, uint32(family), preserve, origin)
					calls := 0
					journal := f.x.f.store.JournalLen()
					require.NoError(t, qualLocalSetupRead(f, r, func(view lifecycleReadView, local localSetupState) (*vmcommon.VMOutput, error) {
						calls++
						require.Equal(t, "SETUP", view.lifecycle)
						if origin {
							require.NotNil(t, local.supply)
							require.Equal(t, f.h.fields.supplyOrigin, local.supply.origin)
							require.Equal(t, f.h.fields.supplyOriginShard, local.supply.originShard)
							require.Zero(t, local.supply.accounting.cumulativeIssued.Sign())
							require.Zero(t, local.supply.accounting.liveSupply.Sign())
							require.Zero(t, local.supply.accounting.nextSupplyNonce)
							require.Equal(t, f.r.current.codec.hasher.Compute(string(h.supply)), local.supplyHash)
							require.Equal(t, h.supply, local.supplyRaw)
							local.supply.origin[0] ^= 1
							local.supply.accounting.liveSupply.SetUint64(100)
							local.supplyHash[0] ^= 1
							local.supplyRaw[0] ^= 1
						} else {
							require.Nil(t, local.supply)
							require.Empty(t, local.supplyHash)
							require.Empty(t, local.supplyRaw)
						}
						if preserve {
							require.NotNil(t, local.positions)
							require.Zero(t, local.positions.quantity.Sign())
							require.Zero(t, local.positions.version)
							require.Equal(t, qualSetupRoot(), local.positions.root)
							require.Equal(t, f.r.current.codec.hasher.Compute(string(h.positions)), local.positionHash)
							require.Equal(t, h.positions, local.positionRaw)
							local.positions.root[0] ^= 1
							local.positions.quantity.SetUint64(100)
							local.positionHash[0] ^= 1
							local.positionRaw[0] ^= 1
						} else {
							require.Nil(t, local.positions)
							require.Empty(t, local.positionHash)
							require.Empty(t, local.positionRaw)
						}
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
					}))
					require.Equal(t, 1, calls)
					require.Equal(t, 1, h.calls)
					require.Equal(t, journal, f.x.f.store.JournalLen())
					if origin {
						sk, _ := qualSetupKeys()
						require.Equal(t, h.supply, qualActivationValue(t, f.x.f.store, sk))
					}
					if preserve {
						_, pk := qualSetupKeys()
						require.Equal(t, h.positions, qualActivationValue(t, f.x.f.store, pk))
					}
				})
			}
		}
	}
}

func TestQualDRWASetupLocalStateRefusesUnexpectedRecords(t *testing.T) {
	for _, scenario := range []struct {
		name             string
		preserve, origin bool
	}{
		{"supply-outside-origin", true, false},
		{"positions-under-burn-plan", false, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, r, h := qualLocalSetupNew(t, uint32(core.Fungible), scenario.preserve, scenario.origin)
			consume := func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) {
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}
			require.NoError(t, qualLocalSetupRead(f, r, consume), "the lawful native layout remains readable")
			supplyKey, positionKey := qualSetupKeys()
			key, raw := supplyKey, qualRecordFrame(qualLocalSupplyFields(f)...)
			if !scenario.preserve {
				key, raw = positionKey, qualRecordFrame(qualLocalPositionFields(f)...)
			}
			qualRecordPut(t, f.x.f.store, key, raw)
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			journal, outputs := f.x.f.store.JournalLen(), len(f.x.f.boundary.outputs)
			calls := 0
			err = qualLocalSetupRead(f, r, func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) {
				calls++
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
			require.ErrorIs(t, err, errSetupLocalState)
			require.Equal(t, 1, h.calls, "no second local-readiness verification")
			require.Zero(t, calls)
			after, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
			require.Len(t, f.x.f.boundary.outputs, outputs)
			require.Equal(t, raw, qualActivationValue(t, f.x.f.store, key), "the reader does not remove unexpected state")
		})
	}
}

func TestQualDRWASetupLocalStateNonzeroIsUnitsAndContinuousState(t *testing.T) {
	f, r, h := qualLocalSetupNew(t, uint32(core.SemiFungible), true, true)
	s, p := qualLocalSupplyFields(f), qualLocalPositionFields(f)
	s[5], s[6], s[7], s[8] = []byte{20}, []byte{12}, bytes.Repeat([]byte{8}, 32), binary.BigEndian.AppendUint64(nil, 9)
	p[4], p[5], p[6] = bytes.Repeat([]byte{4}, 32), []byte{12}, binary.BigEndian.AppendUint64(nil, 3)
	h.supply, h.positions = qualRecordFrame(s...), qualRecordFrame(p...)
	sk, pk := qualSetupKeys()
	qualRecordPut(t, f.x.f.store, sk, h.supply)
	qualRecordPut(t, f.x.f.store, pk, h.positions)
	require.NoError(t, qualLocalSetupRead(f, r, func(_ lifecycleReadView, v localSetupState) (*vmcommon.VMOutput, error) {
		require.Equal(t, uint64(20), v.supply.accounting.cumulativeIssued.Uint64())
		require.Equal(t, uint64(12), v.supply.accounting.liveSupply.Uint64())
		require.Equal(t, uint64(9), v.supply.accounting.nextSupplyNonce)
		require.Equal(t, uint64(12), v.positions.quantity.Uint64())
		require.Equal(t, uint64(3), v.positions.version)
		next, err := v.positions.quantityAfter(true, big.NewInt(5), f.r.current.codec.maxBytes)
		require.NoError(t, err)
		require.Zero(t, next.Cmp(big.NewInt(17)))
		require.Equal(t, uint64(12), v.positions.quantity.Uint64())
		require.Equal(t, uint64(3), v.positions.version)

		// The owner may write its separately admitted record; reading is not a
		// universal read-only transaction. This fixture grants no holder authority.
		qualRecordPut(t, f.x.f.store, []byte("fixture/local-pending-decision"), []byte{1})
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}))
	require.Equal(t, 1, h.calls)
	require.Equal(t, h.supply, qualActivationValue(t, f.x.f.store, sk))
	require.Equal(t, h.positions, qualActivationValue(t, f.x.f.store, pk))
}

func TestQualDRWASetupLocalStateMissingMalformedAndNoImplicitZero(t *testing.T) {
	for _, mode := range []string{"missing supply", "missing positions", "wrong token", "wrong origin", "wrong shard", "shard width", "supply nonce width", "issued leading zero", "live exceeds issued", "missing nonce root", "fungible root", "uninitialized positions", "position token", "missing position root", "position quantity zero prefix", "position version width"} {
		t.Run(mode, func(t *testing.T) {
			family := uint32(core.SemiFungible)
			if mode == "fungible root" {
				family = uint32(core.Fungible)
			}
			f, r, h := qualLocalSetupNew(t, family, true, true)
			s, p := qualLocalSupplyFields(f), qualLocalPositionFields(f)
			sk, pk := qualSetupKeys()
			switch mode {
			case "wrong token":
				s[1] = []byte("OTHER-abcdef")
			case "wrong origin":
				s[3] = bytes.Repeat([]byte{3}, 32)
			case "wrong shard":
				s[4] = binary.BigEndian.AppendUint32(nil, (f.h.fields.supplyOriginShard+1)%3)
			case "shard width":
				s[4] = []byte{1}
			case "supply nonce width":
				s[8] = []byte{1}
			case "issued leading zero":
				s[5] = []byte{0, 1}
			case "live exceeds issued":
				s[6] = []byte{1}
			case "missing nonce root":
				s[7] = nil
			case "fungible root":
				s[7] = bytes.Repeat([]byte{1}, 32)
			case "uninitialized positions":
				p[3] = nil
			case "position token":
				p[1] = []byte("OTHER-abcdef")
			case "missing position root":
				p[4] = nil
			case "position quantity zero prefix":
				p[5] = []byte{0}
			case "position version width":
				p[6] = []byte{1}
			}
			sraw, praw := qualRecordFrame(s...), qualRecordFrame(p...)
			if mode == "missing supply" {
				sraw = nil
			}
			if mode == "missing positions" {
				praw = nil
			}
			qualRecordPut(t, f.x.f.store, sk, sraw)
			qualRecordPut(t, f.x.f.store, pk, praw)
			journal := f.x.f.store.JournalLen()
			calls := 0
			err := qualLocalSetupRead(f, r, func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) { calls++; return nil, nil })
			if mode == "missing supply" || mode == "missing positions" {
				require.ErrorIs(t, err, errCurrentLocalDependency)
			} else {
				require.ErrorIs(t, err, errSetupLocalState)
			}
			require.Zero(t, calls)
			require.Zero(t, h.calls)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWASetupLocalStateCanonicalProofAndOriginalOwner(t *testing.T) {
	for _, mutation := range []bool{false, true} {
		t.Run(fmt.Sprint(mutation), func(t *testing.T) {
			f, r, h := qualLocalSetupNew(t, uint32(core.Fungible), true, true)
			sentinel := errors.New("local canonical initialization unavailable")
			if mutation {
				h.hook = func() { qualRecordPut(t, f.x.f.store, []byte("fixture/local-proof-alias"), []byte{1}) }
			} else {
				h.err = sentinel
			}
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			calls := 0
			err = qualLocalSetupRead(f, r, func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) { calls++; return nil, nil })
			if mutation {
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
			} else {
				require.ErrorIs(t, err, sentinel)
			}
			require.Equal(t, 1, h.calls)
			require.Zero(t, calls)
			after, e := f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
		})
	}
	f, r, h := qualLocalSetupNew(t, uint32(core.Fungible), false, true)
	out, err := r.withInitializedState(f.context, []byte("TOKEN-abcdef"), 1, f.hash, func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) { return nil, nil })
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, out)
	require.Zero(t, h.calls)
	_, err = newSetupLocalStateReader(nil, h, 32)
	require.ErrorIs(t, err, errSetupLocalState)
	_, err = newSetupLocalStateReader(f.r, nil, 32)
	require.ErrorIs(t, err, errSetupLocalState)
	meta := qualLifecycleNew(t)
	_, err = newSetupLocalStateReader(meta.r, h, 32)
	require.ErrorIs(t, err, errSetupLocalState)
}

// Numeric component only: roots/versions are preserved inputs, not generated
// successors. Actual native parsed effects and same-journal root/quantity writes
// retain their distinct grammar/owner/input admission and integration gates.
func TestQualDRWASetupPositionQuantitySuccessor(t *testing.T) {
	integer := func(s string) *big.Int {
		if s == "nil" {
			return nil
		}
		v, ok := new(big.Int).SetString(s, 10)
		require.True(t, ok)
		return v
	}
	for _, tc := range []struct {
		name, prior, quantity, expected string
		credit                          bool
		max                             int
		denied                          bool
	}{
		{"credit units", "12", "5", "17", true, 32, false},
		{"debit units", "12", "5", "7", false, 32, false},
		{"full debit", "12", "12", "0", false, 32, false},
		{"empty initialized credit", "0", "5", "5", true, 32, false},
		{"zero delta", "12", "0", "12", false, 32, false},
		{"above uint64", "1000000000000000000000000000000", "7", "1000000000000000000000000000007", true, 32, false},
		{"exact width", "254", "1", "255", true, 1, false},
		{"result overflow", "255", "1", "", true, 1, true},
		{"underflow", "4", "5", "", false, 32, true},
		{"absent quantity", "nil", "5", "", true, 32, true},
		{"negative prior", "-1", "5", "", true, 32, true},
		{"prior width", "256", "1", "", false, 1, true},
		{"nil delta", "12", "nil", "", true, 32, true},
		{"negative delta", "12", "-1", "", false, 32, true},
		{"delta width", "12", "256", "", true, 1, true},
		{"absent limit", "12", "1", "", true, 0, true},
		{"negative limit", "12", "1", "", true, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior, quantity := integer(tc.prior), integer(tc.quantity)
			p := &initializedPositionState{root: []byte{3, 4}, quantity: prior, version: ^uint64(0)}
			next, err := p.quantityAfter(tc.credit, quantity, tc.max)
			if tc.denied {
				require.ErrorIs(t, err, errSetupLocalState)
				require.Nil(t, next)
			} else {
				require.NoError(t, err)
				require.Zero(t, next.Cmp(integer(tc.expected)))
				next.SetInt64(999)
			}
			require.Equal(t, []byte{3, 4}, p.root)
			require.Equal(t, ^uint64(0), p.version)
			if prior != nil {
				require.Zero(t, prior.Cmp(integer(tc.prior)))
			}
			if quantity != nil {
				require.Zero(t, quantity.Cmp(integer(tc.quantity)))
			}
		})
	}
	var absent *initializedPositionState
	next, err := absent.quantityAfter(true, big.NewInt(1), 32)
	require.ErrorIs(t, err, errSetupLocalState)
	require.Nil(t, next)
}
