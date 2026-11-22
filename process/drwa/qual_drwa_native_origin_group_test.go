package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// Existing opaque core candidates and real account/data proofs are reused.
// Header/proof doubles retain their original limits: no native canonical,
// consumer-class or funding authority is supplied by these fixtures.
func TestQualDRWANativeOriginGroup(t *testing.T) {
	inputs := func(t *testing.T) (*qualOriginBodiesFixture, []pendingFinalCandidate, int) {
		f := newQualOriginBodiesFixture(t)
		require.Len(t, f.items, 2)
		var candidates []pendingFinalCandidate
		limit := f.limit
		for _, item := range f.items {
			c := item.candidate
			candidates = append(candidates, pendingFinalCandidate{key: bytes.Clone(c.key), version: c.version,
				predecessor: bytes.Clone(c.predecessor), body: bytes.Clone(c.body), origin: bytes.Clone(c.origin)})
			encoded, err := f.r.encode(c)
			require.NoError(t, err)
			limit += len(encoded)
		}
		return f, candidates, limit
	}
	t.Run("whole-source-group-and-read-replay", func(t *testing.T) {
		f, candidates, limit := inputs(t)
		host := &qualOriginBodiesRefusingHost{}
		f.r.host = host
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit)
		require.NoError(t, err)
		require.Equal(t, candidates, group)
		require.Len(t, body.MiniBlocks, 2)
		require.Len(t, scrs, 4)
		original := bytes.Clone(candidates[0].body)
		group[0].body[0] ^= 0xff
		require.Equal(t, original, candidates[0].body)
		again, _, _, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit)
		require.NoError(t, err)
		require.Equal(t, candidates, again)
		require.Zero(t, host.calls)
	})
	cases := []struct {
		name  string
		alter func([]pendingFinalCandidate) []pendingFinalCandidate
	}{
		{"empty", func(c []pendingFinalCandidate) []pendingFinalCandidate { return nil }},
		{"subset", func(c []pendingFinalCandidate) []pendingFinalCandidate { return c[:1] }},
		{"reordered", func(c []pendingFinalCandidate) []pendingFinalCandidate { return []pendingFinalCandidate{c[1], c[0]} }},
		{"duplicate", func(c []pendingFinalCandidate) []pendingFinalCandidate { return []pendingFinalCandidate{c[0], c[0]} }},
		{"changed-body", func(c []pendingFinalCandidate) []pendingFinalCandidate { c[0].body[0] ^= 0xff; return c }},
		{"changed-origin", func(c []pendingFinalCandidate) []pendingFinalCandidate { c[0].origin[0] ^= 0xff; return c }},
		{"changed-version", func(c []pendingFinalCandidate) []pendingFinalCandidate { c[0].version++; return c }},
		{"malformed", func(c []pendingFinalCandidate) []pendingFinalCandidate { c[0].body = nil; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, candidates, limit := inputs(t)
			origin := bytes.Clone(candidates[0].origin)
			host := &qualOriginBodiesRefusingHost{}
			f.r.host = host
			group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
				origin, f.w, tc.alter(candidates), f.mbs, f.txs, limit)
			require.Error(t, err)
			require.Nil(t, group)
			require.Nil(t, body)
			require.Nil(t, scrs)
			require.Zero(t, host.calls)
		})
	}
	t.Run("extra", func(t *testing.T) {
		f, candidates, limit := inputs(t)
		encoded, err := f.r.encode(candidates[0])
		require.NoError(t, err)
		candidates = append(candidates, candidates[0])
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit+len(encoded))
		require.Error(t, err)
		require.Nil(t, group)
		require.Nil(t, body)
		require.Nil(t, scrs)
	})
	t.Run("missing-tail-restored", func(t *testing.T) {
		f, candidates, limit := inputs(t)
		host := &qualOriginBodiesRefusingHost{}
		f.r.host = host
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs[:len(f.txs)-1], limit)
		require.ErrorIs(t, err, process.ErrMissingTransaction)
		require.Nil(t, group)
		require.Nil(t, body)
		require.Nil(t, scrs)
		group, _, _, err = f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit)
		require.NoError(t, err)
		require.Equal(t, candidates, group)
		require.Zero(t, host.calls)
	})
	t.Run("candidate-budget", func(t *testing.T) {
		f, candidates, _ := inputs(t)
		encoded, err := f.r.encode(candidates[0])
		require.NoError(t, err)
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, len(encoded)-1)
		require.ErrorIs(t, err, ErrInvalidAccountWitness)
		require.Nil(t, group)
		require.Nil(t, body)
		require.Nil(t, scrs)
	})
	t.Run("nil-reader", func(t *testing.T) {
		f, candidates, limit := inputs(t)
		group, body, scrs, err := f.r.nativeOriginSCRGroup(nil, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit)
		require.ErrorIs(t, err, ErrInvalidAccountWitness)
		require.Nil(t, group)
		require.Nil(t, body)
		require.Nil(t, scrs)
	})

	t.Run("no-destination-carrier-retains-class-group", func(t *testing.T) {
		f, candidates, _ := inputs(t)
		require.NoError(t, f.h.ExecutionResults[0].SetMiniBlockHeadersHandlers(nil))
		f.proposalReferences = nil
		f.mbs = nil
		f.txs = nil
		f.seal(t)
		limit := f.limit
		for _, candidate := range candidates {
			encoded, err := f.r.encode(candidate)
			require.NoError(t, err)
			limit += len(encoded)
		}
		host := &qualOriginBodiesRefusingHost{}
		f.r.host = host
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, nil, nil, limit)
		require.NoError(t, err)
		require.Equal(t, candidates, group)
		require.Empty(t, body.MiniBlocks)
		require.Empty(t, scrs)
		require.Zero(t, host.calls)
		// Empty native carriers do not authenticate class no-work or discharge.
	})
	t.Run("oversized-component", func(t *testing.T) {
		for _, field := range []string{"key", "body", "origin", "predecessor"} {
			t.Run(field, func(t *testing.T) {
				f, candidates, limit := inputs(t)
				before, err := f.s.RootHash()
				require.NoError(t, err)
				origin := bytes.Clone(candidates[0].origin)
				oversized := bytes.Repeat([]byte{'x'}, limit+1)
				switch field {
				case "key":
					candidates[0].key = oversized
				case "body":
					candidates[0].body = oversized
				case "origin":
					candidates[0].origin = oversized
				case "predecessor":
					candidates[0].predecessor = oversized
				}
				host := &qualOriginBodiesRefusingHost{}
				f.r.host = host
				group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
					origin, f.w, candidates, f.mbs, f.txs, limit)
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Nil(t, group)
				require.Nil(t, body)
				require.Nil(t, scrs)
				require.Zero(t, host.calls)
				after, err := f.s.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	})

	t.Run("authenticated-malformed-origin-list", func(t *testing.T) {
		f, candidates, _ := inputs(t)
		// Deliberately corrupt the source manifest, then commit native state
		// and build its real account/data proofs. Header admission remains
		// the existing explicitly synthetic fixture, not native authority.
		corrupt := []byte{0xff} // unterminated protobuf varint, not an empty list
		account, err := f.s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		user, ok := account.(state.UserAccountHandler)
		require.True(t, ok)
		require.NoError(t, user.SaveKeyValue(f.originKey, corrupt))
		require.NoError(t, f.s.SaveAccount(user))
		root, err := f.s.Commit()
		require.NoError(t, err)
		f.reopen(t)
		f.h.ExecutionResults[0].BaseExecutionResult.RootHash = bytes.Clone(root)
		f.seal(t)
		witness, err := f.reader.accounts.BuildNativeWitness(f.s, f.hash(f.w.Account.Header), f.producer,
			core.SystemAccountAddress, f.originKey, f.w.Account, f.limit)
		require.NoError(t, err)
		f.w.Account = witness
		f.seal(t)

		value, nativeBody, nativeSCRs, err := f.readBodies()
		require.NoError(t, err)
		require.Equal(t, corrupt, value)
		require.Len(t, nativeBody.MiniBlocks, 2)
		require.Len(t, nativeSCRs, 4)
		limit := f.limit
		for _, candidate := range candidates {
			encoded, encodeErr := f.r.encode(candidate)
			require.NoError(t, encodeErr)
			limit += len(encoded)
		}
		host := &qualOriginBodiesRefusingHost{}
		f.r.host = host
		group, body, scrs, err := f.r.nativeOriginSCRGroup(f.reader, f.bHash, f.consumer, f.producer,
			candidates[0].origin, f.w, candidates, f.mbs, f.txs, limit)
		require.Error(t, err)
		require.Nil(t, group)
		require.Nil(t, body)
		require.Nil(t, scrs)
		require.Zero(t, host.calls)
		after, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
	})

}
