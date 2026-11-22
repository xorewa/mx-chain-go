package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// O7/O8: missing source data differs from a proven missing key. These fixtures
// use the native account/data tries and limited header/proof doubles. They
// supply neither production B admission nor class no-work/funding permission.
func qualReadCanonicalAbsence(f *canonicalTestFixture, key []byte,
	w canonicalResultWitness, limit int) error {
	if reader, present := interface{}(f.reader).(interface {
		readAbsent([]byte, uint32, uint32, []byte, []byte, canonicalResultWitness, int) error
	}); present {
		return reader.readAbsent(f.bHash, f.consumer, f.producer,
			f.items[0].candidate.origin, key, w, limit)
	}
	_, err := f.reader.read(f.bHash, f.consumer, f.producer,
		f.items[0].candidate.origin, key, w, limit)
	if err == nil {
		return ErrInvalidAccountWitness // positive evidence cannot prove absence
	}
	return err
}

func qualCanonicalAbsenceFixture(t *testing.T) (*canonicalTestFixture, []byte) {
	t.Helper()
	f := newCanonicalTestFixture(t, 0, 1)
	key := []byte("qual/missing-origin")
	account, err := f.s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	data := account.(state.UserAccountHandler).DataTrie().(common.Trie)
	value, _, err := data.Get(key)
	require.NoError(t, err)
	require.Nil(t, value, "independent native lookup establishes the fixture's missing key")
	query := data.(interface {
		GetProofForQuery([]byte) ([][]byte, []byte, error)
	})
	proof, value, queryErr := query.GetProofForQuery(key)
	require.Error(t, queryErr, "query retains its native missing-key error")
	require.Nil(t, value)
	require.NotEmpty(t, proof)
	f.w.Account.DataProof = proof
	f.rebudget()
	return f, key
}

func TestQualDRWACanonicalResultAbsence(t *testing.T) {
	t.Run("authenticated missing key", func(t *testing.T) {
		f, key := qualCanonicalAbsenceFixture(t)
		before, err := f.s.RootHash()
		require.NoError(t, err)
		require.NoError(t, qualReadCanonicalAbsence(f, key, f.w, f.limit))
		require.NoError(t, qualReadCanonicalAbsence(f, key, f.w, f.limit))
		after, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, before, after)
	})
	t.Run("positive key is not absence", func(t *testing.T) {
		f := newCanonicalTestFixture(t, 0, 1)
		require.Error(t, qualReadCanonicalAbsence(f, f.originKey, f.w, f.limit))
	})
	t.Run("unavailable remains unavailable then restores", func(t *testing.T) {
		f, key := qualCanonicalAbsenceFixture(t)
		require.NoError(t, qualReadCanonicalAbsence(f, key, f.w, f.limit))
		partial := f.w
		partial.Account.DataProof = nil
		require.Error(t, qualReadCanonicalAbsence(f, key, partial, f.limit),
			"a warmed reader cannot fill a missing witness")
		partial = f.w
		partial.HeaderProof = nil
		require.Error(t, qualReadCanonicalAbsence(f, key, partial, f.limit))
		require.NoError(t, qualReadCanonicalAbsence(f, key, f.w, f.limit))
	})
	t.Run("wrong B origin and budget refuse", func(t *testing.T) {
		f, key := qualCanonicalAbsenceFixture(t)
		b := bytes.Clone(f.bHash)
		f.bHash[0] ^= 1
		require.Error(t, qualReadCanonicalAbsence(f, key, f.w, f.limit))
		f.bHash = b
		wrong := f.w
		wrong.Account.ExecutedHeader = bytes.Clone(wrong.Account.ExecutedHeader)
		wrong.Account.ExecutedHeader[0] ^= 1
		require.Error(t, qualReadCanonicalAbsence(f, key, wrong, f.limit))
		// rebudget includes the independent promotion fixture budget as well.
		readBudget := f.limit - f.budget
		require.NoError(t, qualReadCanonicalAbsence(f, key, f.w, readBudget))
		require.Error(t, qualReadCanonicalAbsence(f, key, f.w, readBudget-1))
	})
}
