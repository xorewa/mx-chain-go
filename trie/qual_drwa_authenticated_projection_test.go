package trie_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE W04 feasibility, Part A 5.1, AM-014 and AR-01.
// Reuse the native trie; do not invent a Merkle scheme or negative-proof codec.
// A COMPLETE cold snapshot is rebuilt and compared with an independently
// supplied root. Only then can local absence mean non-membership AT THAT ROOT.
// The authenticated/fresh metachain anchor and transport are NOT implemented.
// Full reconstruction is a cold-start experiment, not a per-block/per-call scan.
// Keys/values and work limits below are synthetic fixtures, not DRWA formats.
type qualProjectionRow struct{ key, value []byte }
type qualAuthenticatedProjection struct {
	trie common.Trie
	root []byte
}

var errQualProjectionBinding = errors.New("non-normative projection binding unavailable")

func qualProjectionFromRows(t *testing.T, anchor []byte, rows []qualProjectionRow, workLimit int) (*qualAuthenticatedProjection, error) {
	t.Helper()
	if len(anchor) == 0 || len(rows) > workLimit || workLimit < 0 {
		return nil, errQualProjectionBinding
	}
	tr := emptyTrie()
	t.Cleanup(func() { require.NoError(t, tr.Close()) })
	seen := make(map[string]bool)
	for _, row := range rows {
		if len(row.key) == 0 || !bytes.Equal(row.value, []byte{1}) || seen[string(row.key)] {
			return nil, errQualProjectionBinding
		}
		seen[string(row.key)] = true
		if err := tr.Update(row.key, row.value); err != nil {
			return nil, err
		}
	}
	root, err := tr.RootHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(anchor, root) {
		return nil, errQualProjectionBinding
	}
	return &qualAuthenticatedProjection{trie: tr, root: append([]byte(nil), root...)}, nil
}

func (p *qualAuthenticatedProjection) member(requiredRoot, key []byte) (bool, error) {
	if p == nil || !bytes.Equal(p.root, requiredRoot) {
		return false, errQualProjectionBinding
	}
	value, _, err := p.trie.Get(key)
	if err != nil {
		return false, err
	}
	return bytes.Equal(value, []byte{1}), nil
}

func TestQualDRWACompleteProjectionAuthentication(t *testing.T) {
	origin := emptyTrie()
	t.Cleanup(func() { require.NoError(t, origin.Close()) })
	// Expected membership is declared independently of the reconstruction helper.
	require.NoError(t, origin.Update([]byte("regulated-A"), []byte{1}))
	require.NoError(t, origin.Update([]byte("regulated-B"), []byte{1}))
	anchor, err := origin.RootHash()
	require.NoError(t, err)
	rows := []qualProjectionRow{{[]byte("regulated-A"), []byte{1}}, {[]byte("regulated-B"), []byte{1}}}
	p, err := qualProjectionFromRows(t, anchor, rows, 2)
	require.NoError(t, err)
	for _, tc := range []struct {
		key  string
		want bool
	}{{"regulated-A", true}, {"regulated-B", true}, {"ordinary-C", false}} {
		got, lookupErr := p.member(anchor, []byte(tc.key))
		require.NoError(t, lookupErr)
		require.Equal(t, tc.want, got)
	}
	for _, tc := range []struct {
		name  string
		rows  []qualProjectionRow
		limit int
	}{
		{"omitted_member", rows[:1], 2},
		{"injected_member", append(append([]qualProjectionRow(nil), rows...), qualProjectionRow{[]byte("ordinary-C"), []byte{1}}), 3},
		{"duplicate", []qualProjectionRow{rows[0], rows[0]}, 2},
		{"altered_marker", []qualProjectionRow{{[]byte("regulated-A"), []byte{0}}, rows[1]}, 2},
		{"work_exhaustion", rows, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, installErr := qualProjectionFromRows(t, anchor, tc.rows, tc.limit)
			require.ErrorIs(t, installErr, errQualProjectionBinding)
			require.Nil(t, bad, "no partially validated projection may be published")
		})
	}
	t.Run("stale_anchor", func(t *testing.T) {
		require.NoError(t, origin.Update([]byte("ordinary-C"), []byte{1}))
		next, rootErr := origin.RootHash()
		require.NoError(t, rootErr)
		_, lookupErr := p.member(next, []byte("ordinary-C"))
		require.ErrorIs(t, lookupErr, errQualProjectionBinding, "stale absence must not become ordinary")
	})
}

func TestQualDRWAProjectionNativeProofBoundary(t *testing.T) {
	tr := emptyTrie()
	t.Cleanup(func() { require.NoError(t, tr.Close()) })
	require.NoError(t, tr.Update([]byte("regulated-A"), []byte{1}))
	root, err := tr.RootHash()
	require.NoError(t, err)
	proof, value, err := tr.GetProof([]byte("regulated-A"))
	require.NoError(t, err)
	require.Equal(t, []byte{1}, value)
	ok, err := tr.VerifyProof(root, []byte("regulated-A"), proof)
	require.NoError(t, err)
	require.True(t, ok)
	// The response value is a separate object, not an argument to VerifyProof.
	value = append([]byte(nil), value...)
	value[0] = 0
	ok, err = tr.VerifyProof(root, []byte("regulated-A"), proof)
	require.NoError(t, err)
	require.True(t, ok, "a separately supplied value cannot be trusted from this boolean")
	_, _, err = tr.GetProof([]byte("ordinary-B"))
	require.Error(t, err, "this missing-key path does not produce a non-membership witness")
	ok, err = tr.VerifyProof(root, []byte("ordinary-B"), proof)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestQualDRWAProjectionColdWorkMeasurements(t *testing.T) {
	// Finite experiment points, not proposed production limits or admission policy.
	for _, count := range []int{0, 1, 8, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			origin := emptyTrie()
			t.Cleanup(func() { require.NoError(t, origin.Close()) })
			rows := make([]qualProjectionRow, count)
			bytesIn := 0
			for i := range rows {
				rows[i] = qualProjectionRow{[]byte(fmt.Sprintf("synthetic-%04d", i)), []byte{1}}
				bytesIn += len(rows[i].key) + len(rows[i].value)
				require.NoError(t, origin.Update(rows[i].key, rows[i].value))
			}
			root, err := origin.RootHash()
			require.NoError(t, err)
			p, err := qualProjectionFromRows(t, root, rows, count)
			require.NoError(t, err)
			member, err := p.member(root, []byte("not-in-snapshot"))
			require.NoError(t, err)
			require.False(t, member)
			t.Logf("fixture_entries=%d input_bytes=%d root_bytes=%d native_updates=%d", count, bytesIn, len(root), count)
		})
	}
}
