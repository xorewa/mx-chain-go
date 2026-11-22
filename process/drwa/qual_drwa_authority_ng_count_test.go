package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Qualification-only review candidate. Do not execute before independent
// admission. The accepted fixture/codec/parameters remain byte-identical.
// The original count_mismatch witness also lacked quorum, masking the count
// guard. These cases keep two valid, ordered in-roster indices and independently
// vary the proof count. No authority, codec, key, threshold or parameter changes.
func TestQualDRWAAuthorityNGSyntheticCountIsolation(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*testing.T, *w03SyntheticNGFixture, *w03SyntheticNGProofs)
	}{
		{"extra_valid_proof", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.possession = append(p.possession, w03NGSign(t, f.memberPrivate[2], f.context, "W03/SYNTHETIC_SUCCESSOR_SET_PROOF/v1"))
		}},
		{"extra_invalid_proof", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			proof := w03NGSign(t, f.memberPrivate[2], f.context, "W03/SYNTHETIC_SUCCESSOR_SET_PROOF/v1")
			proof[0] ^= 1
			p.possession = append(p.possession, proof)
		}},
		{"missing_proof", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.possession = p.possession[:1]
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := w03NewNGFixture(t)
			p := f.proofs(t, f.context, []uint64{0, 1})
			row.change(t, f, &p)
			require.Equal(t, []uint64{0, 1}, p.indices)
			require.NotEqual(t, len(p.indices), len(p.possession))
			require.Error(t, f.stage(7, p))
			require.False(t, f.staged)
		})
	}
}
