package drwa

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"testing"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/stretchr/testify/require"
)

// Signature-only qualification candidate under ledger L37's new-file boundary.
// Expectations use Part A L1172-1189, the independently accepted W03 model 02
// (2d27162b...) and ledger L37's invalid-extra-signature rule. Experimental bounds
// are declared in W03_authority_signature_experiment_02.json. Claude's parameter
// review (33d477cf...) admits behavior after these SE-01 stronger-threshold rows.
// No scope/resource-admission or production-profile claim follows.
func TestQualDRWAAuthorityThreshold(t *testing.T) {
	for _, row := range []struct{ n, minimum uint64 }{
		{5, 3}, {6, 4}, {7, 5}, {8, 5}, {9, 6}, {10, 6},
	} {
		minimum, err := minimumProgrammeAuthorityThreshold(row.n)
		require.NoError(t, err)
		require.Equal(t, row.minimum, minimum)
		require.Error(t, validateProgrammeAuthorityThreshold(row.n, row.minimum-1))
		for threshold := row.minimum; threshold <= row.n; threshold++ {
			require.NoError(t, validateProgrammeAuthorityThreshold(row.n, threshold))
		}
		require.Error(t, validateProgrammeAuthorityThreshold(row.n, row.n+1))
	}
	for _, n := range []uint64{0, 1, 2, 3, 4} {
		_, err := minimumProgrammeAuthorityThreshold(n)
		require.Error(t, err)
		require.Error(t, validateProgrammeAuthorityThreshold(n, 3))
	}
	// An independent arbitrary-precision evaluation of the definition tests the
	// uint64 boundary without allocating a roster or copying the quotient formula.
	for _, n := range []uint64{math.MaxUint64 - 4, math.MaxUint64 - 3, math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64} {
		numerator := new(big.Int).Mul(new(big.Int).SetUint64(n), big.NewInt(3))
		numerator.Add(numerator, big.NewInt(4))
		expected := numerator.Quo(numerator, big.NewInt(5))
		minimum, err := minimumProgrammeAuthorityThreshold(n)
		require.NoError(t, err)
		require.Equal(t, expected.Uint64(), minimum)
	}
}

type w03SignatureFixture struct {
	members    [][]byte
	private    []crypto.PrivateKey
	indices    []uint64
	signatures [][]byte
	digest     []byte
	threshold  uint64
	maxMembers uint64
	maxBytes   uint64
	scheme     string
}

func w03SignatureProof(t *testing.T, n int, threshold uint64, indices []uint64) w03SignatureFixture {
	t.Helper()
	f := w03SignatureFixture{
		digest: []byte("W03 synthetic signature-only bytes"), threshold: threshold,
		indices: indices, maxMembers: 10, scheme: "ED25519_M_OF_N",
	}
	f.maxBytes = uint64(len(f.digest))
	keygen := signing.NewKeyGenerator(ed25519.NewEd25519())
	for i := 0; i < n; i++ {
		private, public := keygen.GeneratePair()
		member, err := public.ToByteArray()
		require.NoError(t, err)
		f.members = append(f.members, member)
		f.private = append(f.private, private)
	}
	f.sign(t)
	return f
}

func (f *w03SignatureFixture) sign(t *testing.T) {
	t.Helper()
	f.signatures = nil
	signer := &singlesig.Ed25519Signer{}
	for _, index := range f.indices {
		sig, err := signer.Sign(f.private[index], f.digest)
		require.NoError(t, err)
		f.signatures = append(f.signatures, sig)
	}
}

func (f *w03SignatureFixture) verify() error {
	return verifyProgrammeAuthoritySignatures(f.scheme, f.threshold, f.members, f.indices,
		f.signatures, f.digest, f.maxMembers, f.maxBytes)
}

func TestQualDRWAAuthoritySignatures(t *testing.T) {
	for _, row := range []struct {
		n         int
		threshold uint64
	}{
		{5, 3}, {6, 4}, {7, 5}, {8, 5}, {9, 6}, {10, 6},
	} {
		for threshold := row.threshold; threshold <= uint64(row.n); threshold++ {
			t.Run(fmt.Sprintf("n%d_t%d", row.n, threshold), func(t *testing.T) {
				indices := make([]uint64, threshold)
				for i := range indices {
					indices[i] = uint64(i)
				}
				f := w03SignatureProof(t, row.n, threshold, indices)
				require.NoError(t, f.verify()) // exactly the configured t, including t=n
				f.indices = f.indices[:len(f.indices)-1]
				f.signatures = f.signatures[:len(f.signatures)-1]
				require.Error(t, f.verify()) // t-1 never shrinks the immutable roster or t
			})
		}
	}
	for _, row := range []struct {
		name   string
		change func(*testing.T, *w03SignatureFixture)
	}{
		{"unknown_scheme", func(_ *testing.T, f *w03SignatureFixture) { f.scheme = "BLS" }},
		{"roster_bound", func(_ *testing.T, f *w03SignatureFixture) { f.maxMembers = 4 }},
		{"zero_roster_bound", func(_ *testing.T, f *w03SignatureFixture) { f.maxMembers = 0 }},
		{"below_threshold", func(_ *testing.T, f *w03SignatureFixture) { f.threshold = 2 }},
		{"above_roster", func(_ *testing.T, f *w03SignatureFixture) { f.threshold = 6 }},
		{"digest_bound", func(_ *testing.T, f *w03SignatureFixture) { f.maxBytes-- }},
		{"zero_digest_bound", func(_ *testing.T, f *w03SignatureFixture) { f.maxBytes = 0 }},
		{"signature_count", func(_ *testing.T, f *w03SignatureFixture) { f.signatures = f.signatures[:2]; f.indices = f.indices[:2] }},
		{"count_mismatch", func(_ *testing.T, f *w03SignatureFixture) { f.indices = append(f.indices, 3) }},
		{"duplicate_roster_unused", func(_ *testing.T, f *w03SignatureFixture) { f.members[4] = f.members[3] }},
		{"malformed_roster_unused", func(_ *testing.T, f *w03SignatureFixture) { f.members[4] = nil }},
		// Keep ordered, in-range indices and quorum valid to isolate wrong-key
		// rejection. The earlier outside-module draft also made these unordered.
		{"wrong_member", func(_ *testing.T, f *w03SignatureFixture) { f.indices = []uint64{1, 2, 3} }},
		{"out_of_roster", func(_ *testing.T, f *w03SignatureFixture) { f.indices[2] = 5 }},
		{"duplicate_indices", func(t *testing.T, f *w03SignatureFixture) { f.indices = []uint64{0, 0, 2}; f.sign(t) }},
		{"unsorted_indices", func(t *testing.T, f *w03SignatureFixture) { f.indices = []uint64{1, 0, 2}; f.sign(t) }},
		{"invalid_signature", func(_ *testing.T, f *w03SignatureFixture) { f.signatures[0][0] ^= 1 }},
		{"changed_signing_bytes", func(_ *testing.T, f *w03SignatureFixture) { f.digest[0] ^= 1 }},
		{"empty_digest", func(t *testing.T, f *w03SignatureFixture) { f.digest = nil; f.sign(t) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
			row.change(t, &f)
			require.Error(t, f.verify())
		})
	}
	four := w03SignatureProof(t, 4, 3, []uint64{0, 1, 2})
	require.Error(t, four.verify())
	extra := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2, 3})
	require.NoError(t, extra.verify())
	extra.signatures[3][0] ^= 1
	require.Error(t, extra.verify())
	oversized := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2, 3, 4, 0})
	require.Error(t, oversized.verify())
}

func TestQualDRWAAuthoritySignatureConcurrency(t *testing.T) {
	f := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
	var group sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < cap(errors); i++ {
		group.Add(1)
		go func() { defer group.Done(); errors <- f.verify() }()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}
