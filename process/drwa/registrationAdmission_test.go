package drwa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

type rootReadFault struct {
	state.AccountsAdapter
	at, calls int
	failure   error
}

func (s *rootReadFault) RootHash() ([]byte, error) {
	s.calls++
	if s.calls == s.at {
		return nil, s.failure
	}
	return s.AccountsAdapter.RootHash()
}

func TestVerifyRegistrationState(t *testing.T) {
	for _, at := range []int{1, 2} {
		t.Run(strings.ReplaceAll(fmt.Sprint(at), "/", " ")+" should preserve the expected result", func(t *testing.T) {
			sentinel := errors.New("native root unavailable")
			s := &rootReadFault{AccountsAdapter: qualRegistrationStore(t, 0), at: at, failure: sentinel}
			calls := 0
			err := verifyRegistrationState([]state.AccountsAdapter{s}, func() error { calls++; return nil })
			require.ErrorIs(t, err, sentinel)
			require.Equal(t, at-1, calls)
		})
	}
}

func admissionDependencyOperation(t *testing.T, ready bool) (*qualRegistrationAdmissionFixture, func() error, *int) {
	t.Helper()
	f := qualRegistrationAdmission(t, core.FungibleESDT)
	t.Cleanup(f.end)
	effects := new(int)
	if ready {
		require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
		acks, verifier := qualRegistrationAcks(t, f)
		return f, func() error {
			return f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, verifier, func() (*vmcommon.VMOutput, error) {
				*effects++
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
		}, effects
	}
	f.admit.verifier = &qualBootstrapVerifier{f.verify}
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), f.owner.id...), nil)
	key := []byte(scopedAdmissionPrefix + "budget")
	budget := make([]byte, 32)
	binary.BigEndian.PutUint64(budget, 1)
	binary.BigEndian.PutUint64(budget[8:], uint64(len(key)+32))
	binary.BigEndian.PutUint64(budget[16:], 10)
	qualRecordPut(t, f.store, key, budget)
	return f, func() error { return f.admit.RetainBootstrapIntent(f.verify.body, []byte("explicit-step1-mandate")) }, effects
}
