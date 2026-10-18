package drwa

// FA-01 RT-01: retained batch 4a reconciler regression probe. Settles FA-codex-B4a-1 independently of the Codex
// probe: (1) whether the injected PrivilegedConsentReferenceReader runs while
// c.mut is held, observed with TryLock at each reader call of a real native
// ExecuteNativeTransaction; (2) whether a synchronous nested
// ExecuteNativeTransaction from inside the reader returns ErrExecutionBusy
// (the executing predicate, privilegedConsent.go L183-185) or blocks.
// Expectations come from the candidate's own refusal predicate, not from the
// observed behaviour. The 5s bound is an observation bound, not a protocol value.

import (
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/integrationTests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualReconB4aReader struct {
	inner  PrivilegedConsentReferenceReader
	c      *PrivilegedConsentCandidate
	held   []bool
	nested func()
}

func (r *qualReconB4aReader) AdmittedProgram(token []byte) ([]byte, error) {
	free := r.c.mut.TryLock()
	if free {
		r.c.mut.Unlock()
	}
	r.held = append(r.held, !free)
	if f := r.nested; f != nil {
		r.nested = nil
		f()
	}
	return r.inner.AdmittedProgram(token)
}

func (r *qualReconB4aReader) IsInterfaceNil() bool { return r == nil }

func TestQualReconB4aConsentReaderLockHeld(t *testing.T) {
	ctx := qualConsentContext(t)
	c, _ := qualConsentInstall(t, ctx, 0)
	r := &qualReconB4aReader{inner: c.references, c: c}
	c.references = r
	tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
	code, err := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, code)
	t.Logf("OBSERVATION reader_calls=%d mutex_held_at_each_call=%v", len(r.held), r.held)
	require.Len(t, r.held, 2)
	require.Equal(t, []bool{false, false}, r.held, "injected reader runs while c.mut is held")
}

func TestQualReconB4aConsentReaderNestedEntry(t *testing.T) {
	ctx := qualConsentContext(t)
	c, _ := qualConsentInstall(t, ctx, 0)
	r := &qualReconB4aReader{inner: c.references, c: c}
	c.references = r
	tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
	nestedErr := make(chan error, 1)
	r.nested = func() {
		_, e := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
		nestedErr <- e
	}
	outer := make(chan error, 1)
	go func() {
		_, e := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
		outer <- e
	}()
	select {
	case <-outer:
		require.ErrorIs(t, <-nestedErr, ErrExecutionBusy)
	case <-time.After(5 * time.Second):
		t.Fatalf("OBSERVATION synchronous nested ExecuteNativeTransaction from the reader did not return within 5s; expected ErrExecutionBusy")
	}
}
