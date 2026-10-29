package drwa

import (
	"bytes"
	"fmt"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestRegistrationAdmission_WithBootstrapReadinessDependencyFailures(t *testing.T) {
	var absent *RegistrationAdmission
	require.Error(t, absent.RetainBootstrapIntent(nil, nil))
	for _, ready := range []bool{false, true} {
		t.Run(strings.ReplaceAll(fmt.Sprintf("readiness=%t", ready), "/", " ")+" should preserve the expected result", func(t *testing.T) {
			f, run, _ := admissionDependencyOperation(t, ready)
			control := &recordFault{calls: make(map[string]int)}
			f.store.AccountsAdapter = &recordStore{AccountsAdapter: f.store.AccountsAdapter, fault: control}
			f.owner.records.marshaller = &recordMarshal{Marshalizer: f.owner.records.marshaller, fault: control}
			require.NoError(t, run())
			for _, kind := range []string{"account", "read", "write", "save-account", "marshal", "unmarshal"} {
				for at := 1; at <= control.calls[kind]; at++ {
					t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%d", kind, at), "/", " ")+" should preserve the expected result", func(t *testing.T) {
						f, run, effects := admissionDependencyOperation(t, ready)
						fault := &recordFault{kind: kind, at: at, calls: make(map[string]int)}
						f.store.AccountsAdapter = &recordStore{AccountsAdapter: f.store.AccountsAdapter, fault: fault}
						f.owner.records.marshaller = &recordMarshal{Marshalizer: f.owner.records.marshaller, fault: fault}
						root, err := f.store.RootHash()
						require.NoError(t, err)
						journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
						require.Error(t, run())
						require.True(t, fault.hit)
						require.Zero(t, *effects)
						after, err := f.store.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, after)
						require.Equal(t, journal, f.store.JournalLen())
						require.Len(t, f.boundary.outputs, outputs)
						fault.kind = ""
						if !ready {
							require.Empty(t, qualRegistryValue(t, f.store, registrationIntentPrefix+string(f.owner.id)), "failed retention left a positive record")
						}
					})
				}
			}
			f, run, _ = admissionDependencyOperation(t, ready)
			f.end()
			require.Error(t, run())
		})
	}
}

// Keep the seed ownership check independent of any admission encoder.
func TestRegistrationAdmission_WithBootstrapReadinessBounds(t *testing.T) {
	f, _, _ := admissionDependencyOperation(t, true)
	acks, verifier := qualRegistrationAcks(t, f)
	before := bytes.Clone(acks[0].GlobalState)
	f.owner.records.maxBytes = 3
	err := f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, verifier, func() (*vmcommon.VMOutput, error) { t.Fatal("impossible ACK budget executed"); return nil, nil })
	require.Error(t, err)
	require.Equal(t, before, acks[0].GlobalState)
}
