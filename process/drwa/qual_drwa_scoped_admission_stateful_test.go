package drwa

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Independent finite safety model: admitted/withdrawn facts only grow. Explore
// all depth-four words over admission, withdrawal, eligibility and local native
// persistence. Fixed synthetic mandates/time/budgets do not prove real ingress,
// appointment, finality, node restart, all-state capacity or unbounded progress.
func TestQualDRWAScopedAdmissionStateful(t *testing.T) {
	const alphabet = "AWQK"
	const depth = 4
	const traces = 256 // 4^4; prefixes are observed after every action
	for number := 0; number < traces; number++ {
		word := make([]byte, depth)
		remaining := number
		for i := depth - 1; i >= 0; i-- {
			word[i] = alphabet[remaining%len(alphabet)]
			remaining /= len(alphabet)
		}
		t.Run(string(word), func(t *testing.T) {
			f := qualScopedNew(t)
			t.Cleanup(func() { require.NoError(t, f.store.Close()) })
			f.enroll(t)
			admitted, withdrawn := false, false
			probe := func() error {
				return f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					return nil, f.records.checkDecision(f.context, f.d)
				})
			}
			for step, action := range word {
				label := fmt.Sprintf("%s step%d %c", word, step, action)
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journalBefore := f.store.JournalLen()
				unchanged := false
				switch action {
				case 'A':
					unchanged = admitted
					f.admit(t)
					admitted = true // duplicate never clears withdrawn
				case 'W':
					unchanged = !admitted || withdrawn
					err = f.records.withdraw(f.context, f.d, f.withdrawProof())
					if admitted {
						require.NoError(t, err, label)
						withdrawn = true
					} else {
						require.Error(t, err, label)
					}
				case 'Q':
					unchanged = true
					err = probe()
					if admitted && !withdrawn {
						require.NoError(t, err, label)
					} else {
						require.Error(t, err, label)
					}
				case 'K':
					roots, _, e := f.boundary.Commit()
					require.NoError(t, e, label)
					require.Len(t, roots, 1)
					require.Equal(t, before, roots[0], label)
					require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])), label)
					require.Zero(t, f.store.JournalLen(), label)
					f.boundary, err = NewRollbackContainment(f.store)
					require.NoError(t, err)
					f.records, err = newScopedAdmissionRecords(f.store, f.boundary,
						&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"),
						scopedAdmissionLimits{4096, 100, 1 << 20, 100}, f.mandates, qualClockSource(f.clock, f.store))
					require.NoError(t, err)
				}
				after, err := f.store.RootHash()
				require.NoError(t, err)
				if unchanged || action == 'K' {
					require.Equal(t, before, after, label)
				}
				if unchanged {
					require.Equal(t, journalBefore, f.store.JournalLen(), label)
				}

				// Independent expected state is never decoded from the component.
				// Each prefix must agree, including withdrawal→commit→replay.
				journalAfter := f.store.JournalLen()
				err = probe()
				if admitted && !withdrawn {
					require.NoError(t, err, label)
				} else {
					require.Error(t, err, label)
				}
				require.Equal(t, journalAfter, f.store.JournalLen(), label)
				observedRoot, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, after, observedRoot, label)
				budget := qualRegistryValue(t, f.store, "ELRONDDRWA@scopedAdmission@budget")
				require.Len(t, budget, 32)
				expectedCount := uint64(3) // budget + initial body + current pointer
				if admitted {
					expectedCount++
				}
				if withdrawn {
					expectedCount++
				}
				require.Equal(t, expectedCount, binary.BigEndian.Uint64(budget[:8]), label)
			}
		})
	}
}
