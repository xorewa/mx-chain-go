package drwa

import (
	"bytes"
	"encoding/binary"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
	"testing"
)

// Auditor reproduction: Part A 2130-2131 forbids OPEN-intent creation before
// enforcement. Reuses existing experimental identities, time, budget and host.
func TestQualFreshAudit4bBootstrapIntentEnforcement(t *testing.T) {
	for _, enable := range []uint32{10, 11} {
		t.Run(map[uint32]string{10: "at_enforcement", 11: "before_enforcement"}[enable], func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			f.admit.verifier = &qualBootstrapVerifier{f.verify}
			f.admit.enableEpoch = enable
			key := append([]byte(registrationIntentPrefix), f.owner.id...)
			budgetKey := []byte(scopedAdmissionPrefix + "budget")
			budget := bytes.Clone(qualRegistryValue(t, f.store, string(budgetKey)))
			qualRecordPut(t, f.store, key, nil)
			binary.BigEndian.PutUint64(budget, 1)
			binary.BigEndian.PutUint64(budget[8:], uint64(len(budgetKey)+32))
			qualRecordPut(t, f.store, budgetKey, budget)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			err = f.admit.RetainBootstrapIntent(f.verify.body, []byte("explicit-step1-mandate"))
			after, readErr := f.store.RootHash()
			require.NoError(t, readErr)
			retained := qualRegistryValue(t, f.store, string(key))
			t.Logf("native epoch=10 enableEpoch=%d error=%v root_changed=%t retained_bytes=%d", enable, err, !bytes.Equal(before, after), len(retained))
			if enable == 10 {
				require.NoError(t, err)
				require.NotEmpty(t, retained)
				return
			}
			require.Error(t, err, "Part A 2130-2131: deny before configured enforcement epoch")
			require.Equal(t, before, after)
			require.Empty(t, retained)
		})
	}
}
