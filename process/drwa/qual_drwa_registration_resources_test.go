package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAT44T45RegistrationResourceConsumption(t *testing.T) {
	for _, fault := range []string{"healthy", "missing-budget", "malformed-budget", "count-full", "bytes-full", "rate-full", "epoch-regression"} {
		t.Run(fault, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			key := []byte(scopedAdmissionPrefix + "budget")
			beforeBudget := bytes.Clone(qualRegistryValue(t, f.store, string(key)))
			budget := bytes.Clone(beforeBudget)
			switch fault {
			case "missing-budget":
				budget = nil
			case "malformed-budget":
				budget = []byte{0}
			case "count-full":
				binary.BigEndian.PutUint64(budget, f.admit.limits.Records)
			case "bytes-full":
				binary.BigEndian.PutUint64(budget[8:], f.admit.limits.RetainedBytes)
			case "rate-full":
				binary.BigEndian.PutUint64(budget[24:], f.admit.limits.NewRecordsPerEpoch)
			case "epoch-regression":
				binary.BigEndian.PutUint64(budget[16:], 11)
			}
			qualRecordPut(t, f.store, key, budget)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			outputs, journal := len(f.boundary.outputs), f.store.JournalLen()
			err = f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef"))
			if fault == "healthy" {
				require.NoError(t, err)
				after := qualRegistryValue(t, f.store, string(key))
				require.Equal(t, binary.BigEndian.Uint64(beforeBudget)+2, binary.BigEndian.Uint64(after))
				require.Equal(t, uint64(2), binary.BigEndian.Uint64(after[24:]))
				oldIntent := qualRecordFrame(f.verify.body, []byte("OPEN"), nil)
				newIntent := qualRecordFrame(f.verify.body, []byte("CONSUMED"), []byte("TOKEN-abcdef"))
				association := qualRecordFrame([]byte("TOKEN-abcdef"), f.owner.id, f.owner.digest, f.verify.body, f.owner.manager)
				activation := qualRecordFrame([]byte("TOKEN-abcdef"), f.owner.id, []byte("BootstrapDeny"))
				delta := len(newIntent) - len(oldIntent) + len(registrationAssociationPrefix) + len("TOKEN-abcdef") + len(association) + len(registrationActivationPrefix) + len("TOKEN-abcdef") + len(activation)
				require.Equal(t, binary.BigEndian.Uint64(beforeBudget[8:])+uint64(delta), binary.BigEndian.Uint64(after[8:]))
				return
			}
			require.Error(t, err)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Len(t, f.boundary.outputs, outputs)
			require.Equal(t, budget, qualRegistryValue(t, f.store, string(key)))
		})
	}
}

// Bootstrap retention is a separate Step-1 mandate, with explicit synthetic
// semantics here. It never treats a registration/finality certificate as that
// mandate, and resource exhaustion precedes a new retained record.
type qualBootstrapVerifier struct{ base *qualRegistrationVerifier }

func (v *qualBootstrapVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualBootstrapVerifier) VerifyRegistration(p string, id, digest, body, creation, proof []byte, at HeaderMilliseconds, epoch uint32) error {
	if p != "BOOTSTRAP_INTENT" || !bytes.Equal(id, v.base.id) || !bytes.Equal(digest, v.base.intentHash) ||
		!bytes.Equal(body, v.base.body) || len(creation) != 0 || !bytes.Equal(proof, []byte("explicit-step1-mandate")) || at != 1 || epoch != 10 {
		return errInvalidRegistrationRecord
	}
	return nil
}

func TestQualDRWAT44T45OpenIntentAggregateAdmission(t *testing.T) {
	for _, fault := range []string{"healthy", "count", "bytes", "rate", "missing-budget", "wrong-mandate", "duplicate-open", "consumed", "cancelled", "expired-retained"} {
		t.Run(fault, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			f.admit.verifier = &qualBootstrapVerifier{f.verify}
			key := append([]byte(registrationIntentPrefix), f.owner.id...)
			budgetKey := []byte(scopedAdmissionPrefix + "budget")
			budget := bytes.Clone(qualRegistryValue(t, f.store, string(budgetKey)))
			// A new-chain fixture starts with only the already provisioned budget.
			qualRecordPut(t, f.store, key, nil)
			binary.BigEndian.PutUint64(budget, 1)
			binary.BigEndian.PutUint64(budget[8:], uint64(len(budgetKey)+32))
			proof := []byte("explicit-step1-mandate")
			switch fault {
			case "count":
				binary.BigEndian.PutUint64(budget, f.admit.limits.Records)
			case "bytes":
				binary.BigEndian.PutUint64(budget[8:], f.admit.limits.RetainedBytes)
			case "rate":
				binary.BigEndian.PutUint64(budget[24:], f.admit.limits.NewRecordsPerEpoch)
			case "missing-budget":
				budget = nil
			case "wrong-mandate":
				proof = []byte("REGISTER_TOKEN_ADMISSION")
			case "duplicate-open", "expired-retained":
				qualRecordPut(t, f.store, key, qualRecordFrame(f.verify.body, []byte("OPEN"), nil))
				if fault == "expired-retained" {
					f.end()
					qualT42Install(t, f.hook, core.MetachainShardId, 2)
				}
			case "consumed":
				qualRecordPut(t, f.store, key, qualRecordFrame(f.verify.body, []byte("CONSUMED"), []byte("TOKEN-abcdef")))
			case "cancelled":
				qualRecordPut(t, f.store, key, qualRecordFrame(f.verify.body, []byte("CANCELLED"), nil))
			}
			qualRecordPut(t, f.store, budgetKey, budget)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			err = f.admit.RetainBootstrapIntent(f.verify.body, proof)
			if fault == "healthy" {
				require.NoError(t, err)
				require.Equal(t, qualRecordFrame(f.verify.body, []byte("OPEN"), nil), qualRegistryValue(t, f.store, string(key)))
				retained := qualRegistryValue(t, f.store, string(budgetKey))
				require.Equal(t, uint64(2), binary.BigEndian.Uint64(retained))
				require.Equal(t, uint64(1), binary.BigEndian.Uint64(retained[24:]))
				return
			}
			require.Error(t, err)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
		})
	}
}
