package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Model04 DEVELOPMENT ONLY: the consumer callback is explicit experimental
// assembly, not protected ingress. The token creator is the existing synthetic
// storage fixture, not createNewToken. Mandates/manager/profile remain synthetic.
// Native signatures, accounts, journals, registration records and trie are real.
func qualScopedRegistration(t *testing.T) (*qualScopedFixture, *RegistrationIntentOwner) {
	t.Helper()
	f := qualScopedNew(t)
	body, _, _, _ := qualRecordBody()
	body.networkDomain, body.issuer, body.programID = f.records.domain, f.d.issuer, f.d.program
	body.issuerProgramAdmissionDecision, body.expiry = f.body(), 200
	encoded := qualRecordFrame(body.networkDomain, body.issuer, body.programID, body.intentNonce,
		body.requestedTokenFamily, body.creationProfile, body.nameCommitment, body.tickerCommitment,
		body.propertyCommitment, body.publicSchemaProfile, body.issuerProgramAdmissionDecision,
		qualRecordFrame(body.proposedProgramAuthoritySetBodies...), qualRecordFrame(body.proposedProgramAuthoritySetHashes...),
		body.closurePlan, body.networkProfile, binary.BigEndian.AppendUint64(nil, uint64(body.expiry)))
	hasher := blake2b.NewBlake2b()
	digest := hasher.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), encoded)))
	id := hasher.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), body.networkDomain,
		body.issuer, body.programID, body.intentNonce, digest)))
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("OPEN"), nil))
	_, err := f.store.Commit()
	require.NoError(t, err)
	registration, boundary := qualRegistrationOwner(t, f.store, 2)
	f.boundary, f.records.boundary = boundary, boundary // ONE exclusive journal owner
	owner, err := registration.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32),
		&marshal.GogoProtoMarshalizer{}, hasher, 4096)
	require.NoError(t, err)
	f.enroll(t)
	f.admit(t)
	return f, owner
}

func qualScopedRegister(t *testing.T, f *qualScopedFixture, owner *RegistrationIntentOwner,
	create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	t.Helper()
	return owner.RegisterTokenForCreation(f.d.issuer, bytes.Repeat([]byte{0x22}, 32), []byte(core.FungibleESDT),
		func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			intent, err := owner.records.intent(owner.id)
			if err != nil {
				return nil, nil, err
			}
			if !bytes.Equal(intent.body.networkDomain, f.records.domain) ||
				!bytes.Equal(intent.body.issuer, f.d.issuer) || !bytes.Equal(intent.body.programID, f.d.program) ||
				!bytes.Equal(intent.body.issuerProgramAdmissionDecision, f.body()) {
				return nil, nil, errScopedAdmission
			}
			// Fresh read INSIDE registration's owning journal, before first write.
			if err = f.records.checkDecision(f.context, f.d); err != nil {
				return nil, nil, err
			}
			return create(accounts)
		})
}

func qualScopedTokenBytes(t *testing.T, f *qualScopedFixture) []byte {
	t.Helper()
	a, err := f.store.GetExistingAccount(core.ESDTSCAddress)
	if err != nil { // no synthetic native creator has run
		require.ErrorIs(t, err, state.ErrAccNotFound)
		return nil
	}
	value, _, err := a.(state.UserAccountHandler).RetrieveValue([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	return value
}

func qualScopedRegistrationFacts(t *testing.T, f *qualScopedFixture, owner *RegistrationIntentOwner) [][]byte {
	t.Helper()
	return [][]byte{qualScopedTokenBytes(t, f), qualRegistryValue(t, f.store, registryCountKey),
		qualRegistryValue(t, f.store, registryMemberKeyPrefix+"TOKEN-abcdef"),
		qualRegistryValue(t, f.store, registrationIntentPrefix+string(owner.id)),
		qualRegistryValue(t, f.store, registrationAssociationPrefix+"TOKEN-abcdef"),
		qualRegistryValue(t, f.store, registrationActivationPrefix+"TOKEN-abcdef")}
}

func TestQualDRWAScopedAdmissionRegistrationCurrentness(t *testing.T) {
	for _, condition := range []string{"healthy", "withdrawn", "expired", "successor", "missing-decision", "malformed-withdrawal", "ended-context"} {
		t.Run(condition, func(t *testing.T) {
			f, owner := qualScopedRegistration(t)
			require.NoError(t, f.records.checkDecision(f.context, f.d)) // NOT a cached permission
			switch condition {
			case "withdrawn":
				require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
			case "expired":
				var err error
				f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 201})
				require.NoError(t, err)
			case "successor":
				qualScopedSuccessors(t, f, 1)
			case "missing-decision":
				qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"decision@"+string(f.id())), nil)
			case "malformed-withdrawal":
				qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"withdrawn@"+string(f.id())), []byte{1})
			case "ended-context":
				f.clock.End(f.context)
			}
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal, outputCount := f.store.JournalLen(), len(f.boundary.outputs)
			facts, budget := qualScopedRegistrationFacts(t, f, owner), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
			called := 0
			err = qualScopedRegister(t, f, owner, func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				called++
				return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
			})
			if condition == "healthy" {
				require.NoError(t, err)
				require.Equal(t, 1, called)
				intent, manager, err := owner.records.registeredToken([]byte("TOKEN-abcdef"))
				require.NoError(t, err)
				require.Equal(t, "CONSUMED", intent.status)
				require.Equal(t, owner.manager, manager)
				require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, registryCountKey)))
				require.Equal(t, []byte{1}, qualRegistryValue(t, f.store, registryMemberKeyPrefix+"TOKEN-abcdef"))
				require.Equal(t, []byte("native-token-record"), qualScopedTokenBytes(t, f))
				require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), owner.id, []byte("BootstrapDeny")),
					qualRegistryValue(t, f.store, registrationActivationPrefix+"TOKEN-abcdef"))
				return
			}
			require.Error(t, err)
			require.Zero(t, called)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, outputCount, len(f.boundary.outputs))
			require.Equal(t, facts, qualScopedRegistrationFacts(t, f, owner))
			require.Equal(t, budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
		})
	}
}

func TestQualDRWAScopedAdmissionRegistrationRollback(t *testing.T) {
	for _, fault := range []string{"creator-error", "failed-output"} {
		t.Run(fault, func(t *testing.T) {
			f, owner := qualScopedRegistration(t)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			facts := qualScopedRegistrationFacts(t, f, owner)
			journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
			failure := errors.New("registration composition creator error")
			err = qualScopedRegister(t, f, owner, func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				id, output, err := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
				if err != nil {
					return nil, nil, err
				}
				if fault == "creator-error" {
					return nil, nil, failure
				}
				output.ReturnCode = vmcommon.UserError
				return id, output, nil
			})
			require.Error(t, err)
			if fault == "creator-error" {
				require.ErrorIs(t, err, failure)
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, outputs, len(f.boundary.outputs))
			require.Equal(t, facts, qualScopedRegistrationFacts(t, f, owner))
			require.NoError(t, f.records.checkDecision(f.context, f.d))
			require.NoError(t, qualScopedRegister(t, f, owner, qualRegistrationCreator(t, "TOKEN-abcdef")))
			require.Error(t, qualScopedRegister(t, f, owner, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				t.Fatal("consumed intent replay invoked creator")
				return nil, nil, nil
			}))
		})
	}
}

func TestQualDRWAScopedAdmissionRegisteredThenWithdrawn(t *testing.T) {
	f, owner := qualScopedRegistration(t)
	require.NoError(t, qualScopedRegister(t, f, owner, qualRegistrationCreator(t, "TOKEN-abcdef")))
	require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), owner.id, []byte("BootstrapDeny")),
		qualRegistryValue(t, f.store, registrationActivationPrefix+"TOKEN-abcdef"))
	facts := qualScopedRegistrationFacts(t, f, owner)
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	require.Equal(t, facts, qualScopedRegistrationFacts(t, f, owner))
	require.Error(t, f.records.checkDecision(f.context, f.d), "next admission prerequisite fails; no activation is attempted")
	roots, outputs, err := f.boundary.Commit()
	require.NoError(t, err)
	nativeOutputs := 0
	for _, output := range outputs {
		if output != nil {
			nativeOutputs++
			require.Equal(t, [][]byte{[]byte("TOKEN-abcdef")}, output.ReturnData)
		}
	}
	require.Equal(t, 1, nativeOutputs)
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	require.Equal(t, facts, qualScopedRegistrationFacts(t, f, owner))
	intent, _, err := owner.records.registeredToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, "CONSUMED", intent.status)
	require.Equal(t, f.body(), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
	require.Error(t, f.records.checkDecision(f.context, f.d))
}

func TestQualDRWAScopedAdmissionRegistrationExclusiveOrder(t *testing.T) {
	f, owner := qualScopedRegistration(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- qualScopedRegister(t, f, owner, func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			close(entered)
			<-release
			return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
		})
	}()
	<-entered
	err := f.records.withdraw(f.context, f.d, f.withdrawProof())
	close(release)
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.NoError(t, <-done)
	require.Empty(t, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
	facts := qualScopedRegistrationFacts(t, f, owner)
	require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
	require.Equal(t, facts, qualScopedRegistrationFacts(t, f, owner))
	require.Error(t, f.records.checkDecision(f.context, f.d))
}
