package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualDRWASetupCompletedPhaseGuards(t *testing.T) {
	for _, name := range []string{"matching", "token", "epoch", "configured shard count"} {
		t.Run(name, func(t *testing.T) {
			x := qualSetupLifecycleNew(t)
			t.Cleanup(x.f.x.f.end)
			transition := x.transitions["READY"]
			view := lifecycleReadView{token: bytes.Clone(transition.token), cebEpoch: 1}
			switch name {
			case "token":
				view.token = []byte("OTHER-abcdef")
			case "epoch":
				view.cebEpoch++
			case "configured shard count":
				x.s.current.coordinator = &testscommon.ShardsCoordinatorMock{NoShards: 4, CurrentShard: core.MetachainShardId}
			}
			store := x.f.x.f.store
			key := x.keys["READY"]
			retained := bytes.Clone(qualActivationValue(t, store, key))
			require.NotEmpty(t, retained)
			root, err := store.RootHash()
			require.NoError(t, err)
			journal, calls := store.JournalLen(), x.ph.transitionCalls
			proof, readKey, readValue, err := x.s.completed(transition, view)
			if name == "matching" {
				require.NoError(t, err)
				require.Equal(t, key, readKey)
				require.Equal(t, retained, readValue)
				require.Equal(t, x.h.proofs["READY"], proof)
				require.Equal(t, calls+1, x.ph.transitionCalls)
			} else {
				require.ErrorIs(t, err, errSetupLifecycle)
				require.Nil(t, readKey)
				require.Nil(t, readValue)
				// The exact phase is present and otherwise usable. No alternate
				// key or provider denial can mask these prechecks.
				require.Equal(t, calls, x.ph.transitionCalls)
			}
			after, err := store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, store.JournalLen())
		})
	}
}

func TestQualDRWAActivationParentIdentityGuards(t *testing.T) {
	for _, name := range []string{"matching", "intent", "commitment"} {
		t.Run(name, func(t *testing.T) {
			x := qualActivationNew(t)
			t.Cleanup(x.f.end)
			store := x.f.store
			binding, commitment := []byte("synthetic verified readiness identity"), bytes.Repeat([]byte{7}, 32)
			token, expectedIntent := []byte("TOKEN-abcdef"), x.f.owner.id
			intent, retainedCommitment := bytes.Clone(expectedIntent), bytes.Clone(commitment)
			if name == "intent" {
				intent[0] ^= 1
			}
			if name == "commitment" {
				retainedCommitment[0] ^= 1
			}
			key := append([]byte(registrationActivationPrefix), token...)
			qualRecordPut(t, store, key, qualRecordFrame(token, intent, []byte("Active"), retainedCommitment))
			qualRecordPut(t, store, []byte(qualConvergenceParent), qualRecordFrame(binding, commitment))
			phase := qualConvergenceNew(t, 3)
			phase.host.store, phase.host.binding = store, binding
			phaseHost := &activationReadinessHost{
				convergenceHost: phase.host, activation: x.a, binding: binding,
				token: token, intentID: expectedIntent,
			}
			err := phaseHost.VerifyParent(binding, commitment)
			if name == "matching" {
				require.NoError(t, err)
				require.Equal(t, 1, phase.host.parentCalls)
			} else {
				require.ErrorIs(t, err, errActivationRecord)
				require.Zero(t, phase.host.parentCalls)
			}
		})
	}
}

func TestQualDRWAConvergenceRetainedParentRecheck(t *testing.T) {
	for _, name := range []string{"matching", "changed status", "changed commitment"} {
		t.Run(name, func(t *testing.T) {
			f := qualConvergenceNew(t, 3)
			f.create(t)
			for shard := uint32(0); shard < 3; shard++ {
				require.NoError(t, f.ack(shard))
			}
			require.NoError(t, f.records.complete(f.tr))
			progress, err := f.records.load(f.key, f.binding, 3)
			require.NoError(t, err)
			if name == "changed status" {
				progress.status = "PENDING"
			}
			if name == "changed commitment" {
				progress.commitment[0] ^= 1
				// The separately checked host parent agrees with the supplied
				// commitment. The retained progress record still differs.
				qualRecordPut(t, f.store, []byte(qualConvergenceParent), qualRecordFrame(f.binding, progress.commitment))
			}
			priorCalls := f.host.parentCalls
			err = f.records.verifyParent(f.key, f.binding, 3, progress)
			require.Equal(t, priorCalls+1, f.host.parentCalls)
			if name == "matching" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errConvergence)
			}
		})
	}
}
