package drwa

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// H/S wrappers are explicit proof fixtures, NOT canonical/finality evidence.
// Their root/account/data bytes come from the real native transaction result.
func qualConsentWitness(t *testing.T, ctx *vm.VMTestContext, epoch uint32) ([]byte, PrivilegedConsentWitness, int) {
	return qualConsentWitnessAddress(t, ctx, epoch, qualConsentEOA)
}

func qualConsentWitnessAddress(t *testing.T, ctx *vm.VMTestContext, epoch uint32, address []byte) ([]byte, PrivilegedConsentWitness, int) {
	s := qualConsentScope()
	s.Address = bytes.Clone(address)
	return qualConsentWitnessScope(t, ctx, epoch, s)
}

func qualConsentWitnessScope(t *testing.T, ctx *vm.VMTestContext, epoch uint32, scope PrivilegedConsentScope) ([]byte, PrivilegedConsentWitness, int) {
	t.Helper()
	root, err := ctx.Accounts.Commit()
	require.NoError(t, err)
	s := &block.HeaderV3{Nonce: 11, Round: 21, Epoch: epoch, ShardID: 1}
	w := PrivilegedConsentWitness{}
	w.ExecutedHeader, err = ctx.Marshalizer.Marshal(s)
	require.NoError(t, err)
	h := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: epoch, ShardID: 1, ExecutionResults: []*block.ExecutionResult{{BaseExecutionResult: &block.BaseExecutionResult{
		HeaderHash: integrationTests.TestHasher.Compute(string(w.ExecutedHeader)), HeaderNonce: s.Nonce, HeaderRound: s.Round, HeaderEpoch: epoch, RootHash: root}}}}
	w.Header, err = ctx.Marshalizer.Marshal(h)
	require.NoError(t, err)
	mainTrie, err := ctx.Accounts.GetTrie(root)
	require.NoError(t, err)
	w.EOAProof, _, err = mainTrie.GetProof(scope.Address)
	require.NoError(t, err)
	w.AccountProof, _, err = mainTrie.GetProof(core.SystemAccountAddress)
	require.NoError(t, err)
	a, err := ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	logicalKey := privilegedConsentRecordKey(scope.Address, scope.Token, scope.Program)
	key := logicalKey
	if ctx.EnableEpochsHandler.IsFlagEnabled(common.AutoBalanceDataTriesFlag) {
		key = integrationTests.TestHasher.Compute(string(key))
	}
	// Native empty tries have no membership proof. An absent consent supplies
	// no data proof and must be rejected; a nonce is never evidence of consent.
	value, _, _ := u.RetrieveValue(logicalKey)
	if len(value) != 0 {
		w.DataProof, _, err = u.DataTrie().(common.Trie).GetProof(key)
		require.NoError(t, err)
	}
	budget := 0
	for _, nodes := range [][][]byte{w.AccountProof, w.DataProof, w.EOAProof} {
		for _, node := range nodes {
			budget += len(node)
		}
	}
	return integrationTests.TestHasher.Compute(string(w.Header)), w, budget
}
func qualConsentReader(t *testing.T, ctx *vm.VMTestContext) *ResultAccountReader {
	t.Helper()
	args := qualReaderArgs(false)
	args.Hasher = integrationTests.TestHasher
	args.Marshaller = ctx.Marshalizer
	args.EnableEpochsHandler = ctx.EnableEpochsHandler
	r, err := NewResultAccountReader(args)
	require.NoError(t, err)
	return r
}

func TestQualDRWAPrivilegedConsentEvidence(t *testing.T) {
	// Component-level call sites only; actual admission consumers remain unwired.
	for _, instant := range []string{"genesis_target", "preparation", "currentization", "setup_sealing", "role_assignment_supply", "previously_unmarked"} {
		for _, name := range []string{"valid", "duplicate", "target", "domain", "roles", "token", "program", "address", "empty_field", "over_bound", "missing_reader", "meta", "wrong_H", "wrong_shard", "stale_nonce", "code", "malformed_record", "nonce_without_action"} {
			t.Run(instant+"/"+name, func(t *testing.T) {
				ctx := qualConsentContext(t)
				c, owner := qualConsentInstall(t, ctx, 0)
				s := qualConsentScope()
				qualConsentProcess(t, ctx, qualConsentData(s), nil)
				_, _, err := owner.Commit()
				require.NoError(t, err)
				if name == "stale_nonce" {
					qualConsentProcess(t, ctx, []byte("SaveKeyValue@01@02"), nil)
				}
				if name == "code" || name == "malformed_record" || name == "nonce_without_action" {
					a, e := ctx.Accounts.LoadAccount(qualConsentEOA)
					require.NoError(t, e)
					u := a.(state.UserAccountHandler)
					if name == "code" {
						u.SetCode([]byte("code-install-state-origin-challenge"))
					}
					if name == "nonce_without_action" {
						u.IncreaseNonce(1)
					}
					require.NoError(t, ctx.Accounts.SaveAccount(u))
					if name != "code" {
						system, e := ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
						require.NoError(t, e)
						var value []byte
						if name == "malformed_record" {
							value = []byte("not a consent record")
						}
						require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(privilegedConsentRecordKey(s.Address, s.Token, s.Program), value))
						require.NoError(t, ctx.Accounts.SaveAccount(system))
					}
				}
				anchor, w, budget := qualConsentWitness(t, ctx, 0)
				reader := qualConsentReader(t, ctx)
				shard := uint32(1)
				switch name {
				case "target":
					s.Target = []byte("wrong-target")
				case "domain":
					s.Domain = []byte("wrong-domain")
				case "roles":
					s.Roles = []byte("wrong-roles")
				case "token":
					s.Token = []byte("wrong-token")
				case "program":
					s.Program = []byte("wrong-program")
				case "address":
					s.Address = bytes.Repeat([]byte{0x32}, 32)
				case "empty_field":
					s.Program = nil
				case "over_bound":
					s.Program = bytes.Repeat([]byte{1}, 257)
				case "missing_reader":
					reader = nil
				case "meta":
					shard = core.MetachainShardId
				case "wrong_H":
					anchor = []byte("later required canonical H")
				case "wrong_shard":
					shard = 2
				}
				err = c.ReadEvidence(reader, anchor, shard, s, w, budget)
				if name == "valid" || name == "duplicate" {
					require.NoError(t, err)
					for i := 0; i < 2; i++ {
						require.NoError(t, c.ReadEvidence(reader, anchor, shard, s, w, budget))
					}
					require.Zero(t, ctx.Accounts.JournalLen())
				} else {
					if name == "meta" {
						require.ErrorIs(t, err, ErrPrivilegedConsent)
					} else {
						require.Error(t, err)
					}
				}
			})
		}
	}
}

func TestQualDRWAPrivilegedConsentGuardianTiming(t *testing.T) {
	for _, name := range []string{"delayed_activation", "instant_replacement"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			epoch := qualConsentGuard(t, ctx)
			newGuardian := bytes.Repeat([]byte{0x51}, 32)
			if name == "delayed_activation" {
				qualConsentProcess(t, ctx, []byte("SetGuardian@"+hex.EncodeToString(newGuardian)+"@01"), nil)
			}
			c, owner := qualConsentInstall(t, ctx, epoch)
			s := qualConsentScope()
			qualConsentProcess(t, ctx, qualConsentData(s), qualConsentGuardian)
			_, _, err := owner.Commit()
			require.NoError(t, err)
			oldH, oldW, oldBudget := qualConsentWitness(t, ctx, epoch)
			reader := qualConsentReader(t, ctx)
			require.NoError(t, c.ReadEvidence(reader, oldH, 1, s, oldW, oldBudget))
			before := qualConsentValue(t, ctx)
			a, err := ctx.Accounts.GetExistingAccount(qualConsentEOA)
			require.NoError(t, err)
			oldNonce := a.GetNonce()
			if name == "delayed_activation" {
				epoch += vm.EpochGuardianDelay
				ctx.EpochNotifier.CheckEpoch(&block.Header{Epoch: epoch})
			} else {
				qualConsentProcess(t, ctx, []byte("SetGuardian@"+hex.EncodeToString(newGuardian)+"@01"), qualConsentGuardian)
			}
			active, err := ctx.GuardedAccountsHandler.GetActiveGuardian(a.(vmcommon.UserAccountHandler))
			require.NoError(t, err)
			require.Equal(t, newGuardian, active)
			require.Equal(t, before, qualConsentValue(t, ctx), "pure guardian transition writes no consent or DRWA epoch")
			if name == "delayed_activation" {
				require.Equal(t, oldNonce, a.GetNonce(), "epoch activation has no nonce effect")
			}
			h, w, budget := qualConsentWitness(t, ctx, epoch)
			require.Error(t, c.ReadEvidence(reader, h, 1, s, w, budget))
			require.Error(t, c.ReadEvidence(reader, h, 1, s, oldW, oldBudget), "old observation cannot satisfy a different required context")
			// Unchanged possession of the owner key supplies no suitability waiver.
			// Native authorization by the replacement guardian creates fresh evidence.
			_, owner = qualConsentInstall(t, ctx, epoch)
			bad := qualConsentTx(t, ctx, qualConsentData(s), qualConsentGuardian)
			code, err := ctx.TxProcessor.ProcessTransaction(bad)
			require.Error(t, err)
			require.NotEqual(t, vmcommon.Ok, code)
			qualConsentProcess(t, ctx, qualConsentData(s), newGuardian)
			_, _, err = owner.Commit()
			require.NoError(t, err)
			h, w, budget = qualConsentWitness(t, ctx, epoch)
			require.NoError(t, c.ReadEvidence(reader, h, 1, s, w, budget))
		})
	}
}
