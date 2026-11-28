package drwa

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-79 at the carrier the product emits today: the registry delta of a
// registration, one asynchronous call for each execution shard, whose outcome
// is that shard's acknowledgment (SP2-22).

var sp279Delta = CarrierPrice{Source: 4000, Destination: 0, Success: 9000, Refund: 0, Completion: 51000}

type sp279Registry struct {
	*sp279World
	registration *RegistryRegistration
	boundary     *RollbackContainment
}

func sp279NewRegistry(t *testing.T, shards uint32) *sp279Registry {
	w := sp279World_(t, sp223Ample(), map[string]CarrierPrice{RegistryDeltaCarrierClass: sp279Delta})
	registration, boundary, err := NewRegistryRegistration(w.store,
		&testscommon.ShardsCoordinatorMock{NoShards: shards, CurrentShard: core.MetachainShardId}, 8)
	require.NoError(t, err)
	return &sp279Registry{sp279World: w, registration: registration, boundary: boundary}
}

// creator is a native creator that writes its token record and returns the
// gas it has left and one result of its own.
func sp279Creator(token string, gasRemaining uint64) func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
	return func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		a, err := accounts.LoadAccount(core.ESDTSCAddress)
		if err != nil {
			return nil, nil, err
		}
		if err = a.(state.UserAccountHandler).SaveKeyValue([]byte(token), []byte("native-token-record")); err != nil {
			return nil, nil, err
		}
		if err = accounts.SaveAccount(a); err != nil {
			return nil, nil, err
		}
		issuer := bytes.Repeat([]byte{7}, 32)
		return []byte(token), &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: gasRemaining,
			OutputAccounts: map[string]*vmcommon.OutputAccount{string(issuer): {Address: issuer, BalanceDelta: big.NewInt(0),
				OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), GasLimit: 0, Data: []byte("creator")}}}}}, nil
	}
}

func sp279Deltas(t *testing.T, output *vmcommon.VMOutput) map[uint32]vmcommon.OutputTransfer {
	t.Helper()
	deltas := map[uint32]vmcommon.OutputTransfer{}
	for _, account := range output.OutputAccounts {
		for _, transfer := range account.OutputTransfers {
			if !bytes.HasPrefix(transfer.Data, []byte(RegistryDeltaFunctionName+"@")) {
				continue
			}
			shard := uint32(account.Address[len(account.Address)-1])
			require.Equal(t, registryDeltaSystemAddress(shard), account.Address)
			_, twice := deltas[shard]
			require.False(t, twice)
			deltas[shard] = transfer
		}
	}
	return deltas
}

// callback is the acknowledgment of shard for a member, as the metachain
// processor hands it to the ESDT system contract (SP2-22).
func sp279Callback(token string, ordinal uint64, shard uint32, gas uint64) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: registryDeltaSystemAddress(shard), CallValue: big.NewInt(0), GasProvided: gas,
			CallType:  vmData.AsynchronousCallBack,
			Arguments: [][]byte{{byte(vmcommon.Ok)}, []byte(token), binary.BigEndian.AppendUint64(nil, ordinal)}},
		RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: RegistryAcknowledgmentFunctionName,
	}
}

func TestQualSP279RegistrationFundsItsDeltaBeforeTheMember(t *testing.T) {
	const shards = uint32(3)
	r := sp279NewRegistry(t, shards)
	require.ErrorIs(t, r.registration.SetCarrierFunding(nil), ErrInvalidRegistryRegistration)
	foreign := sp279Default(t)
	require.ErrorIs(t, r.registration.SetCarrierFunding(foreign.funding), ErrInvalidRegistryRegistration, "the funding owner of another store")
	require.NoError(t, r.registration.SetCarrierFunding(r.funding))
	require.ErrorIs(t, r.registration.SetCarrierFunding(r.funding), ErrInvalidRegistryRegistration, "installed once")

	leg := sp279Leg(sp279Delta)
	total := sp279Total(sp279Delta, shards)
	require.Equal(t, uint64(4000+3*60000), total)
	// The clause's replication reservation (SP2-26) gives the same amount.
	work := make([]replicationShardWork, shards)
	for i := range work {
		work[i] = replicationShardWork{fanout: sp279Delta.Destination, acknowledgement: sp279Delta.Success, processing: sp279Delta.Completion}
	}
	reserved, remaining, err := reserveReplicationWork(total+123, sp279Delta.Source, shards, work)
	require.NoError(t, err)
	require.Equal(t, total, reserved)
	require.Equal(t, uint64(123), remaining)

	// One unit short: the registration is refused and nothing of it remains,
	// neither the creator's record, nor the member, nor the count, nor a
	// funding record, nor an output.
	root := r.root()
	err = r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", total-1))
	require.ErrorIs(t, err, ErrCarrierUnderfunded)
	require.Equal(t, root, r.root())
	require.Zero(t, r.store.JournalLen())
	require.Empty(t, qualRegistryValue(t, r.store, registryMemberKeyPrefix+"TOKEN-abcdef"))
	require.Equal(t, make([]byte, 8), qualRegistryValue(t, r.store, registryCountKey))
	require.Nil(t, r.state(RegistryDeltaCarrierClass, string(registryDeltaEffect([]byte("TOKEN-abcdef"), 0))))

	// Funded: the registration returns what is left, every delta carries the
	// leg's gas, and the price is retained with the member.
	require.NoError(t, r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", total+123)))
	require.NoError(t, r.registration.RegisterToken(sp279Creator("OTHER-abcdef", total)))
	_, outputs, err := r.boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 2, "the refused registration released nothing")
	require.Equal(t, uint64(123), outputs[0].GasRemaining)
	require.Zero(t, outputs[1].GasRemaining)
	for ordinal, output := range outputs {
		deltas := sp279Deltas(t, output)
		require.Len(t, deltas, int(shards))
		carried := uint64(0)
		for _, delta := range deltas {
			require.Equal(t, leg, delta.GasLimit)
			require.Equal(t, vmData.AsynchronousCall, delta.CallType)
			carried += delta.GasLimit
		}
		given := []uint64{total + 123, total}[ordinal]
		require.Equal(t, given, output.GasRemaining+carried+sp279Delta.Source, "returned, carried and source work are the whole gas")
	}
	s := r.state(RegistryDeltaCarrierClass, string(registryDeltaEffect([]byte("TOKEN-abcdef"), 0)))
	require.Equal(t, CarrierOpen, s.Phase)
	require.Equal(t, sp279Delta, s.Price)
	require.Equal(t, shards, s.Legs)
	require.Equal(t, []byte{1}, qualRegistryValue(t, r.store, registryMemberKeyPrefix+"TOKEN-abcdef"))
}

func TestQualSP279RegistrationWithoutAPriceIsRefused(t *testing.T) {
	r := sp279NewRegistry(t, 3)
	require.NoError(t, r.registration.SetCarrierFunding(r.funding))
	root := r.root()
	// A leg that would carry no gas is never acknowledged (SP2-22): refused.
	r.notifier.change(sp279Schedule(map[string]CarrierPrice{RegistryDeltaCarrierClass: {Source: 10}}))
	require.ErrorIs(t, r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", ^uint64(0))), ErrInvalidRegistryRegistration)
	// No price under the active schedule.
	r.notifier.change(map[string]map[string]uint64{})
	require.ErrorIs(t, r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", ^uint64(0))), ErrCarrierFunding)
	require.Equal(t, root, r.root())
	_, outputs, err := r.boundary.Commit()
	require.NoError(t, err)
	require.Empty(t, outputs)
}

func TestQualSP279FundingNamesTheGasWhenTheMetachainHalfIsInstalled(t *testing.T) {
	r := sp279NewRegistry(t, 2)
	effects := &sp222Effects{}
	require.NoError(t, r.registration.SetRegistrationEffects(effects))
	require.NoError(t, r.registration.SetCarrierFunding(r.funding))
	total := sp279Total(sp279Delta, 2)
	require.NoError(t, r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", total)))
	_, outputs, err := r.boundary.Commit()
	require.NoError(t, err)
	deltas := sp279Deltas(t, outputs[0])
	require.Len(t, deltas, 2)
	for _, delta := range deltas {
		require.Equal(t, sp279Leg(sp279Delta), delta.GasLimit, "the funded amount, not the amount the metachain half names")
	}
	require.Len(t, effects.calls, 1, "the creator's own result is still withheld")

	// Without a funding owner the registration is as SP2-22 built it.
	plain := sp279NewRegistry(t, 2)
	require.NoError(t, plain.registration.SetRegistrationEffects(&sp222Effects{}))
	require.NoError(t, plain.registration.RegisterToken(sp279Creator("TOKEN-abcdef", 5)))
	_, outputs, err = plain.boundary.Commit()
	require.NoError(t, err)
	require.Equal(t, uint64(5), outputs[0].GasRemaining)
	for _, delta := range sp279Deltas(t, outputs[0]) {
		require.Equal(t, uint64(700), delta.GasLimit)
	}
	require.Nil(t, plain.state(RegistryDeltaCarrierClass, string(registryDeltaEffect([]byte("TOKEN-abcdef"), 0))))
}

func TestQualSP279AcknowledgmentAndRedriveOfTheRegistryDelta(t *testing.T) {
	const shards = uint32(3)
	r := sp279NewRegistry(t, shards)
	require.NoError(t, r.registration.SetCarrierFunding(r.funding))
	require.NoError(t, r.registration.RegisterToken(sp279Creator("TOKEN-abcdef", sp279Total(sp279Delta, shards))))
	_, outputs, err := r.boundary.Commit()
	require.NoError(t, err)
	first := sp279Deltas(t, outputs[0])
	member := string(registryDeltaEffect([]byte("TOKEN-abcdef"), 0))
	returned := sp279Delta.Success + sp279Delta.Completion // the delta uses no gas

	// Shard 1 acknowledges.
	acknowledgment, result, err := r.funding.AcknowledgeRegistryDelta(sp279Callback("TOKEN-abcdef", 0, 1, returned), shards)
	require.NoError(t, err)
	require.Equal(t, &RegistryAcknowledgment{Shard: 1, TokenID: []byte("TOKEN-abcdef"), Ordinal: 0}, acknowledgment)
	require.Equal(t, CarrierOutcomeResult{Applied: true, Completion: sp279Delta.Completion, Remaining: sp279Delta.Success}, result)
	// The same acknowledgment again: nothing.
	_, result, err = r.funding.AcknowledgeRegistryDelta(sp279Callback("TOKEN-abcdef", 0, 1, returned), shards)
	require.NoError(t, err)
	require.False(t, result.Applied)

	refused := map[string]*vmcommon.ContractCallInput{
		"a member that was never funded":       sp279Callback("OTHER-abcdef", 0, 0, returned),
		"another ordinal of the member":        sp279Callback("TOKEN-abcdef", 1, 0, returned),
		"less gas than the retained work":      sp279Callback("TOKEN-abcdef", 0, 0, sp279Delta.Completion-1),
		"a shard the network does not have":    sp279Callback("TOKEN-abcdef", 0, 3, returned),
		"the callback of a refused delta":      sp279Callback("TOKEN-abcdef", 0, 0, returned),
		"a call that is not a callback at all": sp279Callback("TOKEN-abcdef", 0, 0, returned),
	}
	refused["the callback of a refused delta"].Arguments[0] = []byte{byte(vmcommon.UserError)}
	refused["a call that is not a callback at all"].CallType = vmData.DirectCall
	for label, input := range refused {
		r.unchanged(label, nil, func() error {
			_, _, ackErr := r.funding.AcknowledgeRegistryDelta(input, shards)
			return ackErr
		})
	}
	require.False(t, r.state(RegistryDeltaCarrierClass, member).HasOutcome(0))

	// Shard 0 did not acknowledge. After a restart and a delay the same delta
	// is funded again, at the retained entries although the schedule changed.
	r.notifier.change(sp279Schedule(map[string]CarrierPrice{RegistryDeltaCarrierClass: sp279New}))
	r.block.epoch += 50
	r.restart()
	cost := sp279Delta.Source + sp279Leg(sp279Delta)
	redrive := func(output *vmcommon.VMOutput, token string, ordinal uint64, shard uint32, available uint64) func() error {
		return func() error {
			_, redriveErr := r.funding.RedriveRegistryDelta(output, []byte(token), ordinal, shard, shards, available)
			return redriveErr
		}
	}
	empty := func() *vmcommon.VMOutput { return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok} }
	r.unchanged("one unit short", ErrCarrierUnderfunded, redrive(empty(), "TOKEN-abcdef", 0, 0, cost-1))
	r.unchanged("the acknowledged shard", ErrCarrierFunding, redrive(empty(), "TOKEN-abcdef", 0, 1, cost))
	r.unchanged("a member that was never funded", ErrCarrierFunding, redrive(empty(), "OTHER-abcdef", 1, 0, cost))
	r.unchanged("a shard the network does not have", ErrInvalidRegistryDelta, redrive(empty(), "TOKEN-abcdef", 0, 3, cost))
	r.unchanged("not a token identifier", ErrInvalidRegistryDelta, redrive(empty(), "token", 0, 0, cost))
	r.unchanged("no output", ErrInvalidRegistryDelta, redrive(nil, "TOKEN-abcdef", 0, 0, cost))
	r.unchanged("more shards than a delivery can name", ErrInvalidRegistryDelta, func() error {
		_, redriveErr := r.funding.RedriveRegistryDelta(empty(), []byte("TOKEN-abcdef"), 0, 0, 256, cost)
		return redriveErr
	})
	r.unchanged("a nil output account", ErrInvalidRegistryDelta, redrive(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": nil}}, "TOKEN-abcdef", 0, 0, cost))
	full := &vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x"),
		OutputTransfers: []vmcommon.OutputTransfer{{Index: ^uint32(0)}}}}}
	r.unchanged("no result index left", ErrInvalidRegistryDelta, redrive(full, "TOKEN-abcdef", 0, 0, cost))

	// The redriving operation already has a result of its own for shard 0's
	// system account: the delta goes behind the last of them.
	address := registryDeltaSystemAddress(0)
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{
		string(address): {Address: address, BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{
			{Index: 2, Data: []byte("own")}, {Index: 4, Data: []byte("own, later")}, {Index: 3, Data: []byte("own, between")}}}}}
	remaining, err := r.funding.RedriveRegistryDelta(output, []byte("TOKEN-abcdef"), 0, 0, shards, cost+9)
	require.NoError(t, err)
	require.Equal(t, uint64(9), remaining)
	again := sp279Deltas(t, output)
	require.Len(t, again, 1)
	expected := first[0]
	expected.Index = 5
	require.Equal(t, expected, again[0], "the same delivery: data, identifiers, sender, call type and the retained gas")
	require.Len(t, output.OutputAccounts[string(address)].OutputTransfers, 4)
	// Into an output with no accounts yet.
	output = empty()
	_, err = r.funding.RedriveRegistryDelta(output, []byte("TOKEN-abcdef"), 0, 0, shards, cost)
	require.NoError(t, err)
	expected.Index = 0
	require.Equal(t, expected, sp279Deltas(t, output)[0])
	require.Equal(t, uint64(2), r.state(RegistryDeltaCarrierClass, member).Redrives)

	// Both deliveries are acknowledged: one outcome for shard 0.
	_, result, err = r.funding.AcknowledgeRegistryDelta(sp279Callback("TOKEN-abcdef", 0, 0, returned), shards)
	require.NoError(t, err)
	require.True(t, result.Applied)
	_, result, err = r.funding.AcknowledgeRegistryDelta(sp279Callback("TOKEN-abcdef", 0, 0, returned), shards)
	require.NoError(t, err)
	require.False(t, result.Applied)
	_, result, err = r.funding.AcknowledgeRegistryDelta(sp279Callback("TOKEN-abcdef", 0, 2, returned), shards)
	require.NoError(t, err)
	require.True(t, result.Terminal)
	r.unchanged("redrive of a complete member", ErrCarrierFunding, redrive(empty(), "TOKEN-abcdef", 0, 2, cost))

	// A leg priced with no gas cannot be redriven either.
	free := sp279NewRegistry(t, 1)
	free.notifier.change(sp279Schedule(map[string]CarrierPrice{RegistryDeltaCarrierClass: {Source: 10}}))
	_, err = free.funding.Accept(RegistryDeltaCarrierClass, registryDeltaEffect([]byte("TOKEN-abcdef"), 0), 1, 10)
	require.NoError(t, err)
	_, err = free.funding.RedriveRegistryDelta(empty(), []byte("TOKEN-abcdef"), 0, 0, 1, 10)
	require.ErrorIs(t, err, ErrInvalidRegistryDelta)
}

func TestQualSP279MetaClassificationInstallsFundingInEveryCandidate(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	// The fixture's coordinator has no execution shard; a network has.
	f.owner.coordinator = &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: core.MetachainShardId}
	w := sp279World_(t, sp223Ample(), map[string]CarrierPrice{RegistryDeltaCarrierClass: sp279Delta})
	budget := qualRegistryValue(t, w.store, sp223BudgetKey)
	account, err := f.user.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(sp223BudgetKey), budget))
	require.NoError(t, f.user.SaveAccount(account))
	f.commit(t)
	funding, err := NewCarrierFunding(ArgsCarrierFunding{Accounts: f.user, Marshaller: w.funding.args.Marshaller, Hasher: w.hasher,
		Block: w.block, Prices: w.prices, Limits: sp223Ample(), RecordBytes: 4096})
	require.NoError(t, err)

	require.ErrorIs(t, f.owner.SetRegistrationCarrierFunding(nil), ErrInvalidRegistryRegistration)
	require.ErrorIs(t, f.owner.SetRegistrationCarrierFunding(w.funding), ErrInvalidRegistryRegistration, "the funding owner of another store")
	require.NoError(t, f.owner.BeginExecution())
	require.NoError(t, f.owner.SetRegistrationCarrierFunding(funding))
	require.ErrorIs(t, f.owner.SetRegistrationCarrierFunding(funding), ErrInvalidRegistryRegistration, "installed once")
	require.Same(t, funding, f.owner.current.writer.funding, "the open candidate")

	// The fixture's creator returns no gas: the registration cannot pay.
	require.ErrorIs(t, f.owner.current.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")), ErrCarrierUnderfunded)
	f.commit(t)
	require.NoError(t, f.owner.BeginExecution())
	require.Same(t, funding, f.owner.current.writer.funding, "every later candidate")
	regulated, err := f.owner.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.False(t, regulated)

	// Installed before the first block as well.
	early := qualSP225NewMeta(t, true)
	earlyFunding, err := NewCarrierFunding(ArgsCarrierFunding{Accounts: early.user, Marshaller: w.funding.args.Marshaller, Hasher: w.hasher,
		Block: w.block, Prices: w.prices, Limits: sp223Ample(), RecordBytes: 4096})
	require.NoError(t, err)
	require.NoError(t, early.owner.SetRegistrationCarrierFunding(earlyFunding))
	require.NoError(t, early.owner.BeginExecution())
	require.Same(t, earlyFunding, early.owner.current.writer.funding)
}

// The two fail-closed duties of the row's Notes cell name two upstream
// functions whose error is not visible to their caller: vmContext.GetBalance
// (a failed account read reads as a zero balance) and
// ExecuteSyncCallbackAndFinishOutput (a callback-input gas error is
// discarded). A DRWA path of this row that used either would have to treat
// that failure as deny. No path of this row uses either: funding reads no
// balance and runs no synchronous callback. This test keeps it so.
// sp279FundingUsers is the closed set of product files that name the funding
// owner, each with the reason it is admitted. The criterion, stated once: a
// file is admitted when it is the funding owner or its pricing; or when it is
// a protected carrier, which means that every path into its use of the owner
// is a protected metachain operation or a call the file admits only from the
// metachain ESDT system contract, so that no ordinary (non-DRWA) path reaches
// it; or when it only constructs or installs such an owner at node
// construction. Every admitted file is also checked for the two blurred
// upstream functions. A later row whose carrier uses the owner adds its
// files here with its reason; nothing else about the check changes.
var sp279FundingUsers = map[string]string{
	"carrierFunding.go":                              "the funding owner",
	"carrierPricing.go":                              "its pricing source",
	"registryCarrierFunding.go":                      "SP2-79: acknowledgment and redrive of the registry delta",
	"registryRegistration.go":                        "SP2-79: funding of the registry delta inside the protected registration",
	"nativeClassification.go":                        "SP2-79: hands the installed owner to the registration writer",
	"adminEffectOrigin.go":                           "SP2-32: funds an OpenEffect's legs, outcomes and redrive; callers are protected metachain operations",
	"adminEffectDestination.go":                      "SP2-32: pure CarrierDestinationGas inside a call admitted only from the metachain ESDT system contract",
	"lifecycleSealOrigin.go":                         "SP2-37: funds the replication of the setup seal, its outcomes and redrive; callers are the protected setup operations",
	"burnForAllReadiness.go":                         "SP2-33: opens its effects only through the admin-effect carrier, checks their whole price before its first write and reads each effect's funding record; callers are the protected registration and the completion of a convergence phase",
	"../../factory/processing/drwaFinalityImport.go": "node construction of the metachain owners",
	"../../factory/processing/drwaBurnReadiness.go":  "SP2-33: node construction of the readiness owner",
	"../../factory/processing/drwaLifecycleSeal.go":  "SP2-37: node construction of the seal's replication owner",
}

func TestQualSP279NoPathOfThisRowUsesTheTwoBlurredUpstreamFunctions(t *testing.T) {
	blurred := regexp.MustCompile(`\bGetBalance\(|ExecuteSyncCallbackAndFinishOutput|executeSyncCallback`)
	checked := []string{"outcomeGasReservation.go", "replicationWorkReservation.go", "shardRegistry.go"}
	for file := range sp279FundingUsers {
		checked = append(checked, file)
	}
	for _, file := range checked {
		source, err := os.ReadFile(file)
		require.NoError(t, err)
		require.False(t, blurred.Match(source), file)
	}
	// And the funding owner is named only by the admitted files: no ordinary
	// path names it.
	callers := map[string]bool{}
	for _, root := range []string{".", "../smartContract", "../transaction", "../block", "../coordinator", "../../vm", "../../factory", "../../node", "../../genesis"} {
		require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			source, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if regexp.MustCompile(`CarrierFunding|CarrierPric|CarrierDestinationGas`).Match(source) {
				callers[filepath.Clean(path)] = true
			}
			return nil
		}))
	}
	admitted := map[string]bool{}
	for file, reason := range sp279FundingUsers {
		require.NotEmpty(t, reason, file)
		admitted[filepath.Clean(file)] = true
	}
	require.Equal(t, admitted, callers)
}
