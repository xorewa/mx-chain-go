package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 DEVELOPMENT only. Canonical projection/current-binding/funding/proof/ACK
// are SYNTHETIC host contracts, not actual G3/native token integration. The
// effect is an explicit native account balance fixture, not a regulated debit.
// Actual AccountsDB/trie/journal/save/recreation and T04 output retention run.
type qualSourceGrantHost struct {
	t                                        *testing.T
	store                                    *qualNativeStore
	projection, key, effect                  []byte
	faults                                   map[string]error
	hooks                                    map[string]func()
	verifyCalls, admissionCalls, effectCalls int
	ackCalls                                 int
	nilEffect, deniedEffect, deniedAck       bool
	invalidEffectIdentity                    bool
}

func (h *qualSourceGrantHost) IsInterfaceNil() bool { return h == nil }
func (h *qualSourceGrantHost) check(stage string, projection []byte) error {
	if hook := h.hooks[stage]; hook != nil {
		hook()
	}
	if !bytes.Equal(projection, h.projection) {
		return errSourceGrant
	}
	return h.faults[stage]
}
func (h *qualSourceGrantHost) VerifyProjection(projection, evidence []byte) error {
	h.verifyCalls++
	if !bytes.Equal(evidence, []byte("synthetic-canonical-proof")) {
		return errSourceGrant
	}
	return h.check("verify", projection)
}
func (h *qualSourceGrantHost) ValidateAdmission(projection []byte, retained uint64) error {
	h.admissionCalls++
	h.t.Helper()
	require.Equal(h.t, uint64(len(h.key)+len(qualRecordFrame(h.projection, []byte("OPEN"), nil, nil))), retained)
	return h.check("admission", projection)
}
func (h *qualSourceGrantHost) ValidateConsume(projection []byte) error {
	return h.check("consume", projection)
}
func (h *qualSourceGrantHost) VerifyUnused(projection []byte, reason string, evidence []byte) error {
	if reason != "EXPIRED" && reason != "STALE_BINDING" || !bytes.Equal(evidence, []byte("synthetic-canonical-proof")) {
		return errSourceGrant
	}
	return h.check("unused", projection)
}
func (h *qualSourceGrantHost) Apply(projection []byte) ([]byte, *vmcommon.VMOutput, error) {
	h.effectCalls++
	if err := h.check("apply", projection); err != nil {
		return nil, nil, err
	}
	if err := qualContainmentBalance(h.store, 97); err != nil {
		return nil, nil, err
	}
	// Also mutate the same protected account to detect a stale-account overwrite.
	qualRecordPut(h.t, h.store, []byte("fixture/source-native-effect"), []byte("preserved"))
	if h.nilEffect {
		return bytes.Clone(h.effect), nil, nil
	}
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 44, GasRefund: big.NewInt(2),
		ReturnMessage: "native-effect", ReturnData: [][]byte{[]byte("native-return")},
		OutputAccounts: map[string]*vmcommon.OutputAccount{"native": {Address: bytes.Clone(qualContainmentAddress), BalanceDelta: big.NewInt(0)}},
		Logs:           []*vmcommon.LogEntry{{Identifier: []byte("native-log")}}}
	if h.deniedEffect {
		output.ReturnCode = vmcommon.UserError
	}
	if h.invalidEffectIdentity {
		return []byte{1}, output, nil
	}
	return bytes.Clone(h.effect), output, nil
}
func (h *qualSourceGrantHost) Ack(projection []byte, status, reason string, effect []byte, output *vmcommon.VMOutput) error {
	h.ackCalls++
	if err := h.check("ack", projection); err != nil {
		return err
	}
	// Independently check that the durable state was saved BEFORE ACK creation.
	expectedStatus := "CONSUMED"
	if status == "UNUSED" {
		expectedStatus = "CLOSED_UNUSED"
	}
	require.Equal(h.t, qualRecordFrame(h.projection, []byte(expectedStatus), []byte(reason), effect), qualRegistryValue(h.t, h.store, string(h.key)))
	output.ReturnData = append(output.ReturnData, []byte(status))
	if h.deniedAck {
		output.ReturnCode = vmcommon.UserError
	}
	return nil
}

type qualSourceGrantFixture struct {
	store     *qualNativeStore
	owner     *RollbackContainment
	records   *sourceGrantRecords
	clock     *qualUnboundHeaderTime
	context   *HeaderTimeContext
	p         sourceGrantProjection
	host      *qualSourceGrantHost
	key, body []byte
}

func qualSourceGrantNew(t *testing.T) *qualSourceGrantFixture {
	t.Helper()
	f := &qualSourceGrantFixture{store: qualRegistrationStore(t, 0), clock: qualHeaderTimeOwner(t)}
	f.p = sourceGrantProjection{token: []byte("TOKEN-abcdef"), source: bytes.Clone(qualContainmentAddress),
		action: bytes.Repeat([]byte{7}, 32), digest: bytes.Repeat([]byte{8}, 32), expiry: 112,
		body: []byte("synthetic complete frozen projection; no lawful G3/body/funding proof claimed")}
	f.key = append([]byte(sourceGrantPrefix), qualRecordFrame(f.p.token, f.p.source, f.p.action)...)
	f.body = qualRecordFrame(f.p.token, f.p.source, f.p.action, f.p.digest, []byte{0, 0, 0, 0, 0, 0, 0, 112}, f.p.body)
	f.host = &qualSourceGrantHost{t: t, store: f.store, projection: f.body, key: f.key,
		effect: bytes.Repeat([]byte{9}, 32), faults: make(map[string]error), hooks: make(map[string]func())}
	f.context = qualGovernedContext(t, f.clock, 1, 111)
	f.reopen(t, f.store)
	return f
}
func (f *qualSourceGrantFixture) reopen(t *testing.T, accounts state.AccountsAdapter) {
	t.Helper()
	var err error
	f.owner, err = NewRollbackContainment(accounts)
	require.NoError(t, err)
	f.records, err = newSourceGrantRecords(accounts, f.owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 1, f.host, qualClockSource(f.clock, accounts))
	require.NoError(t, err)
}
func (f *qualSourceGrantFixture) install(t *testing.T) {
	t.Helper()
	require.NoError(t, f.records.install(f.context, f.p, []byte("synthetic-canonical-proof")))
}
func (f *qualSourceGrantFixture) consume() error {
	return f.records.consume(f.context, f.p, []byte("synthetic-canonical-proof"))
}
func (f *qualSourceGrantFixture) close(reason string) error {
	return f.records.closeUnused(f.context, f.p, reason, []byte("synthetic-canonical-proof"))
}
func (f *qualSourceGrantFixture) assertState(t *testing.T, status, reason string, effect []byte) {
	t.Helper()
	require.Equal(t, qualRecordFrame(f.body, []byte(status), []byte(reason), effect), qualRegistryValue(t, f.store, string(f.key)))
}

func TestQualDRWASourceGrantConsumeAndRedrive(t *testing.T) {
	f := qualSourceGrantNew(t)
	f.install(t)
	journal := f.store.JournalLen()
	f.install(t)
	require.Equal(t, journal, f.store.JournalLen())
	require.Equal(t, 1, f.host.admissionCalls)
	require.NoError(t, f.consume())
	f.assertState(t, "CONSUMED", "", f.host.effect)
	qualAssertContainmentBalance(t, f.store, 97)
	require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, "fixture/source-native-effect"))
	journal = f.store.JournalLen()
	require.NoError(t, f.consume(), "same-window redrive cannot execute a second effect")
	require.Equal(t, journal, f.store.JournalLen())
	require.Equal(t, 1, f.host.effectCalls)
	f.context = qualGovernedContext(t, f.clock, 1, 113)
	require.NoError(t, f.consume(), "late redrive is not a new debit")
	require.Equal(t, 1, f.host.effectCalls)
	require.ErrorIs(t, f.close("EXPIRED"), errSourceGrant)
	f.install(t)
	f.assertState(t, "CONSUMED", "", f.host.effect)
	roots, outputs, err := f.owner.Commit()
	require.NoError(t, err)
	require.NotEmpty(t, roots)
	var first *vmcommon.VMOutput
	for _, output := range outputs {
		if output != nil && output.ReturnMessage == "native-effect" {
			first = output
		}
	}
	require.NotNil(t, first)
	require.Equal(t, uint64(44), first.GasRemaining)
	require.Equal(t, big.NewInt(2), first.GasRefund)
	require.Equal(t, [][]byte{[]byte("native-return"), []byte("STARTED")}, first.ReturnData)
	require.Equal(t, []byte("native-log"), first.Logs[0].Identifier)
	require.Equal(t, qualContainmentAddress, first.OutputAccounts["native"].Address)
}

func TestQualDRWASourceGrantExpiryAndClosure(t *testing.T) {
	for _, time := range []uint64{111, 112, 113} {
		t.Run(big.NewInt(int64(time)).String(), func(t *testing.T) {
			f := qualSourceGrantNew(t)
			f.install(t)
			f.context = qualGovernedContext(t, f.clock, 1, time)
			if time < 112 {
				require.ErrorIs(t, f.close("EXPIRED"), errSourceGrant)
				f.assertState(t, "OPEN", "", nil)
				return
			}
			require.ErrorIs(t, f.consume(), errSourceGrant)
			f.assertState(t, "OPEN", "", nil)
			fault := errors.New("no canonical non-consumption proof")
			f.host.faults["unused"] = fault
			require.ErrorIs(t, f.close("EXPIRED"), fault)
			f.assertState(t, "OPEN", "", nil)
			delete(f.host.faults, "unused")
			require.NoError(t, f.close("EXPIRED"))
			f.assertState(t, "CLOSED_UNUSED", "EXPIRED", nil)
			require.NoError(t, f.close("EXPIRED"))
			require.ErrorIs(t, f.close("STALE_BINDING"), errSourceGrant)
			f.context = qualGovernedContext(t, f.clock, 1, 111)
			require.ErrorIs(t, f.consume(), errSourceGrant, "hostile earlier request cannot reopen a retained closed grant")
			f.install(t)
			f.assertState(t, "CLOSED_UNUSED", "EXPIRED", nil)
			require.Zero(t, f.host.effectCalls)
			qualAssertContainmentBalance(t, f.store, 100)
		})
	}
	t.Run("stale_before_expiry", func(t *testing.T) {
		f := qualSourceGrantNew(t)
		f.install(t)
		require.NoError(t, f.close("STALE_BINDING"))
		f.assertState(t, "CLOSED_UNUSED", "STALE_BINDING", nil)
		require.ErrorIs(t, f.consume(), errSourceGrant)
	})
}

func TestQualDRWASourceGrantMissingAndConflictingState(t *testing.T) {
	for _, name := range []string{"absent", "corrupt", "empty_status", "open_with_effect", "consumed_without_effect", "closed_wrong_reason", "wrong_body", "wrong_expiry", "wrong_digest", "wrong_token", "wrong_source", "wrong_action"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			if name != "absent" {
				f.install(t)
			}
			switch name {
			case "corrupt":
				qualRecordPut(t, f.store, f.key, []byte("corrupt"))
			case "empty_status":
				qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, nil, nil, nil))
			case "open_with_effect":
				qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, []byte("OPEN"), nil, f.host.effect))
			case "consumed_without_effect":
				qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, []byte("CONSUMED"), nil, nil))
			case "closed_wrong_reason":
				qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, []byte("CLOSED_UNUSED"), []byte("timeout"), nil))
			case "wrong_body":
				f.p.body = []byte("another immutable body")
			case "wrong_expiry":
				f.p.expiry = 113
			case "wrong_digest":
				f.p.digest = bytes.Repeat([]byte{5}, 32)
			case "wrong_token":
				f.p.token = []byte("OTHER-abcdef")
			case "wrong_source":
				f.p.source = bytes.Repeat([]byte{5}, 32)
			case "wrong_action":
				f.p.action = bytes.Repeat([]byte{5}, 32)
			}
			require.Error(t, f.consume())
			require.Error(t, f.close("STALE_BINDING"))
			require.Zero(t, f.host.effectCalls)
		})
	}
	t.Run("conflicting_import", func(t *testing.T) {
		f := qualSourceGrantNew(t)
		f.install(t)
		f.p.body = []byte("another body under the same identity")
		// Both bodies have synthetic provenance here: isolate stored equality.
		f.host.projection = qualRecordFrame(f.p.token, f.p.source, f.p.action, f.p.digest, []byte{0, 0, 0, 0, 0, 0, 0, 112}, f.p.body)
		require.ErrorIs(t, f.records.install(f.context, f.p, []byte("synthetic-canonical-proof")), errSourceGrant)
		f.assertState(t, "OPEN", "", nil)
	})
}

func TestQualDRWASourceGrantContextAndBounds(t *testing.T) {
	for _, name := range []string{"nil", "reset", "wrong_source", "meta", "verify_invalidates", "admission_invalidates", "consume_invalidates", "unused_invalidates", "oversized_body", "oversized_proof", "small_record_bound", "invalid_reason"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			if name != "verify_invalidates" && name != "admission_invalidates" {
				f.install(t)
			}
			switch name {
			case "nil":
				f.context = nil
			case "reset":
				f.clock.Reset()
			case "wrong_source":
				f.context = qualGovernedContext(t, f.clock, 2, 111)
			case "meta":
				f.context = qualGovernedContext(t, f.clock, core.MetachainShardId, 111)
			case "verify_invalidates", "admission_invalidates":
				stage := "verify"
				if name == "admission_invalidates" {
					stage = "admission"
				}
				f.host.hooks[stage] = f.clock.Reset
				require.ErrorIs(t, f.records.install(f.context, f.p, []byte("synthetic-canonical-proof")), ErrInactiveHeaderTime)
				return
			case "consume_invalidates":
				f.host.hooks["consume"] = f.clock.Reset
			case "unused_invalidates":
				f.host.hooks["unused"] = f.clock.Reset
				require.ErrorIs(t, f.close("STALE_BINDING"), ErrInactiveHeaderTime)
				f.assertState(t, "OPEN", "", nil)
				return
			case "oversized_body":
				f.p.body = make([]byte, 4097)
			case "oversized_proof":
				calls := f.host.verifyCalls
				require.ErrorIs(t, f.records.consume(f.context, f.p, make([]byte, 4097)), errSourceGrant)
				require.Equal(t, calls, f.host.verifyCalls)
				return
			case "small_record_bound":
				f.records.codec.maxBytes = len(f.body)
			case "invalid_reason":
				require.ErrorIs(t, f.close("TIMEOUT"), errSourceGrant)
				return
			}
			require.Error(t, f.consume())
			require.Zero(t, f.host.effectCalls)
		})
	}
}

func TestQualDRWASourceGrantRollback(t *testing.T) {
	for _, name := range []string{"verify", "consume", "apply", "ack", "nil_effect", "denied_effect", "denied_ack", "wrong_effect_identity", "key_save", "account_save", "rollback_failure", "unselected_key_control"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			f.install(t)
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			original := errors.New("selected owning-stage failure")
			accounts := state.AccountsAdapter(f.store)
			switch name {
			case "nil_effect":
				f.host.nilEffect = true
			case "denied_effect":
				f.host.deniedEffect = true
			case "denied_ack":
				f.host.deniedAck = true
			case "wrong_effect_identity":
				f.host.invalidEffectIdentity = true
			case "key_save", "unselected_key_control":
				key := f.key
				if name == "unselected_key_control" {
					key = []byte("not-the-grant-key")
				}
				accounts = &qualAdminKeyFault{&qualScopedAccountFault{f.store, key, original}}
			case "account_save":
				accounts = &qualAdminNthSave{AccountsAdapter: f.store, failAt: 1, fault: original}
			case "rollback_failure":
				f.host.faults["ack"] = original
				f.store.revertErr = errors.New("native rollback failed")
			default:
				f.host.faults[name] = original
			}
			f.reopen(t, accounts)
			err = f.consume()
			if name == "unselected_key_control" {
				require.NoError(t, err)
				f.assertState(t, "CONSUMED", "", f.host.effect)
				qualAssertContainmentBalance(t, f.store, 97)
				return
			}
			if name == "nil_effect" || name == "denied_effect" || name == "denied_ack" || name == "wrong_effect_identity" {
				require.ErrorIs(t, err, errSourceGrant)
			} else {
				require.ErrorIs(t, err, original)
			}
			if name == "rollback_failure" {
				require.ErrorIs(t, err, f.store.revertErr)
				_, output, commitErr := f.owner.Commit()
				require.Error(t, commitErr)
				require.Empty(t, output)
				f.store.revertErr = nil
				require.NoError(t, f.owner.Recover())
			}
			f.assertState(t, "OPEN", "", nil)
			qualAssertContainmentBalance(t, f.store, 100)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, roots[0], after)
		})
	}
}

func TestQualDRWASourceGrantPersistenceAndOrders(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		name := "consume_first"
		if closeFirst {
			name = "close_first"
		}
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			f.install(t)
			if closeFirst {
				require.NoError(t, f.close("STALE_BINDING"))
				require.ErrorIs(t, f.consume(), errSourceGrant)
			} else {
				require.NoError(t, f.consume())
				require.ErrorIs(t, f.close("STALE_BINDING"), errSourceGrant)
			}
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			f.reopen(t, f.store)
			f.install(t)
			if closeFirst {
				f.assertState(t, "CLOSED_UNUSED", "STALE_BINDING", nil)
				require.ErrorIs(t, f.consume(), errSourceGrant)
			} else {
				f.assertState(t, "CONSUMED", "", f.host.effect)
				require.ErrorIs(t, f.close("EXPIRED"), errSourceGrant)
			}
		})
	}
}

func TestQualDRWASourceGrantConcurrentWriters(t *testing.T) {
	f := qualSourceGrantNew(t)
	f.install(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	// Synthetic host permits both validations to isolate storage serialization,
	// not to claim consume and stale-proof predicates can lawfully coexist.
	for _, op := range []func() error{f.consume, func() error { return f.close("STALE_BINDING") }} {
		wg.Add(1)
		go func(op func() error) { defer wg.Done(); results <- op() }(op)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.True(t, errors.Is(err, ErrExecutionBusy) || errors.Is(err, errSourceGrant))
		}
	}
	require.Equal(t, 1, successes)
	status, _, _, err := f.records.load(f.key, f.body)
	require.NoError(t, err)
	require.True(t, status == "CONSUMED" || status == "CLOSED_UNUSED")
}

func TestQualDRWASourceGrantClosureRollback(t *testing.T) {
	for _, name := range []string{"unused", "ack", "key_save", "account_save", "denied_ack"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			f.install(t)
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			original := errors.New("closure owning-stage failure")
			accounts := state.AccountsAdapter(f.store)
			switch name {
			case "key_save":
				accounts = &qualAdminKeyFault{&qualScopedAccountFault{f.store, f.key, original}}
			case "account_save":
				accounts = &qualAdminNthSave{AccountsAdapter: f.store, failAt: 1, fault: original}
			case "denied_ack":
				f.host.deniedAck = true
			default:
				f.host.faults[name] = original
			}
			f.reopen(t, accounts)
			f.context = qualGovernedContext(t, f.clock, 1, 112)
			err = f.close("EXPIRED")
			if name == "denied_ack" {
				require.ErrorIs(t, err, errSourceGrant)
			} else {
				require.ErrorIs(t, err, original)
			}
			f.assertState(t, "OPEN", "", nil)
			qualAssertContainmentBalance(t, f.store, 100)
			after, rootErr := f.store.RootHash()
			require.NoError(t, rootErr)
			require.Equal(t, roots[0], after)
			_, output, commitErr := f.owner.Commit()
			require.NoError(t, commitErr)
			require.Empty(t, output, "failed closure releases no unused ACK")
		})
	}
}

func TestQualDRWASourceGrantAdmissionAndDependencies(t *testing.T) {
	f := qualSourceGrantNew(t)
	for _, name := range []string{"nil_host", "nil_owner", "wrong_store", "meta_shard"} {
		t.Run(name, func(t *testing.T) {
			accounts, owner, host, shard := state.AccountsAdapter(f.store), f.owner, sourceGrantHost(f.host), uint32(1)
			switch name {
			case "nil_host":
				host = nil
			case "nil_owner":
				owner = nil
			case "wrong_store":
				accounts = qualRegistrationStore(t, 0)
			case "meta_shard":
				shard = core.MetachainShardId
			}
			got, err := newSourceGrantRecords(accounts, owner, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, shard, host, qualClockSource(f.clock, accounts))
			require.ErrorIs(t, err, errSourceGrant)
			require.Nil(t, got)
		})
	}
	t.Run("admission_denied", func(t *testing.T) {
		f := qualSourceGrantNew(t)
		fault := errors.New("aggregate admission denied")
		f.host.faults["admission"] = fault
		require.ErrorIs(t, f.records.install(f.context, f.p, []byte("synthetic-canonical-proof")), fault)
		require.Empty(t, qualRegistryValue(t, f.store, string(f.key)))
	})
}
