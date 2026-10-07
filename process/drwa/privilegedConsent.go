package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// ExperimentalPrivilegedConsentEndpoint and the key/encoding below are DRWA-
// defined experimental candidates, NOT production allocations (Part B L346).
// Ledger L29 adopts the action, not these choices. No dispatcher installs it.
const ExperimentalPrivilegedConsentEndpoint = "DRWAPrivilegedConsentCandidate"

var (
	ErrPrivilegedConsent             = errors.New("invalid DRWA privileged consent candidate")
	experimentalPrivilegedConsentKey = []byte(core.ProtectedKeyPrefix + "drwa/experimental/privileged-consent")
)

// PrivilegedConsentScope is an experimental exact tuple, not a CEB codec.
// Roles contains the owning caller's canonical bound-role encoding; selecting
// that encoding and proving possession/programme approvals are separate gates.
type PrivilegedConsentScope struct {
	Domain, Token, Program, Target, Roles, Address []byte
}

// PrivilegedConsentCandidate is an unwired native builtin candidate. The native
// interceptor and transaction processor MUST authenticate the transaction before
// dispatch. No detached signature, caller bool or guardian snapshot is accepted.
// Its owner supplies exclusive AccountsAdapter/containment ownership, selected
// executing epoch and explicit experimental resource bounds. The outer owner
// must refuse proposal commit/output publication when containment fails, even
// if native error processing later returns UserError/nil (T04 contract).
// Native failed-transaction nonce/fees remain outside this operation's snapshot.
// A single protected account slot bounds retained record cardinality per EOA;
// newer consent replaces older scope. This retention choice needs owner review.
type PrivilegedConsentCandidate struct {
	mut                          sync.Mutex
	accounts                     state.AccountsAdapter
	containment                  *RollbackContainment
	domain                       []byte
	addressLength, maxFieldBytes int
	reserved                     [][]byte
	epoch                        func() uint32
	gas                          uint64
	executing                    bool
	expectedHash                 []byte
	pendingAccount               state.UserAccountHandler
	pendingRecord                []byte
	pendingOutput                *vmcommon.VMOutput
}

func NewPrivilegedConsentCandidate(accounts state.AccountsAdapter, containment *RollbackContainment,
	domain []byte, addressLength, maxFieldBytes int, reserved [][]byte, epoch func() uint32, gas uint64) (*PrivilegedConsentCandidate, error) {
	if check.IfNil(accounts) || containment == nil || len(domain) == 0 || addressLength <= core.NumInitCharactersForScAddress ||
		len(domain) > maxFieldBytes || epoch == nil || gas == 0 {
		return nil, ErrPrivilegedConsent
	}
	r := &PrivilegedConsentCandidate{accounts: accounts, containment: containment, domain: bytes.Clone(domain),
		addressLength: addressLength, maxFieldBytes: maxFieldBytes, epoch: epoch, gas: gas}
	for _, address := range reserved {
		r.reserved = append(r.reserved, bytes.Clone(address))
	}
	return r, nil
}

func (c *PrivilegedConsentCandidate) validAddress(address []byte) bool {
	if len(address) != c.addressLength || core.IsSmartContractAddress(address) || core.IsSystemAccountAddress(address) {
		return false
	}
	for _, reserved := range c.reserved {
		if bytes.Equal(address, reserved) {
			return false
		}
	}
	return true
}

func (c *PrivilegedConsentCandidate) scope(input *vmcommon.ContractCallInput) (PrivilegedConsentScope, error) {
	if len(input.Arguments) != 6 {
		return PrivilegedConsentScope{}, ErrPrivilegedConsent
	}
	for _, field := range input.Arguments {
		if len(field) == 0 || len(field) > c.maxFieldBytes {
			return PrivilegedConsentScope{}, ErrPrivilegedConsent
		}
	}
	s := PrivilegedConsentScope{input.Arguments[0], input.Arguments[1], input.Arguments[2], input.Arguments[3], input.Arguments[4], input.Arguments[5]}
	if !bytes.Equal(s.Domain, c.domain) || !bytes.Equal(s.Address, input.CallerAddr) || !c.validAddress(s.Address) {
		return PrivilegedConsentScope{}, ErrPrivilegedConsent
	}
	return s, nil
}

// ProcessBuiltinFunction uses native dispatch, data storage and T04 journals.
// It adds NO guardian predicate. A guarded or unguarded EOA is authenticated by
// the unchanged native pipeline according to its own rules (GU-01 L1976-1993).
// Direct calls are self-calls, with no value/token effect and no asynchronous
// continuation. Freshness uses generic native nonce + executing epoch, not a
// guardian event/DRWA control epoch; this conservative candidate needs review.
func (c *PrivilegedConsentCandidate) ProcessBuiltinFunction(sender, _ vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	c.mut.Lock()
	defer c.mut.Unlock()
	if check.IfNil(sender) || input == nil {
		return nil, ErrPrivilegedConsent
	}
	if !c.executing || !bytes.Equal(input.CurrentTxHash, c.expectedHash) || c.pendingAccount != nil {
		return nil, ErrPrivilegedConsent
	}
	if input.Function != ExperimentalPrivilegedConsentEndpoint || input.CallType != vm.DirectCall ||
		!bytes.Equal(sender.AddressBytes(), input.CallerAddr) || !bytes.Equal(input.CallerAddr, input.RecipientAddr) ||
		input.CallValue == nil || input.CallValue.Sign() != 0 || len(input.ESDTTransfers) != 0 ||
		input.ReturnCallAfterError || input.GasLocked != 0 {
		return nil, ErrPrivilegedConsent
	}
	if input.GasProvided < c.gas {
		return nil, builtInFunctions.ErrNotEnoughGas
	}
	s, err := c.scope(input)
	if err != nil {
		return nil, err
	}
	// Actual native code hash is inspected. Address classification alone is NOT
	// substituted for the still-unproved whole-state-origin invariant (A L2615).
	if len(sender.GetCodeHash()) != 0 {
		return nil, ErrPrivilegedConsent
	}
	account, ok := sender.(state.UserAccountHandler)
	if !ok {
		return nil, ErrPrivilegedConsent
	}
	// Native SetCode stages code before AccountsDB.saveCode assigns CodeHash.
	// Reject that pending state too (Part A L2606-2618); the exported state
	// account interface omits GetCode, so require its concrete native method
	// explicitly and fail closed when unavailable.
	codeAccount, hasNativeCode := sender.(interface{ GetCode() []byte })
	if !hasNativeCode || len(codeAccount.GetCode()) != 0 {
		return nil, ErrPrivilegedConsent
	}
	record := encodeExperimentalConsent(s, sender.GetNonce(), c.epoch())
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: input.GasProvided - c.gas}
	// Stage only. Native processing can still fail after this return; it must
	// finish successfully before any authenticated consent slot is written.
	c.pendingAccount, c.pendingRecord, c.pendingOutput = account, record, output
	return output, nil
}

// ExecuteNativeTransaction surrounds real native processing and final consent
// persistence with T04. The transaction MUST already have passed the native
// interceptor; signature verification is not reimplemented here. processor,
// codec and hasher are the selected native pipeline dependencies. This method
// accepts no success bool, detached signature or callback claiming execution.
// Ordinary transactions never call it. Native failure returns its original
// code/error and retains native fee/nonce effects, without a new consent record.
// A persistence/containment failure aborts the outer candidate; speculative
// native logs/fees/outputs may not be independently published by its owner.
func (c *PrivilegedConsentCandidate) ExecuteNativeTransaction(tx *transaction.Transaction,
	processor process.TransactionProcessor, codec marshal.Marshalizer, hasher hashing.Hasher) (vmcommon.ReturnCode, error) {
	if tx == nil || check.IfNil(processor) ||
		!bytes.HasPrefix(tx.Data, []byte(ExperimentalPrivilegedConsentEndpoint+"@")) {
		return vmcommon.UserError, ErrPrivilegedConsent
	}
	hash, err := core.CalculateHash(codec, hasher, tx)
	if err != nil {
		return vmcommon.UserError, err
	}
	c.mut.Lock()
	if c.executing {
		c.mut.Unlock()
		return vmcommon.UserError, ErrExecutionBusy
	}
	c.executing = true
	c.expectedHash = bytes.Clone(hash)
	c.mut.Unlock()
	defer func() {
		c.mut.Lock()
		c.executing = false
		c.expectedHash = nil
		c.pendingAccount = nil
		c.pendingRecord = nil
		c.pendingOutput = nil
		c.mut.Unlock()
	}()
	var code vmcommon.ReturnCode
	var nativeErr error
	err = c.containment.Execute(func() (*vmcommon.VMOutput, error) {
		code, nativeErr = processor.ProcessTransaction(tx)
		if nativeErr != nil || code != vmcommon.Ok {
			return nil, nil
		}
		c.mut.Lock()
		defer c.mut.Unlock()
		if c.pendingAccount == nil {
			return nil, ErrPrivilegedConsent
		}
		// Native execution can reload/refund the sender after builtin dispatch.
		// Never save the earlier staged object over those completed native fields.
		finalAccount, loadErr := c.accounts.GetExistingAccount(c.pendingAccount.AddressBytes())
		if loadErr != nil {
			return nil, loadErr
		}
		current, ok := finalAccount.(state.UserAccountHandler)
		if !ok || current.GetNonce() != c.pendingAccount.GetNonce() || len(current.GetCodeHash()) != 0 {
			return nil, ErrPrivilegedConsent
		}
		if saveErr := current.SaveKeyValue(bytes.Clone(experimentalPrivilegedConsentKey), c.pendingRecord); saveErr != nil {
			return nil, saveErr
		}
		if saveErr := c.accounts.SaveAccount(current); saveErr != nil {
			return nil, saveErr
		}
		return c.pendingOutput, nil
	})
	if err != nil {
		return vmcommon.ExecutionFailed, err
	}
	return code, nativeErr
}

// No production gas schedule entry is selected. The explicit experiment's gas
// is immutable; installation/epoch activation must allocate a real owning key.
func (c *PrivilegedConsentCandidate) SetNewGasConfig(_ *vmcommon.GasCost) {}
func (c *PrivilegedConsentCandidate) IsActive() bool                      { return true }
func (c *PrivilegedConsentCandidate) IsInterfaceNil() bool                { return c == nil }

// Fixed count plus lengths avoids tuple ambiguity. Width/order/version are
// explicitly experimental; bytes are compared exactly, never loose-decoded.
func encodeExperimentalConsent(s PrivilegedConsentScope, nonce uint64, epoch uint32) []byte {
	b := []byte{1}
	b = binary.BigEndian.AppendUint64(b, nonce)
	b = binary.BigEndian.AppendUint32(b, epoch)
	for _, field := range [][]byte{s.Domain, s.Token, s.Program, s.Target, s.Roles, s.Address} {
		b = binary.BigEndian.AppendUint64(b, uint64(len(field)))
		b = append(b, field...)
	}
	return b
}
