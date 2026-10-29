package systemSmartContracts

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type sp1PublicClassifier struct {
	regulated                bool
	classifyErr, accountsErr error
	calls                    int
}

func (c *sp1PublicClassifier) IsInterfaceNil() bool { return c == nil }
func (c *sp1PublicClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return c.accountsErr
}
func (c *sp1PublicClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte, execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.calls++
	if c.classifyErr != nil {
		return nil, c.classifyErr
	}
	return execute(c.regulated)
}

type sp1PublicOwner struct {
	*sp1PublicClassifier
	failure error
}

func (c *sp1PublicOwner) DRWAExecutionError() error { return c.failure }

type sp1PublicHealthOwner struct {
	*sp1PublicOwner
	health error
}

func (c *sp1PublicHealthOwner) DRWAExecutionHealthError() error { return c.health }

type sp1PublicReplacementOwner struct {
	*sp1PublicClassifier
	handoffErr error
	handoffs   int
}

func (c *sp1PublicReplacementOwner) WithDRWAClassifierReplacement(_ vm.DRWATokenClassifier, replace func()) error {
	c.handoffs++
	if c.handoffErr != nil {
		return c.handoffErr
	}
	replace()
	return nil
}

func TestSP1CoveragePublicClassification(t *testing.T) {
	for _, mode := range []string{"unconfigured", "ordinary", "regulated", "classification unavailable", "native failure", "query", "missing arguments", "non ESDT recipient"} {
		t.Run(mode, func(t *testing.T) {
			sentinel := errors.New("synthetic native failure")
			classifier := &sp1PublicClassifier{regulated: mode == "regulated"}
			host := &vmContext{drwaClassifierConfigured: mode != "unconfigured", drwaClassifier: classifier}
			if mode == "unconfigured" {
				host.drwaClassifier = nil
			}
			if mode == "classification unavailable" {
				classifier.classifyErr = sentinel
			}
			input := &vmcommon.ContractCallInput{RecipientAddr: core.ESDTSCAddress, Function: "pause", VMInput: vmcommon.VMInput{Arguments: [][]byte{[]byte("TOKEN-abcdef")}}}
			if mode == "query" {
				input.Function = "getTokenProperties"
			}
			if mode == "missing arguments" {
				input.Arguments = nil
			}
			if mode == "non ESDT recipient" {
				input.RecipientAddr = []byte("other-native-contract")
			}
			expected := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
			calls := 0
			out, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
				calls++
				if mode == "native failure" {
					return expected, sentinel
				}
				return expected, nil
			})
			switch mode {
			case "classification unavailable":
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, sentinel)
				require.Nil(t, out)
				require.Zero(t, calls)
				require.ErrorIs(t, host.DRWAExecutionError(), sentinel)
			case "regulated":
				require.NoError(t, err)
				require.NotNil(t, out)
				require.Equal(t, vmcommon.UserError, out.ReturnCode)
				require.Zero(t, calls)
				require.NoError(t, host.DRWAExecutionError())
			case "native failure":
				require.ErrorIs(t, err, sentinel)
				require.Same(t, expected, out)
				require.Equal(t, 1, calls)
				require.NoError(t, host.DRWAExecutionError(), "entered native failure is not a classifier failure")
			default:
				require.NoError(t, err)
				require.Same(t, expected, out)
				require.Equal(t, 1, calls)
			}
			if mode == "query" || mode == "missing arguments" || mode == "non ESDT recipient" || mode == "unconfigured" {
				require.Zero(t, classifier.calls)
			} else {
				require.Equal(t, 1, classifier.calls)
			}
		})
	}
}
func TestSP1CoveragePublicFailureLatch(t *testing.T) {
	first, second := errors.New("first classifier failure"), errors.New("later failure")
	for _, when := range []string{"before", "during"} {
		t.Run(when, func(t *testing.T) {
			owner := &sp1PublicOwner{sp1PublicClassifier: &sp1PublicClassifier{}}
			if when == "before" {
				owner.failure = first
			}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: owner}
			calls := 0
			output, err := host.ExecuteDRWASystemCall(nil, func() (*vmcommon.VMOutput, error) {
				calls++
				host.retainDRWAExecutionError(first)
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
			require.Nil(t, output)
			require.ErrorIs(t, err, first)
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			if when == "before" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
			owner.failure = nil
			require.ErrorIs(t, host.DRWAExecutionError(), first)
			retained := host.retainDRWAExecutionError(second)
			require.ErrorIs(t, retained, first)
			require.NotErrorIs(t, retained, second)
		})
	}
}
func TestSP1CoveragePublicOwnerStatus(t *testing.T) {
	sentinel := errors.New("owner unavailable")
	for _, health := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy status", true: "health status"}[health], func(t *testing.T) {
			execution := &sp1PublicOwner{sp1PublicClassifier: &sp1PublicClassifier{}, failure: sentinel}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: execution}
			if health {
				host.drwaClassifier = &sp1PublicHealthOwner{sp1PublicOwner: execution, health: sentinel}
			}
			require.ErrorIs(t, host.DRWAExecutionError(), sentinel)
			execution.failure = nil
			require.ErrorIs(t, host.DRWAExecutionError(), sentinel)
		})
	}
	host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: &sp1PublicHealthOwner{sp1PublicOwner: &sp1PublicOwner{sp1PublicClassifier: &sp1PublicClassifier{}}}}
	require.NoError(t, host.DRWAExecutionError())
	require.NoError(t, (&vmContext{}).DRWAExecutionError())
}
func TestSP1CoveragePublicReplacement(t *testing.T) {
	sentinel := errors.New("handoff denied")
	for _, mode := range []string{"absent old", "absent next", "unsupported old", "account mismatch", "owner denial", "latched", "active", "success"} {
		t.Run(mode, func(t *testing.T) {
			old := &sp1PublicReplacementOwner{sp1PublicClassifier: &sp1PublicClassifier{}}
			var next vm.DRWATokenClassifier = &sp1PublicClassifier{}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: old}
			switch mode {
			case "absent old":
				host.drwaClassifier = nil
			case "absent next":
				next = nil
			case "unsupported old":
				host.drwaClassifier = &sp1PublicClassifier{}
			case "account mismatch":
				next = &sp1PublicClassifier{accountsErr: sentinel}
			case "owner denial":
				old.handoffErr = sentinel
			case "latched":
				host.retainDRWAExecutionError(sentinel)
			case "active":
				host.mutDRWAClassifier.RLock()
				defer host.mutDRWAClassifier.RUnlock()
			}
			before := host.drwaClassifier
			err := host.ReplaceDRWAClassifier(next)
			if mode == "success" {
				require.NoError(t, err)
				require.Same(t, next, host.drwaClassifier)
				require.Equal(t, 1, old.handoffs)
			} else {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				if before == nil {
					require.Nil(t, host.drwaClassifier)
				} else {
					require.Same(t, before, host.drwaClassifier)
				}
				if mode == "owner denial" || mode == "account mismatch" || mode == "latched" {
					require.ErrorIs(t, err, sentinel)
				}
			}
		})
	}
}
