package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

type burnBuiltin struct {
	vmcommon.BuiltinFunction
	cost   *vmcommon.GasCost
	calls  int
	output *vmcommon.VMOutput
}

func (b *burnBuiltin) IsInterfaceNil() bool { return b == nil }

func (b *burnBuiltin) IsActive() bool { return true }

func (b *burnBuiltin) SetNewGasConfig(cost *vmcommon.GasCost) { b.cost = cost }

func (b *burnBuiltin) ProcessBuiltinFunction(vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	b.calls++
	return b.output, nil
}

type burnContainer struct {
	vmcommon.BuiltInFunctionContainer
	get     func(string) (vmcommon.BuiltinFunction, error)
	replace func(string, vmcommon.BuiltinFunction) error
}

func (c *burnContainer) IsInterfaceNil() bool { return c == nil }

func (c *burnContainer) Get(name string) (vmcommon.BuiltinFunction, error) { return c.get(name) }

func (c *burnContainer) Replace(name string, f vmcommon.BuiltinFunction) error {
	return c.replace(name, f)
}

func TestNewBurnForAllAbsence(t *testing.T) {
	for _, mode := range []string{"flags", "marshal", "reader", "accounts", "record bound"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
			args := f.args
			switch mode {
			case "flags":
				args.EnableEpochsHandler = nil
			case "marshal":
				args.Marshaller = nil
			case "reader":
				args.Reader = nil
			case "accounts":
				args.Accounts = nil
			case "record bound":
				args.RecordByteLimit = 0
			}
			b, err := NewBurnForAllAbsence(args)
			require.Error(t, err)
			require.Nil(t, b)
		})
	}
	f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
	roots, outputs, err := f.b.Commit()
	require.Error(t, err)
	require.Nil(t, roots)
	require.Nil(t, outputs)
}

func TestRegistrationBuiltin_SetNewGasConfig(t *testing.T) {
	var absent *BurnForAllAbsence
	f, err := absent.BuiltinFunction("pause")
	require.Error(t, err)
	require.Nil(t, f)
	expected := &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, ReturnMessage: "native malformed-arity denial"}
	native := &burnBuiltin{output: expected}
	b := &BurnForAllAbsence{set: native, unset: native, ordinaryType: native}
	_, err = b.BuiltinFunction("unknown-entry")
	require.ErrorIs(t, err, builtInFunctions.ErrInvalidArguments)
	for _, name := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.ESDTSetTokenType} {
		wrapper, err := b.BuiltinFunction(name)
		require.NoError(t, err)
		require.True(t, wrapper.IsActive())
		require.False(t, wrapper.IsInterfaceNil())
		cost := &vmcommon.GasCost{}
		wrapper.SetNewGasConfig(cost)
		require.Same(t, cost, native.cost)
		out, err := wrapper.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{Function: "different-entry"})
		require.ErrorIs(t, err, builtInFunctions.ErrInvalidArguments)
		require.Nil(t, out)
		out, err = wrapper.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{Function: name})
		require.NoError(t, err)
		require.Same(t, expected, out)
	}
	require.Equal(t, 3, native.calls)
}

func TestBurnForAllAbsence_BindBuiltinFunctions(t *testing.T) {
	for _, mode := range []string{"nil container", "unprepared", "busy", "get failure", "nil entry", "foreign wrapper", "restore failure"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
			if mode != "unprepared" {
				qualBurnPrepare(t, f)
			}
			sentinel, restore := errors.New("container replacement/get failed"), errors.New("container restoration failed")
			native := &burnBuiltin{}
			entries := map[string]vmcommon.BuiltinFunction{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll: native, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll: native, core.ESDTSetTokenType: native}
			replacements := 0
			c := &burnContainer{get: func(name string) (vmcommon.BuiltinFunction, error) {
				if mode == "get failure" {
					return nil, sentinel
				}
				if mode == "nil entry" {
					return nil, nil
				}
				if mode == "foreign wrapper" {
					return &registrationBuiltin{owner: &BurnForAllAbsence{}, function: name, native: native}, nil
				}
				return entries[name], nil
			}, replace: func(name string, next vmcommon.BuiltinFunction) error {
				replacements++
				entries[name] = next
				if mode == "restore failure" && replacements == 2 {
					return sentinel
				}
				if mode == "restore failure" && replacements == 3 {
					return restore
				}
				return nil
			}}
			var container vmcommon.BuiltInFunctionContainer = c
			if mode == "nil container" {
				container = nil
			}
			call := func() error { return f.b.BindBuiltinFunctions(container, f.args.Accounts, f.args.EnableEpochsHandler) }
			if mode == "busy" {
				require.NoError(t, f.b.material.owner.Execute(func() (*vmcommon.VMOutput, error) { require.ErrorIs(t, call(), ErrExecutionBusy); return nil, nil }))
				return
			}
			err := call()
			require.Error(t, err)
			if mode == "get failure" {
				require.ErrorIs(t, err, sentinel)
			}
			if mode == "restore failure" {
				require.ErrorIs(t, err, sentinel)
				require.ErrorIs(t, err, restore)
				require.Equal(t, 4, replacements)
			} else {
				require.Zero(t, replacements)
			}
		})
	}
}

type burnNativeFailure struct {
	vmcommon.BuiltinFunction
	failure error
}

func (f *burnNativeFailure) ProcessBuiltinFunction(a, b vmcommon.UserAccountHandler, input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	out, err := f.BuiltinFunction.ProcessBuiltinFunction(a, b, input)
	if err != nil {
		return out, err
	}
	return nil, f.failure
}

type burnMetadataFailure struct {
	vmcommon.GlobalMetadataHandler
	failure error
}

func (f *burnMetadataFailure) GetTokenType([]byte) (uint32, error) { return 0, f.failure }

func TestBurnForAllAbsence_NormalizeDependencyFailures(t *testing.T) {
	for _, install := range []bool{false, true} {
		t.Run(strings.ReplaceAll(fmt.Sprintf("install-type=%t", install), "/", " ")+" should preserve the expected result", func(t *testing.T) {
			prepare := func(t *testing.T) (*qualBurnFixture, func() error) {
				family := core.FungibleESDT
				prior := []byte{5, 1}
				if install {
					family = core.DynamicNFTESDT
					prior = nil
				}
				f := qualBurnFixtureFor(t, false, family, "", prior)
				qualBurnPrepare(t, f)
				f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
				run := func() error {
					if install {
						return f.b.MaterializeRegistration(f.id, f.w)
					}
					return f.b.Normalize(f.id, f.w)
				}
				return f, run
			}
			f, run := prepare(t)
			control := &recordFault{calls: make(map[string]int)}
			f.b.material.state.accounts = &recordStore{AccountsAdapter: f.b.material.state.accounts, fault: control}
			f.b.records.marshaller = &recordMarshal{Marshalizer: f.b.records.marshaller, fault: control}
			require.NoError(t, run())
			for _, kind := range []string{"account", "read", "marshal", "unmarshal"} {
				for at := 1; at <= control.calls[kind]; at++ {
					t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%d", kind, at), "/", " ")+" should preserve the expected result", func(t *testing.T) {
						f, run := prepare(t)
						fault := &recordFault{kind: kind, at: at, calls: make(map[string]int)}
						f.b.material.state.accounts = &recordStore{AccountsAdapter: f.b.material.state.accounts, fault: fault}
						f.b.records.marshaller = &recordMarshal{Marshalizer: f.b.records.marshaller, fault: fault}
						root, err := f.db.RootHash()
						require.NoError(t, err)
						journal := f.db.JournalLen()
						require.Error(t, run())
						require.True(t, fault.hit)
						after, err := f.db.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, after)
						require.Equal(t, journal, f.db.JournalLen())
					})
				}
			}
			for _, where := range []string{"native unset", "native type", "metadata"} {
				if !install && where == "native type" {
					continue
				}
				t.Run(strings.ReplaceAll(where, "/", " ")+" should preserve the expected result", func(t *testing.T) {
					f, run := prepare(t)
					sentinel := errors.New("native dependency failed")
					switch where {
					case "native unset":
						f.b.protected = &burnNativeFailure{BuiltinFunction: f.b.protected, failure: sentinel}
					case "native type":
						f.b.tokenType = &burnNativeFailure{BuiltinFunction: f.b.tokenType, failure: sentinel}
					case "metadata":
						f.b.metadata = &burnMetadataFailure{GlobalMetadataHandler: f.b.metadata, failure: sentinel}
					}
					root, err := f.db.RootHash()
					require.NoError(t, err)
					journal := f.db.JournalLen()
					require.ErrorIs(t, run(), sentinel)
					after, err := f.db.RootHash()
					require.NoError(t, err)
					require.True(t, bytes.Equal(root, after))
					require.Equal(t, journal, f.db.JournalLen())
				})
			}
		})
	}
}
