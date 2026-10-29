package systemSmartContracts

import (
	"bytes"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"strings"
	"testing"
)

func TestNewVMContext_NilBlockChainHook(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.BlockChainHook = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilBlockchainHook, err)
}

func TestNewVMContext_NilCryptoHook(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.CryptoHook = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilCryptoHook, err)
}

func TestNewVMContext_NilInputParser(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.InputParser = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilArgumentsParser, err)
}

func TestNewVMContext_NilValidatorAccountsDB(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.ValidatorAccountsDB = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilValidatorAccountsDB, err)
}

func TestNewVMContext_NilUserAccountsDB(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.UserAccountsDB = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilUserAccountsDB, err)
}

func TestNewVMContext_NilChanceComputer(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.ChanceComputer = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilChanceComputer, err)
}

func TestNewVMContext_NilEnableEpochsHandler(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.EnableEpochsHandler = nil
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.Equal(t, vm.ErrNilEnableEpochsHandler, err)
	assert.True(t, check.IfNil(vmCtx))
}

func TestNewVMContext_InvalidEnableEpochsHandler(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStubWithNoFlagsDefined()
	vmCtx, err := NewVMContext(args)

	assert.Nil(t, vmCtx)
	assert.True(t, errors.Is(err, core.ErrInvalidEnableEpochsHandler))
}

func TestNewVMContext(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	vmCtx, err := NewVMContext(args)
	assert.False(t, check.IfNil(vmCtx))
	assert.Nil(t, err)
}

func TestVmContext_CleanCache(t *testing.T) {
	t.Parallel()

	vmCtx, _ := NewVMContext(createDefaultEeiArgs())

	vmCtx.CleanCache()

	vmOutput := vmCtx.CreateVMOutput()
	assert.Equal(t, 0, len(vmOutput.OutputAccounts))
}

func TestVmContext_GetBalance(t *testing.T) {
	t.Parallel()

	addr := []byte("addr")
	balance := big.NewInt(10)

	account, _ := accounts.NewUserAccount([]byte("123"), &trie.DataTrieTrackerStub{}, &trie.TrieLeafParserStub{})
	_ = account.AddToBalance(balance)

	blockChainHook := &mock.BlockChainHookStub{GetUserAccountCalled: func(address []byte) (a vmcommon.UserAccountHandler, e error) {
		if bytes.Equal(address, addr) {
			return account, nil
		}
		return nil, errors.New("get balance error")
	},
	}

	args := createDefaultEeiArgs()
	args.BlockChainHook = blockChainHook
	vmCtx, _ := NewVMContext(args)

	res := vmCtx.GetBalance(addr)
	assert.Equal(t, res.Uint64(), balance.Uint64())
}

func TestVmContext_CreateVMOutput_Empty(t *testing.T) {
	t.Parallel()

	vmCtx, _ := NewVMContext(createDefaultEeiArgs())

	vmOutput := vmCtx.CreateVMOutput()
	assert.Equal(t, vmcommon.Ok, vmOutput.ReturnCode)
	assert.Equal(t, 0, len(vmOutput.ReturnData))
	assert.Equal(t, 0, len(vmOutput.OutputAccounts))
	assert.Equal(t, 0, len(vmOutput.Logs))
	assert.Equal(t, 0, len(vmOutput.DeletedAccounts))
	assert.Equal(t, 0, len(vmOutput.TouchedAccounts))
	assert.Equal(t, uint64(0), vmOutput.GasRefund.Uint64())
	assert.Equal(t, uint64(0), vmOutput.GasRemaining)
}

func TestVmContext_SetStorage(t *testing.T) {
	t.Parallel()

	vmCtx, _ := NewVMContext(createDefaultEeiArgs())

	addr := "smartcontract"
	vmCtx.SetSCAddress([]byte(addr))

	key := []byte("key")
	data := []byte("data")
	vmCtx.SetStorage(key, data)

	res := vmCtx.GetStorage(key)
	assert.True(t, bytes.Equal(data, res))

	vmOutput := vmCtx.CreateVMOutput()
	assert.Equal(t, 1, len(vmOutput.OutputAccounts))

	assert.True(t, bytes.Equal(vmOutput.OutputAccounts[addr].StorageUpdates[string(key)].Data, data))
}

func TestVmContext_Transfer(t *testing.T) {
	t.Parallel()

	vmCtx, _ := NewVMContext(createDefaultEeiArgs())

	destination := []byte("dest")
	sender := []byte("sender")
	value := big.NewInt(999)
	input := []byte("input")

	vmCtx.Transfer(destination, sender, value, input, 0)
	balance := vmCtx.GetBalance(destination)
	assert.Equal(t, value.Uint64(), balance.Uint64())

	balance = vmCtx.GetBalance(sender)
	assert.Equal(t, value.Int64(), -1*balance.Int64())

	vmOutput := vmCtx.CreateVMOutput()
	assert.Equal(t, 2, len(vmOutput.OutputAccounts))
}

func TestVmContext_IsValidatorNonexistentAccountShouldRetFalse(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.ValidatorAccountsDB = &stateMock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return nil, errors.New("not found")
		},
	}
	vmCtx, _ := NewVMContext(args)

	assert.False(t, vmCtx.IsValidator([]byte("bls key")))
}

func TestVmContext_IsValidatorInvalidAccountTypeShouldRetFalse(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	args.ValidatorAccountsDB = &stateMock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return &stateMock.AccountWrapMock{}, nil
		},
	}
	vmCtx, _ := NewVMContext(args)

	assert.False(t, vmCtx.IsValidator([]byte("bls key")))
}

func TestVmContext_IsValidator(t *testing.T) {
	t.Parallel()

	type testIO struct {
		peerType       common.PeerType
		expectedResult bool
	}

	testData := []testIO{
		{
			peerType:       common.LeavingList,
			expectedResult: true,
		},
		{
			peerType:       common.EligibleList,
			expectedResult: true,
		},
		{
			peerType:       common.WaitingList,
			expectedResult: true,
		},
		{
			peerType:       common.NewList,
			expectedResult: false,
		},
		{
			peerType:       common.JailedList,
			expectedResult: false,
		},
	}

	for _, tio := range testData {
		blsKey := []byte("bls key")
		args := createDefaultEeiArgs()
		args.ValidatorAccountsDB = &stateMock.AccountsStub{
			GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				assert.Equal(t, blsKey, address)

				acnt, _ := accounts.NewPeerAccount(address)
				acnt.List = string(tio.peerType)

				return acnt, nil
			},
		}
		vmCtx, _ := NewVMContext(args)

		assert.Equal(t, tio.expectedResult, vmCtx.IsValidator(blsKey))
	}
}

func TestVmContext_CleanStorage(t *testing.T) {
	t.Parallel()

	vmCtx, _ := NewVMContext(createDefaultEeiArgs())

	vmCtx.CleanCache()
	vmCtx.storageUpdate["address"] = make(map[string][]byte)
	vmCtx.storageUpdate["address"]["key"] = []byte("someData")
	vmCtx.CleanStorageUpdates()
	assert.Equal(t, 0, len(vmCtx.storageUpdate))
}

func TestVmContext_SetOwnerOperatingOnAccount(t *testing.T) {
	t.Parallel()

	scAddress := []byte("sc-address-01234")
	ownerAddress := []byte("owner-address-01")
	expectedErr := errors.New("expected error")

	t.Run("load account errors, should error", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		args.UserAccountsDB = &stateMock.AccountsStub{
			LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				if bytes.Equal(address, scAddress) {
					return nil, expectedErr
				}

				return nil, nil
			},
		}
		vmCtx, _ := NewVMContext(args)
		vmCtx.SetSCAddress(scAddress)
		err := vmCtx.SetOwnerOperatingOnAccount(ownerAddress)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("wrong type assertion, should error", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		args.UserAccountsDB = &stateMock.AccountsStub{
			LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				if bytes.Equal(address, scAddress) {
					return &stateMock.BaseAccountMock{}, nil
				}

				return nil, nil
			},
		}
		vmCtx, _ := NewVMContext(args)
		vmCtx.SetSCAddress(scAddress)
		err := vmCtx.SetOwnerOperatingOnAccount(ownerAddress)
		assert.ErrorIs(t, err, vm.ErrWrongTypeAssertion)
	})
	t.Run("wrong size for the owner, should error", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		args.UserAccountsDB = &stateMock.AccountsStub{
			LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				if bytes.Equal(address, scAddress) {
					return &stateMock.AccountWrapMock{}, nil
				}

				return nil, nil
			},
		}
		vmCtx, _ := NewVMContext(args)
		vmCtx.SetSCAddress(scAddress)
		err := vmCtx.SetOwnerOperatingOnAccount([]byte("wrong size"))
		assert.ErrorIs(t, err, vm.ErrWrongNewOwnerAddress)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		account := &stateMock.AccountWrapMock{}
		saveWasCalled := false
		args.UserAccountsDB = &stateMock.AccountsStub{
			LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				if bytes.Equal(address, scAddress) {
					return account, nil
				}

				return nil, nil
			},
			SaveAccountCalled: func(saveAccount vmcommon.AccountHandler) error {
				if account == saveAccount { // pointer testing
					saveWasCalled = true
				}

				return nil
			},
		}
		vmCtx, _ := NewVMContext(args)
		vmCtx.SetSCAddress(scAddress)
		err := vmCtx.SetOwnerOperatingOnAccount(ownerAddress)
		assert.Nil(t, err)
		assert.Equal(t, ownerAddress, account.Owner)
		assert.True(t, saveWasCalled)
	})
}

func TestVmContext_UpdateCodeDeployerAddress(t *testing.T) {
	t.Parallel()

	scAddress := "sc-address-01234"
	ownerAddress := []byte("owner-address-01")

	t.Run("programming error: account is missing, should error", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		vmCtx, _ := NewVMContext(args)

		err := vmCtx.UpdateCodeDeployerAddress(scAddress, ownerAddress)
		assert.Equal(t, vm.ErrInternalErrorWhileSettingNewOwner, err)
	})
	t.Run("account exists, should update", func(t *testing.T) {
		t.Parallel()

		args := createDefaultEeiArgs()
		vmCtx, _ := NewVMContext(args)

		account := &vmcommon.OutputAccount{
			CodeDeployerAddress: []byte("deployer"),
		}
		vmCtx.outputAccounts[scAddress] = account

		err := vmCtx.UpdateCodeDeployerAddress(scAddress, ownerAddress)
		assert.Nil(t, err)
		assert.Equal(t, ownerAddress, vmCtx.outputAccounts[scAddress].CodeDeployerAddress)
	})
}

func TestVmContext_CopyToNewContext_DeepCopyStorageUpdate(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	vmCtx, _ := NewVMContext(args)
	vmCtx.SetSCAddress([]byte("scAddress1"))
	vmCtx.SetStorage([]byte("key1"), []byte("val1"))

	newCtx := vmCtx.copyToNewContext()

	// Mutate newCtx storage
	newCtx.SetStorage([]byte("key1"), []byte("mutated_val1"))
	newCtx.SetStorage([]byte("key2"), []byte("val2"))

	// Verify original vmCtx storage was not mutated
	assert.Equal(t, []byte("val1"), vmCtx.storageUpdate["scAddress1"]["key1"])
	_, exists := vmCtx.storageUpdate["scAddress1"]["key2"]
	assert.False(t, exists)
}

func TestVmContext_ExecuteOnDestContext_RollbackStorageOnFailure(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	destAddr := []byte("destinationSC")
	senderAddr := []byte("senderAddress")

	mockContract := &mock.SystemSCStub{}

	vmCtx, _ := NewVMContext(args)
	_ = vmCtx.SetSystemSCContainer(&mock.SystemSCContainerStub{
		GetCalled: func(key []byte) (vm.SystemSmartContract, error) {
			if bytes.Equal(key, destAddr) {
				return mockContract, nil
			}
			return nil, errors.New("contract not found")
		},
	})

	vmCtx.SetSCAddress([]byte("parentSC"))
	vmCtx.SetStorage([]byte("parentKey"), []byte("parentVal"))

	mockContract.ExecuteCalled = func(args *vmcommon.ContractCallInput) vmcommon.ReturnCode {
		vmCtx.SetStorage([]byte("calleeKey"), []byte("calleeVal"))
		return vmcommon.UserError
	}

	vmOutput, err := vmCtx.ExecuteOnDestContext(destAddr, senderAddr, big.NewInt(0), []byte("dummyFunc"))
	assert.Nil(t, err)
	assert.Equal(t, vmcommon.UserError, vmOutput.ReturnCode)

	// Verify that the failed callee's storage write was rolled back
	_, calleeKeyExists := vmCtx.storageUpdate[string(destAddr)]["calleeKey"]
	assert.False(t, calleeKeyExists)

	// Verify that parent's storage was preserved
	assert.Equal(t, []byte("parentVal"), vmCtx.storageUpdate["parentSC"]["parentKey"])
}

func TestVmContext_GetBalance_NilBalanceSafe(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	vmCtx, _ := NewVMContext(args)

	addr := []byte("accountWithNilBalance")
	vmCtx.outputAccounts[string(addr)] = &vmcommon.OutputAccount{
		Address:      addr,
		Balance:      nil,
		BalanceDelta: big.NewInt(100),
	}

	assert.NotPanics(t, func() {
		bal := vmCtx.GetBalance(addr)
		assert.Equal(t, big.NewInt(100), bal)
	})

	addrNilDelta := []byte("accountWithNilDelta")
	vmCtx.outputAccounts[string(addrNilDelta)] = &vmcommon.OutputAccount{
		Address:      addrNilDelta,
		Balance:      big.NewInt(200),
		BalanceDelta: nil,
	}

	assert.NotPanics(t, func() {
		bal := vmCtx.GetBalance(addrNilDelta)
		assert.Equal(t, big.NewInt(200), bal)
	})
}

func TestVmContext_AddCode_InitializesBalance(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	vmCtx, _ := NewVMContext(args)

	scAddr := []byte("newSC")
	vmCtx.AddCode(scAddr, []byte("someCode"))

	acc, exists := vmCtx.outputAccounts[string(scAddr)]
	assert.True(t, exists)
	assert.NotNil(t, acc.Balance)
	assert.Equal(t, big.NewInt(0), acc.Balance)
	assert.NotPanics(t, func() {
		bal := vmCtx.GetBalance(scAddr)
		assert.Equal(t, big.NewInt(0), bal)
	})
}

func TestVmContext_AddTxValueToSmartContract_NilBalanceGuards(t *testing.T) {
	t.Parallel()

	args := createDefaultEeiArgs()
	vmCtx, _ := NewVMContext(args)

	scAddr := []byte("scWithNilDeltas")
	// Pre-create output account with nil Balance and nil BalanceDelta
	vmCtx.outputAccounts[string(scAddr)] = &vmcommon.OutputAccount{
		Address:      scAddr,
		Balance:      nil,
		BalanceDelta: nil,
	}

	assert.NotPanics(t, func() {
		vmCtx.AddTxValueToSmartContract(big.NewInt(500), scAddr)
	})

	acc := vmCtx.outputAccounts[string(scAddr)]
	assert.NotNil(t, acc.Balance)
	assert.NotNil(t, acc.BalanceDelta)
	assert.Equal(t, big.NewInt(500), acc.BalanceDelta)
}

func TestVmContext_AddTxValueToSmartContract_LoadsPersistedBalance(t *testing.T) {
	t.Parallel()

	scAddr := []byte("scWithPersistedBalance")
	persistedBalance := big.NewInt(1000)

	account, _ := accounts.NewUserAccount(scAddr, &trie.DataTrieTrackerStub{}, &trie.TrieLeafParserStub{})
	_ = account.AddToBalance(persistedBalance)

	args := createDefaultEeiArgs()
	args.BlockChainHook = &mock.BlockChainHookStub{
		GetUserAccountCalled: func(address []byte) (vmcommon.UserAccountHandler, error) {
			if bytes.Equal(address, scAddr) {
				return account, nil
			}
			return nil, errors.New("not found")
		},
	}
	vmCtx, _ := NewVMContext(args)

	vmCtx.AddTxValueToSmartContract(big.NewInt(250), scAddr)

	acc := vmCtx.outputAccounts[string(scAddr)]
	assert.NotNil(t, acc)
	assert.Equal(t, persistedBalance, acc.Balance)
	assert.Equal(t, big.NewInt(250), acc.BalanceDelta)

	// GetBalance should compute Balance (1000) + BalanceDelta (250) = 1250
	totalBalance := vmCtx.GetBalance(scAddr)
	assert.Equal(t, big.NewInt(1250), totalBalance)
}

type publicClassifier struct {
	regulated                bool
	classifyErr, accountsErr error
	calls                    int
}

func (c *publicClassifier) IsInterfaceNil() bool { return c == nil }

func (c *publicClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return c.accountsErr
}

func (c *publicClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte, execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.calls++
	if c.classifyErr != nil {
		return nil, c.classifyErr
	}
	return execute(c.regulated)
}

type publicOwner struct {
	*publicClassifier
	failure error
}

func (c *publicOwner) DRWAExecutionError() error { return c.failure }

type publicHealthOwner struct {
	*publicOwner
	health error
}

func (c *publicHealthOwner) DRWAExecutionHealthError() error { return c.health }

type publicReplacementOwner struct {
	*publicClassifier
	handoffErr error
	handoffs   int
}

func (c *publicReplacementOwner) WithDRWAClassifierReplacement(_ vm.DRWATokenClassifier, replace func()) error {
	c.handoffs++
	if c.handoffErr != nil {
		return c.handoffErr
	}
	replace()
	return nil
}

func TestVMContext_ExecuteWithDRWAErrorCheck(t *testing.T) {
	for _, mode := range []string{"unconfigured", "ordinary", "regulated", "classification unavailable", "native failure", "query", "missing arguments", "non ESDT recipient"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			sentinel := errors.New("synthetic native failure")
			classifier := &publicClassifier{regulated: mode == "regulated"}
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

func TestVMContext_RetainDRWAExecutionError(t *testing.T) {
	first, second := errors.New("first classifier failure"), errors.New("later failure")
	for _, when := range []string{"before", "during"} {
		t.Run(strings.ReplaceAll(when, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			owner := &publicOwner{publicClassifier: &publicClassifier{}}
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

func TestVMContext_DRWAExecutionError(t *testing.T) {
	sentinel := errors.New("owner unavailable")
	for _, health := range []bool{false, true} {
		t.Run(strings.ReplaceAll(map[bool]string{false: "legacy status", true: "health status"}[health], "/", " ")+" should preserve the expected result", func(t *testing.T) {
			execution := &publicOwner{publicClassifier: &publicClassifier{}, failure: sentinel}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: execution}
			if health {
				host.drwaClassifier = &publicHealthOwner{publicOwner: execution, health: sentinel}
			}
			require.ErrorIs(t, host.DRWAExecutionError(), sentinel)
			execution.failure = nil
			require.ErrorIs(t, host.DRWAExecutionError(), sentinel)
		})
	}
	host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: &publicHealthOwner{publicOwner: &publicOwner{publicClassifier: &publicClassifier{}}}}
	require.NoError(t, host.DRWAExecutionError())
	require.NoError(t, (&vmContext{}).DRWAExecutionError())
}

func TestVMContext_ReplaceDRWAClassifier(t *testing.T) {
	sentinel := errors.New("handoff denied")
	for _, mode := range []string{"absent old", "absent next", "unsupported old", "account mismatch", "owner denial", "latched", "active", "success"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			old := &publicReplacementOwner{publicClassifier: &publicClassifier{}}
			var next vm.DRWATokenClassifier = &publicClassifier{}
			host := &vmContext{drwaClassifierConfigured: true, drwaClassifier: old}
			switch mode {
			case "absent old":
				host.drwaClassifier = nil
			case "absent next":
				next = nil
			case "unsupported old":
				host.drwaClassifier = &publicClassifier{}
			case "account mismatch":
				next = &publicClassifier{accountsErr: sentinel}
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
