package systemSmartContracts

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualG18Snapshot(t *testing.T, e *vmContext) []byte {
	t.Helper()
	b, err := json.Marshal([]interface{}{e.storageUpdate, e.logs, e.outputAccounts})
	require.NoError(t, err)
	return b
}

func TestQualPartialsG18ValidatorZeroValueEffects(t *testing.T) {
	methods := []string{"changeRewardAddress", "get", "cleanRegisteredData", "reStakeUnStakedNodes", "unStake", "unStakeNodes", "unBond", "unBondNodes", "claim", "unStakeTokens", "unBondTokens", "getUnStakedTokensList", "getTotalStaked", "getTotalStakedTopUpStakedBlsKeys", "mergeValidatorData", "changeOwnerOfValidatorData"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			for _, value := range []int64{-1, 1, 0} {
				t.Run(big.NewInt(value).String(), func(t *testing.T) {
					a := createMockArgumentsForValidatorSCWithRealAddresses()
					e := createDefaultEei()
					e.SetSCAddress(vm.ValidatorSCAddress)
					a.Eei = e
					flags := a.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
					flags.AddActiveFlags(common.StakingV2Flag, common.FixCorrectSmallIntAndGasLimitsFlag)
					if method == "get" || method == "claim" {
						flags.RemoveActiveFlags(common.StakingV2Flag)
					}
					v, err := NewValidatorSmartContract(a)
					require.NoError(t, err)
					in := getDefaultVmInputForFunc(method, [][]byte{bytes.Repeat([]byte{1}, 32)})
					in.CallerAddr = bytes.Repeat([]byte{2}, 32)
					in.RecipientAddr = vm.ValidatorSCAddress
					in.CallValue = big.NewInt(value)
					in.GasProvided = 1000000
					if method == "cleanRegisteredData" {
						in.Arguments = nil
					}
					expected := vm.TransactionValueMustBeZero
					if method == "cleanRegisteredData" {
						expected = "must be called with 0 value"
					}
					if method == "mergeValidatorData" || method == "changeOwnerOfValidatorData" {
						in.CallerAddr = vm.DelegationManagerSCAddress
						in.Arguments = [][]byte{bytes.Repeat([]byte{2}, 32), vm.FirstDelegationSCAddress}
						expected = "callValue must be 0"
					}
					e.SetStorage([]byte("qual-g18-sentinel"), []byte("retained"))
					before := qualG18Snapshot(t, e)
					result := v.Execute(in)
					if value != 0 {
						require.Equal(t, vmcommon.UserError, result)
						require.Equal(t, expected, e.returnMessage)
						require.Equal(t, before, qualG18Snapshot(t, e))
					} else {
						require.NotEqual(t, expected, e.returnMessage, "zero must advance beyond value guard")
					}
				})
			}
		})
	}
}

func TestQualPartialsG18DelegationZeroValueEffects(t *testing.T) {
	methods := []string{initFromValidatorData, mergeValidatorDataToDelegation, "whitelistForMerge", deleteWhitelistForMerge, "getWhitelistForMerge", "addNodes", "removeNodes", "stakeNodes", "unStakeNodes", "unBondNodes", "reStakeUnStakedNodes", "changeServiceFee", "setCheckCapOnReDelegateRewards", "setAutomaticActivation", "modifyTotalDelegationCap", changeOwner, "setMetaData", "synchronizeOwner", reDelegateRewards, "unDelegate", "getRewardData", claimRewards, withdraw, "getTotalCumulatedRewards", "getNumUsers", "getTotalUnStaked", "getTotalActiveStake", "getNumNodes", "getAllNodeStates", "getContractConfig", "correctNodesStatus", "getUserActiveStake", "getUserUnStakedValue", "getUserUnBondable", "getUserUnDelegatedList", "getClaimableRewards", "isDelegator", "getDelegatorFundsData", "getTotalCumulatedRewardsForUser", "getMetaData"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			for _, value := range []int64{-1, 1, 0} {
				t.Run(big.NewInt(value).String(), func(t *testing.T) {
					a := createMockArgumentsForDelegation()
					e := createDefaultEei()
					e.SetSCAddress(vm.ValidatorSCAddress)
					a.Eei = e
					flags := a.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
					flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag, common.ChangeDelegationOwnerFlag, common.FixDelegationChangeOwnerOnAccountFlag)
					owner := bytes.Repeat([]byte{2}, 32)
					e.SetStorage([]byte(ownerKey), owner)
					d, err := NewDelegationSystemSC(a)
					require.NoError(t, err)
					in := getDefaultVmInputForFunc(method, nil)
					in.CallerAddr = owner
					in.RecipientAddr = vm.ValidatorSCAddress
					in.CallValue = big.NewInt(value)
					in.GasProvided = 1000000
					expected := vm.ErrCallValueMustBeZero.Error()
					switch method {
					case initFromValidatorData, mergeValidatorDataToDelegation:
						in.CallerAddr = vm.DelegationManagerSCAddress
						in.Arguments = [][]byte{owner}
						expected = "call value must be 0"
					case "whitelistForMerge", deleteWhitelistForMerge:
						expected = "non-payable function"
					case "unDelegate", "getRewardData":
						in.Arguments = [][]byte{{1}}
					}
					e.SetStorage([]byte("qual-g18-sentinel"), []byte("retained"))
					before := qualG18Snapshot(t, e)
					result := d.Execute(in)
					if value != 0 {
						require.Equal(t, vmcommon.UserError, result)
						require.Equal(t, expected, e.returnMessage)
						require.Equal(t, before, qualG18Snapshot(t, e))
					} else {
						require.NotEqual(t, expected, e.returnMessage, "zero must advance beyond value guard")
					}
				})
			}
		})
	}
}

func TestQualPartialsG18AddressLengthEffects(t *testing.T) {
	userViews := []string{"getUserActiveStake", "getUserUnStakedValue", "getUserUnBondable", "getUserUnDelegatedList", "getClaimableRewards", "isDelegator", "getDelegatorFundsData", "getTotalCumulatedRewardsForUser"}
	for _, method := range append(userViews, initFromValidatorData, mergeValidatorDataToDelegation, "whitelistForMerge", changeOwner) {
		for _, size := range []int{0, 31, 33} {
			t.Run("delegation/"+method+"/"+big.NewInt(int64(size)).String(), func(t *testing.T) {
				a := createMockArgumentsForDelegation()
				e := createDefaultEei()
				a.Eei = e
				a.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ChangeDelegationOwnerFlag)
				d, err := NewDelegationSystemSC(a)
				require.NoError(t, err)
				owner := bytes.Repeat([]byte{2}, 32)
				e.SetStorage([]byte(ownerKey), owner)
				in := getDefaultVmInputForFunc(method, [][]byte{bytes.Repeat([]byte{3}, size)})
				in.CallerAddr = owner
				in.CallValue = big.NewInt(0)
				in.GasProvided = 1000000
				expected := "invalid argument, wanted an address"
				if method == initFromValidatorData || method == mergeValidatorDataToDelegation {
					in.CallerAddr = vm.DelegationManagerSCAddress
					expected = "invalid arguments, first must be an address"
				}
				before := qualG18Snapshot(t, e)
				require.Equal(t, vmcommon.UserError, d.Execute(in))
				require.Equal(t, expected, e.returnMessage)
				require.Equal(t, before, qualG18Snapshot(t, e))
			})
		}
	}
	for _, method := range []string{"changeRewardAddress", "mergeValidatorData", "changeOwnerOfValidatorData"} {
		for _, which := range []int{0, 1} {
			if method == "changeRewardAddress" && which == 1 {
				continue
			}
			for _, size := range []int{0, 31, 33} {
				t.Run("validator/"+method+"/"+big.NewInt(int64(which)).String()+"/"+big.NewInt(int64(size)).String(), func(t *testing.T) {
					a := createMockArgumentsForValidatorSCWithRealAddresses()
					e := createDefaultEei()
					a.Eei = e
					v, err := NewValidatorSmartContract(a)
					require.NoError(t, err)
					in := getDefaultVmInputForFunc(method, [][]byte{bytes.Repeat([]byte{2}, 32), vm.FirstDelegationSCAddress})
					in.CallerAddr = vm.DelegationManagerSCAddress
					in.CallValue = big.NewInt(0)
					in.Arguments[which] = bytes.Repeat([]byte{3}, size)
					expected := "invalid argument, wanted an address for the first and second argument"
					if method == "changeRewardAddress" {
						expected = vm.ErrWrongRewardAddress.Error()
					}
					before := qualG18Snapshot(t, e)
					require.Equal(t, vmcommon.UserError, v.Execute(in))
					require.Equal(t, expected, e.returnMessage)
					require.Equal(t, before, qualG18Snapshot(t, e))
				})
			}
		}
	}
	for _, method := range []string{"delegateVote", "clearEndedProposals", "viewVotingPower"} {
		for _, size := range []int{0, 31, 33} {
			t.Run("governance/"+method+"/"+big.NewInt(int64(size)).String(), func(t *testing.T) {
				e := createDefaultEei()
				a := createArgsWithEEI(e)
				a.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.GovernanceFixesFlag)
				g, err := NewGovernanceContract(a)
				require.NoError(t, err)
				in := getDefaultVmInputForFunc(method, [][]byte{bytes.Repeat([]byte{3}, size)})
				in.CallerAddr = vm.ValidatorSCAddress
				in.RecipientAddr = in.CallerAddr
				in.CallValue = big.NewInt(0)
				in.GasProvided = 1000000
				expected := "invalid delegator address"
				if method == "delegateVote" {
					in.Arguments = [][]byte{{1}, []byte("yes"), bytes.Repeat([]byte{3}, size), {1}}
				}
				if method == "viewVotingPower" {
					expected = "invalid address"
				}
				before := qualG18Snapshot(t, e)
				require.Equal(t, vmcommon.UserError, g.Execute(in))
				require.Equal(t, expected, e.returnMessage)
				require.Equal(t, before, qualG18Snapshot(t, e))
			})
		}
	}
}

func TestQualPartialsG18OwnerDenialEffects(t *testing.T) {
	for _, fault := range []string{"caller", "occupied", "active-vote"} {
		t.Run(fault, func(t *testing.T) {
			a := createMockArgumentsForDelegation()
			e := createDefaultEei()
			a.Eei = e
			a.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ChangeDelegationOwnerFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
			d, err := NewDelegationSystemSC(a)
			require.NoError(t, err)
			old := bytes.Repeat([]byte{2}, 32)
			next := bytes.Repeat([]byte{3}, 32)
			e.SetStorage([]byte(ownerKey), old)
			data, err := a.Marshalizer.Marshal(&DelegatorData{RewardsCheckpoint: 10})
			require.NoError(t, err)
			e.SetStorage(old, data)
			in := getDefaultVmInputForFunc(changeOwner, [][]byte{next})
			in.CallerAddr = old
			in.CallValue = big.NewInt(0)
			in.GasProvided = 1000000
			expected := "only owner can call this method"
			if fault == "caller" {
				in.CallerAddr = bytes.Repeat([]byte{4}, 32)
			}
			if fault == "occupied" {
				e.SetStorageForAddress(d.delegationMgrSCAddress, next, []byte("occupied"))
				expected = "destination already deployed a delegation sc"
			}
			if fault == "active-vote" {
				votes, err := a.Marshalizer.Marshal(&OngoingVotedListV2{Direct: []uint64{42}})
				require.NoError(t, err)
				e.SetStorageForAddress(d.governanceSCAddr, old, votes)
				key := []byte("qual-g18-proposal")
				e.SetStorageForAddress(d.governanceSCAddr, append([]byte(noncePrefix), big.NewInt(42).Bytes()...), key)
				prop, err := a.Marshalizer.Marshal(&GeneralProposal{Nonce: 42, CommitHash: key, Closed: false, EndVoteEpoch: 10})
				require.NoError(t, err)
				e.SetStorageForAddress(d.governanceSCAddr, append([]byte(proposalPrefix), key...), prop)
				expected = "cannot change owner while stake has active governance vote"
			}
			before := qualG18Snapshot(t, e)
			require.Equal(t, vmcommon.UserError, d.Execute(in))
			require.Equal(t, expected, e.returnMessage)
			require.Equal(t, before, qualG18Snapshot(t, e))
		})
	}
}

func TestQualPartialsG18NilRewardsEffects(t *testing.T) {
	a := createMockArgumentsForDelegation()
	e := createDefaultEei()
	a.Eei = e
	d, err := NewDelegationSystemSC(a)
	require.NoError(t, err)
	key := bytes.Repeat([]byte{3}, 32)
	// Explicit decoded nulls exercise normalization independently of protobuf defaults.
	e.SetStorage(key, []byte(`{"UnClaimedRewards":null,"TotalCumulatedRewards":null}`))
	before := qualG18Snapshot(t, e)
	isNew, data, err := d.getOrCreateDelegatorData(key)
	require.NoError(t, err)
	require.False(t, isNew)
	require.NotNil(t, data.UnClaimedRewards)
	require.NotNil(t, data.TotalCumulatedRewards)
	require.Zero(t, data.UnClaimedRewards.Sign())
	require.Zero(t, data.TotalCumulatedRewards.Sign())
	require.Equal(t, before, qualG18Snapshot(t, e))
}
