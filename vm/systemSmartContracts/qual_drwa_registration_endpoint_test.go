package systemSmartContracts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 synthetic semantic hosts and unbound time in this native-creator package;
// process/drwa's companion qualifiers exercise native hook/time and real
// independent Ed25519 purposes. Neither host is actual lawful/canonical ingress.
type qualEndpointTime struct {
	*drwa.EvaluatedHeaderTime
	accounts state.AccountsAdapter
}

func (s *qualEndpointTime) GetAccountsAdapter() state.AccountsAdapter { return s.accounts }

type qualEndpointVerifier struct {
	f     qualCommittedFixture
	deny  string
	calls int
}

func (v *qualEndpointVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualEndpointVerifier) VerifyRegistration(p string, id, hash, body, creation, proof []byte,
	at drwa.HeaderMilliseconds, epoch uint32) error {
	v.calls++
	if p == v.deny || at != 1 || epoch != 10 || !bytes.Equal(id, v.f.id) || !bytes.Equal(hash, v.f.digest) ||
		!bytes.Equal(body, v.f.intent) || !bytes.Equal(creation, v.f.bodyDigest) || !bytes.Equal(proof, []byte(p)) {
		return errors.New("synthetic endpoint authorization denied")
	}
	return nil
}

func qualEndpointAdmission(t *testing.T, e *esdt, f *qualCommittedFixture, s *qualDRWARegistrationStore) (*drwa.RegistrationAdmission, *qualEndpointVerifier) {
	t.Helper()
	e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.DynamicESDTFlag, common.MetaESDTSetFlag)
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool {
		return flag != common.SupernovaFlag || epoch >= 10
	}
	clock, err := drwa.NewEvaluatedHeaderTime(flags, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	require.NoError(t, err)
	context, err := clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 1})
	require.NoError(t, err)
	t.Cleanup(func() { clock.End(context) })
	// Provision the fixture's existing global budget at a committed root,
	// then construct the owner at those exact bytes. The prior fixture owner
	// is not used after reconstruction; no actual deployment is asserted.
	account, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	budgetKey := []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget")
	budget := binary.BigEndian.AppendUint64(nil, 2)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32+len(core.ProtectedKeyPrefix+"DRWA@registration@intent@")+len(f.id)+len(qualNativeIntentFrame(f.intent, []byte("OPEN"), nil))))
	budget = binary.BigEndian.AppendUint64(budget, 10)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(budgetKey, budget))
	require.NoError(t, s.SaveAccount(account))
	_, err = s.Commit()
	require.NoError(t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, boundary, err := drwa.NewRegistryRegistration(s, coordinator, 2)
	require.NoError(t, err)
	f.owner, err = r.BindIntent(f.id, f.digest, bytes.Repeat([]byte{2}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.boundary = boundary
	v := &qualEndpointVerifier{f: *f}
	proofs := drwa.RegistrationProofs{CanonicalIntent: []byte("CANONICAL_OPEN_INTENT"), Issuer: []byte("ISSUER_TRANSACTION"),
		CurrentAdmission: []byte("CURRENT_ADMISSION"), Admission: []byte("REGISTER_TOKEN_ADMISSION"),
		ProgramAdministration: []byte("PROGRAM_ADMINISTRATION"), Independent: []byte("REGISTER_TOKEN"),
		Support: []byte("CURRENT_SUPPORT"), Resources: []byte("RESOURCE_ADMISSION")}
	a, err := f.owner.WithRegistrationAdmission(&qualEndpointTime{clock, s}, []byte("n"), 10,
		drwa.RegistrationResourceLimits{Records: 1000, RetainedBytes: 1048576, NewRecordsPerEpoch: 100}, v, proofs)
	require.NoError(t, err)
	return a, v
}

func qualEndpointInput(e *esdt, f qualCommittedFixture, request drwaTokenCreation) *vmcommon.ContractCallInput {
	profileHash := blake2b.NewBlake2b().Compute(string(f.profile))
	body := qualNativeIntentFrame([]byte("DRWA/TOKEN_CREATION_BODY/v1"), request.family,
		profileHash, request.name, request.ticker, []byte{0, 0, 0, 0})
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(request.issuer),
		CallType: vmData.DirectCall, CallValue: new(big.Int).Set(e.baseIssuingCost), Arguments: [][]byte{bytes.Clone(f.id), body}},
		RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: "DRWARegisterToken"}
}

func TestQualDRWAT44T45NativeEndpointFamiliesAndFee(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.family, request.properties = []byte(family), nil
			f := qualCommittedIntent(t, s, request)
			admit, verifier := qualEndpointAdmission(t, e, &f, s)
			input := qualEndpointInput(e, f, request)
			gas := ctx.GasLeft()
			code, err := e.registerDRWATokenEndpoint(admit, input, request, f.profile)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, code)
			require.Equal(t, 8, verifier.calls)
			require.Equal(t, gas-e.gasCost.MetaChainSystemSCsCost.ESDTIssue, ctx.GasLeft())
			_, pending, err := f.boundary.Commit()
			require.NoError(t, err)
			require.Len(t, pending, 1)
			out := pending[0]
			require.Equal(t, input.CallValue, out.OutputAccounts[string(core.ESDTSCAddress)].BalanceDelta)
			require.Empty(t, out.OutputAccounts[string(core.ESDTSCAddress)].OutputTransfers)
			require.Len(t, out.ReturnData, 1)
			native := &ESDTDataV2{}
			require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, out.ReturnData[0])))
			require.Equal(t, request.manager, native.OwnerAddress)
			require.Equal(t, family, string(native.TokenType))
			require.Zero(t, native.MintedValue.Sign())
			require.Empty(t, native.SpecialRoles)
		})
	}
}

func TestQualDRWAT44T45NativeEndpointBasicEconomics(t *testing.T) {
	for _, fault := range []string{"fee-low", "fee-high", "gas", "name", "caller", "recipient", "callback", "function", "arity", "id", "body", "independent-approval", "resource-admission"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			admit, verifier := qualEndpointAdmission(t, e, &f, s)
			input := qualEndpointInput(e, f, request)
			wantCode := vmcommon.UserError
			switch fault {
			case "fee-low":
				input.CallValue.Sub(input.CallValue, big.NewInt(1))
				wantCode = vmcommon.OutOfFunds
			case "fee-high":
				input.CallValue.Add(input.CallValue, big.NewInt(1))
				wantCode = vmcommon.OutOfFunds
			case "gas":
				require.Positive(t, e.gasCost.MetaChainSystemSCsCost.ESDTIssue)
				ctx.SetGasProvided(e.gasCost.MetaChainSystemSCsCost.ESDTIssue - 1)
				wantCode = vmcommon.OutOfGas
			case "name":
				request.name = []byte("x")
				wantCode = vmcommon.FunctionWrongSignature
			case "caller":
				input.CallerAddr[0] ^= 1
			case "recipient":
				input.RecipientAddr[0] ^= 1
			case "callback":
				input.CallType = vmData.AsynchronousCallBack
			case "function":
				input.Function = "issue"
			case "arity":
				input.Arguments = input.Arguments[:1]
			case "id":
				input.Arguments[0][0] ^= 1
			case "body":
				input.Arguments[1][0] ^= 1
			case "independent-approval":
				verifier.deny = "REGISTER_TOKEN"
			case "resource-admission":
				verifier.deny = "RESOURCE_ADMISSION"
			}
			before, err := s.RootHash()
			require.NoError(t, err)
			code, _ := e.registerDRWATokenEndpoint(admit, input, request, f.profile)
			require.Equal(t, wantCode, code)
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, s.JournalLen())
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
			if fault == "fee-low" || fault == "fee-high" || fault == "gas" || fault == "name" {
				require.Zero(t, verifier.calls)
			}
		})
	}
}

func TestQualDRWAT44T45NativeEndpointLateFailureDiscardsValue(t *testing.T) {
	for _, fault := range []string{"records", "registry", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			admit, _ := qualEndpointAdmission(t, e, &f, s)
			input := qualEndpointInput(e, f, request)
			before, err := s.RootHash()
			require.NoError(t, err)
			original, rollback := errors.New("late native save"), errors.New("native rollback")
			s.saves, s.failAt, s.saveFault = 0, 2, original
			if fault == "registry" {
				s.failAt = 3
			}
			if fault == "rollback" {
				s.rollbackFault = rollback
			}
			code, err := e.registerDRWATokenEndpoint(admit, input, request, f.profile)
			require.Equal(t, vmcommon.UserError, code)
			require.ErrorIs(t, err, original)
			require.Empty(t, ctx.storageUpdate)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.logs)
			if fault == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, pending, e := f.boundary.Commit()
				require.ErrorIs(t, e, rollback)
				require.Empty(t, pending)
				return
			}
			after, readErr := s.RootHash()
			require.NoError(t, readErr)
			require.Equal(t, before, after)
			_, pending, commitErr := f.boundary.Commit()
			require.NoError(t, commitErr)
			require.Empty(t, pending)
		})
	}
}

// Part A L2199-2200: a semantic support proof cannot enable a family which
// the ACTUAL native epoch handler does not support. The internal creator is
// lower-level than the native public issuance flag checks, so the adapter owns
// this check while directly reusing the creator.
func TestQualDRWAT44T45NativeEndpointUnsupportedFlags(t *testing.T) {
	for _, family := range []string{core.NonFungibleESDTv2, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.family, request.properties = []byte(family), nil
			f := qualCommittedIntent(t, s, request)
			admit, _ := qualEndpointAdmission(t, e, &f, s)
			e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).RemoveActiveFlags(common.DynamicESDTFlag, common.MetaESDTSetFlag)
			input := qualEndpointInput(e, f, request)
			before, err := s.RootHash()
			require.NoError(t, err)
			code, err := e.registerDRWATokenEndpoint(admit, input, request, f.profile)
			require.Error(t, err)
			require.Equal(t, vmcommon.UserError, code)
			after, readErr := s.RootHash()
			require.NoError(t, readErr)
			require.Equal(t, before, after)
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
		})
	}
}
