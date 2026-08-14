package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestCharacterizationESDTIssueRequiresExactFeeAndMakesCallerOwner(t *testing.T) {
	t.Parallel()

	for _, wrongFee := range []*big.Int{big.NewInt(999), big.NewInt(1001)} {
		args := createMockArgumentsForESDT()
		eei := createDefaultEei()
		args.Eei = eei
		esdtSC, err := NewESDTSmartContract(args)
		require.NoError(t, err)

		input := getDefaultVmInputForFunc("issue", [][]byte{
			[]byte("RegulatedAsset"),
			[]byte("RWA"),
			big.NewInt(123).Bytes(),
			big.NewInt(18).Bytes(),
		})
		input.CallValue = new(big.Int).Set(wrongFee)
		input.GasProvided = args.GasCost.MetaChainSystemSCsCost.ESDTIssue
		eei.gasRemaining = input.GasProvided

		require.Equal(t, vmcommon.OutOfFunds, esdtSC.Execute(input))
		require.Equal(t, "callValue not equals with baseIssuingCost", eei.returnMessage)
		require.Empty(t, eei.logs)
	}

	args := createMockArgumentsForESDT()
	eei := createDefaultEei()
	args.Eei = eei
	esdtSC, err := NewESDTSmartContract(args)
	require.NoError(t, err)

	input := getDefaultVmInputForFunc("issue", [][]byte{
		[]byte("RegulatedAsset"),
		[]byte("RWA"),
		big.NewInt(123).Bytes(),
		big.NewInt(18).Bytes(),
	})
	input.CallValue = new(big.Int).Set(esdtSC.baseIssuingCost)
	input.GasProvided = args.GasCost.MetaChainSystemSCsCost.ESDTIssue
	eei.gasRemaining = input.GasProvided

	require.Equal(t, vmcommon.Ok, esdtSC.Execute(input))
	require.NotEmpty(t, eei.logs)
	issueLog := eei.logs[len(eei.logs)-1]
	require.Equal(t, []byte("issue"), issueLog.Identifier)
	tokenID := issueLog.Topics[0]

	token, err := esdtSC.getExistingToken(tokenID)
	require.NoError(t, err)
	require.Equal(t, input.CallerAddr, token.OwnerAddress)
	require.Equal(t, int64(123), token.MintedValue.Int64())

	ownerOutput := eei.outputAccounts[string(input.CallerAddr)]
	require.NotNil(t, ownerOutput)
	require.NotEmpty(t, ownerOutput.OutputTransfers)
	require.True(t, bytes.HasPrefix(
		ownerOutput.OutputTransfers[0].Data,
		[]byte(core.BuiltInFunctionESDTTransfer+"@"),
	))
}

func TestCharacterizationESDTZeroSupplyDependsOnGlobalMintBurnEpochFlag(t *testing.T) {
	t.Parallel()

	args := createMockArgumentsForESDT()
	eei := createDefaultEei()
	args.Eei = eei
	enableEpochs, ok := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
	require.True(t, ok)
	esdtSC, err := NewESDTSmartContract(args)
	require.NoError(t, err)

	input := getDefaultVmInputForFunc("issue", [][]byte{
		[]byte("RegulatedAsset"),
		[]byte("RWA"),
		big.NewInt(0).Bytes(),
		big.NewInt(18).Bytes(),
	})
	input.CallValue = new(big.Int).Set(esdtSC.baseIssuingCost)
	input.GasProvided = args.GasCost.MetaChainSystemSCsCost.ESDTIssue
	eei.gasRemaining = input.GasProvided

	// GlobalMintBurnFlag is active before GlobalMintBurnDisableEpoch, and in that
	// state a zero initial supply is rejected.
	require.Equal(t, vmcommon.UserError, esdtSC.Execute(input))
	require.Equal(t, "negative initial supply was provided", eei.returnMessage)

	// At and after GlobalMintBurnDisableEpoch the flag is inactive; the exact
	// same zero-supply issue request is accepted.
	enableEpochs.RemoveActiveFlags(common.GlobalMintBurnFlag)
	eei.returnMessage = ""
	eei.gasRemaining = input.GasProvided
	require.Equal(t, vmcommon.Ok, esdtSC.Execute(input))
	require.NotEmpty(t, eei.output)

	token, err := esdtSC.getExistingToken(eei.output[len(eei.output)-1])
	require.NoError(t, err)
	require.Zero(t, token.MintedValue.Sign())
	require.Equal(t, input.CallerAddr, token.OwnerAddress)
}

func TestCharacterizationRegisterAndSetAllRolesCreatesImmediateCallerRoles(t *testing.T) {
	t.Parallel()

	args := createMockArgumentsForESDT()
	eei := createDefaultEei()
	args.Eei = eei
	esdtSC, err := NewESDTSmartContract(args)
	require.NoError(t, err)

	input := getDefaultVmInputForFunc("registerAndSetAllRoles", [][]byte{
		[]byte("RegulatedAsset"),
		[]byte("RWA"),
		[]byte("FNG"),
		big.NewInt(18).Bytes(),
	})
	input.CallValue = new(big.Int).Set(esdtSC.baseIssuingCost)
	input.GasProvided = args.GasCost.MetaChainSystemSCsCost.ESDTIssue
	eei.gasRemaining = input.GasProvided

	require.Equal(t, vmcommon.Ok, esdtSC.Execute(input))
	require.NotEmpty(t, eei.output)
	tokenID := eei.output[len(eei.output)-1]
	token, err := esdtSC.getExistingToken(tokenID)
	require.NoError(t, err)
	require.Equal(t, input.CallerAddr, token.OwnerAddress)
	require.Zero(t, token.MintedValue.Sign())

	roles, _ := getRolesForAddress(token, input.CallerAddr)
	require.Contains(t, roles.Roles, []byte(core.ESDTRoleLocalMint))
	require.Contains(t, roles.Roles, []byte(core.ESDTRoleLocalBurn))

	callerOutput := eei.outputAccounts[string(input.CallerAddr)]
	require.NotNil(t, callerOutput)
	require.NotEmpty(t, callerOutput.OutputTransfers)
	require.True(t, bytes.HasPrefix(
		callerOutput.OutputTransfers[0].Data,
		[]byte(core.BuiltInFunctionSetESDTRole+"@"),
	))
}
