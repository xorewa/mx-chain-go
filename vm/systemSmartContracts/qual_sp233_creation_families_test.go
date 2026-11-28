package systemSmartContracts

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

// SP2-33, Part A L6388-6393: "For every supported family, test the actual
// protected creation path with the cleanup flag active and across any
// supported flag boundary; prove no metachain burn-for-all role". The path is
// registerDRWAToken over the real account store; the role is read back by the
// production reader of the metachain record. The native set, unset and type
// fan-out the creation produced is listed for each boundary: it is what the
// shards refuse for a regulated token (process/drwa tests).
func TestQualSP233ProtectedCreationLeavesNoMetachainBurnRoleForAnyFamily(t *testing.T) {
	families := []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT}
	for _, family := range families {
		for _, cleanup := range []bool{true, false} {
			for _, dynamic := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/cleanup_%t/dynamic_%t", family, cleanup, dynamic), func(t *testing.T) {
					e, ctx, s, r, c, request := qualNativeRegistration(t)
					flags := e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
					flags.RemoveActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.DynamicESDTFlag)
					if cleanup {
						flags.AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag)
					}
					if dynamic {
						flags.AddActiveFlags(common.DynamicESDTFlag)
					}
					request.family = []byte(family)
					if family != core.FungibleESDT {
						request.properties = append(request.properties, []byte(canTransferNFTCreateRole), []byte("true"))
					}
					require.NoError(t, e.registerDRWAToken(r, request))
					id := ctx.output[0]
					reader, err := NewDRWABurnRoleReader(s, e.marshalizer)
					require.NoError(t, err)
					require.False(t, reader.IsInterfaceNil())

					// Inside the registration's own journal step, and after commit
					// and reopen: no role.
					granted, err := reader.HasBurnForAllRole(id)
					require.NoError(t, err)
					require.False(t, granted)
					roots, outputs, err := c.Commit()
					require.NoError(t, err)
					require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
					granted, err = reader.HasBurnForAllRole(id)
					require.NoError(t, err)
					require.False(t, granted, "the committed metachain record has no burn-for-all role")
					record := &ESDTDataV2{}
					require.NoError(t, e.marshalizer.Unmarshal(record, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, id)))
					require.Empty(t, record.SpecialRoles)

					// The native fan-out this boundary produced, per function.
					produced := map[string]int{}
					for _, account := range outputs[0].OutputAccounts {
						for _, transfer := range account.OutputTransfers {
							produced[strings.SplitN(string(transfer.Data), "@", 2)[0]]++
							require.Contains(t, string(transfer.Data), hex.EncodeToString(id))
						}
					}
					enable, disable := produced[vmcommon.BuiltInFunctionESDTSetBurnRoleForAll], produced[vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll]
					require.Equal(t, enable, disable, "every enable message the creation produced has its disable message")
					require.Equal(t, cleanup, enable != 0, "the default grant exists exactly with the cleanup flag")
					require.Equal(t, dynamic, produced[core.ESDTSetTokenType] != 0, "the type is sent exactly with the dynamic flag")
				})
			}
		}
	}
}

// The ordinary creation path keeps its default: with the cleanup flag an
// ordinary token has the burn-for-all role, and the reader says so. The reader
// refuses what it cannot read exactly.
func TestQualSP233BurnRoleReaderAndTheOrdinaryDefault(t *testing.T) {
	e, _, s, _, _, _ := qualNativeRegistration(t)
	flags := e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
	flags.AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag)
	id, token, err := e.createNewToken([]byte(strings.Repeat("o", 32)), []byte("OrdinaryToken"), []byte("ORDIN"), big.NewInt(0), 0, nil, []byte(core.FungibleESDT))
	require.NoError(t, err)
	require.True(t, checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)), "the ordinary default is unchanged")
	// The native contract's write, as the processor applies it.
	raw, err := e.marshalizer.Marshal(token)
	require.NoError(t, err)
	account, err := s.GetExistingAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	require.NoError(t, user.SaveKeyValue(id, raw))
	require.NoError(t, user.SaveKeyValue([]byte("CORRUPT-0a1b2c"), []byte{0xff, 0xff, 0xff}))
	require.NoError(t, s.SaveAccount(user))

	reader, err := NewDRWABurnRoleReader(s, e.marshalizer)
	require.NoError(t, err)
	granted, err := reader.HasBurnForAllRole(id)
	require.NoError(t, err)
	require.True(t, granted)

	_, err = reader.HasBurnForAllRole([]byte("ABSENT-0a1b2c"))
	require.ErrorIs(t, err, ErrDRWABurnRoleRead, "a token without a record is not a token without the role")
	_, err = reader.HasBurnForAllRole([]byte("CORRUPT-0a1b2c"))
	require.ErrorIs(t, err, ErrDRWABurnRoleRead)

	fault := errors.New("selected read fault")
	failing, err := NewDRWABurnRoleReader(&stateMock.AccountsStub{GetExistingAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
		return nil, fault
	}}, e.marshalizer)
	require.NoError(t, err)
	_, err = failing.HasBurnForAllRole(id)
	require.ErrorIs(t, err, fault)
	require.ErrorIs(t, err, ErrDRWABurnRoleRead)
	other, err := NewDRWABurnRoleReader(&stateMock.AccountsStub{GetExistingAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
		return &stateMock.PeerAccountHandlerMock{}, nil
	}}, e.marshalizer)
	require.NoError(t, err)
	_, err = other.HasBurnForAllRole(id)
	require.ErrorIs(t, err, ErrDRWABurnRoleRead)
	items, err := NewDRWABurnRoleReader(&stateMock.AccountsStub{GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return &stateMock.StateUserAccountHandlerStub{RetrieveValueCalled: func([]byte) ([]byte, uint32, error) { return nil, 0, fault }}, nil
	}}, e.marshalizer)
	require.NoError(t, err)
	_, err = items.HasBurnForAllRole(id)
	require.ErrorIs(t, err, fault)

	_, err = NewDRWABurnRoleReader(nil, e.marshalizer)
	require.ErrorIs(t, err, ErrDRWABurnRoleRead)
	_, err = NewDRWABurnRoleReader(s, marshal.Marshalizer(nil))
	require.ErrorIs(t, err, ErrDRWABurnRoleRead)
	require.True(t, (*DRWABurnRoleReader)(nil).IsInterfaceNil())
}
