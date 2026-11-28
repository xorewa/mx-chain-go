package systemSmartContracts

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-29, INV-0: an ordinary token issue and an ordinary mint-with-transfer
// through the native ESDT System SC give the same return code, gas, output
// accounts, transfers, logs and stored token whether the chain carries no DRWA
// state at all or carries an exhausted DRWA retained budget and a full
// permanent registry. The exhausted values are experimental fixture data.
func TestQualSP229OrdinaryIssueAndTransferWithExhaustedLimits(t *testing.T) {
	exhausted := map[string][]byte{
		core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget": bytes.Repeat([]byte{0xff}, 32),
		core.ProtectedKeyPrefix + "DRWA@registry@count":         binary.BigEndian.AppendUint64(nil, ^uint64(0)),
	}
	for _, function := range []string{"issue", "mint"} {
		t.Run(function, func(t *testing.T) {
			var baseline *vmcommon.VMOutput
			var baselineToken *ESDTDataV2
			for _, limits := range []bool{false, true} {
				owner := bytes.Repeat([]byte{1}, 32)
				id := []byte("ORD-abcdef")
				args := createMockArgumentsForESDT()
				args.ESDTSCAddress = core.ESDTSCAddress
				args.GasCost.MetaChainSystemSCsCost.ESDTOperations = 7
				args.GasCost.MetaChainSystemSCsCost.ESDTIssue = 11
				token := &ESDTDataV2{OwnerAddress: owner, TokenType: []byte(core.FungibleESDT), Mintable: true, MintedValue: big.NewInt(100), BurntValue: big.NewInt(0)}
				prestate, err := args.Marshalizer.Marshal(token)
				require.NoError(t, err)
				drwaReads := 0
				contextArgs := createDefaultEeiArgs()
				contextArgs.BlockChainHook = &mock.BlockChainHookStub{GetStorageDataCalled: func(address, key []byte) ([]byte, uint32, error) {
					if function == "mint" && bytes.Equal(address, core.ESDTSCAddress) && bytes.Equal(key, id) {
						return bytes.Clone(prestate), 0, nil
					}
					if limits && bytes.Equal(address, core.SystemAccountAddress) {
						if value, exists := exhausted[string(key)]; exists {
							drwaReads++
							return bytes.Clone(value), 0, nil
						}
					}
					return nil, 0, nil
				}}
				classifier := &qualGateG21OrdinaryClassifier{}
				if limits {
					contextArgs.DRWAClassifier = classifier
				}
				host, err := NewVMContext(contextArgs)
				require.NoError(t, err)
				host.SetSCAddress(core.ESDTSCAddress)
				args.Eei = host
				contract, err := NewESDTSmartContract(args)
				require.NoError(t, err)
				input := getDefaultVmInputForFunc(function, [][]byte{id, {7}})
				input.CallerAddr, input.RecipientAddr, input.GasProvided = owner, core.ESDTSCAddress, 100
				if function == "issue" {
					input.Arguments = [][]byte{[]byte("OrdinaryName"), []byte("ORD"), big.NewInt(100).Bytes(), big.NewInt(6).Bytes()}
					input.CallValue, _ = big.NewInt(0).SetString(args.ESDTSCConfig.BaseIssuingCost, 10)
				}
				host.SetGasProvided(input.GasProvided)
				output, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
					code := contract.Execute(input)
					result := host.CreateVMOutput()
					result.ReturnCode = code
					return result, nil
				})
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, output.ReturnCode, output.ReturnMessage)
				require.Less(t, output.GasRemaining, input.GasProvided)
				stored := token
				if function == "mint" {
					stored, err = contract.getExistingToken(id)
					require.NoError(t, err)
					require.Len(t, output.OutputAccounts[string(owner)].OutputTransfers, 1)
				} else {
					require.NotEmpty(t, output.OutputAccounts)
				}
				require.Zero(t, drwaReads, "the ordinary path reads no DRWA limit or counter")
				if !limits {
					baseline, baselineToken = output, stored
					continue
				}
				require.Equal(t, baseline, output)
				require.Equal(t, baselineToken, stored)
			}
		})
	}
}
