package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native crawler and owning hook only. Classification and public bypass denial
// remain restricted to SP2-25/SP2-68, with metadata composition at SP2-40.
func TestQualTransitionR08MetadataNative(t *testing.T) {
	for _, deleteMetadata := range []bool{false, true} {
		for _, failure := range []string{"none", "late save", "later token"} {
			t.Run(fmt.Sprintf("delete %t %s should preserve every key at the native hook boundary", deleteMetadata, failure), func(t *testing.T) {
				store := qualRegistrationStore(t, 0)
				marshaller := &marshal.GogoProtoMarshalizer{}
				name := vmcommon.ESDTAddMetadata
				if deleteMetadata {
					name = vmcommon.ESDTDeleteMetadata
				}
				function, err := builtInFunctions.NewESDTDeleteMetadataFunc(builtInFunctions.ArgsNewESDTDeleteMetadata{
					Marshalizer: marshaller, Accounts: store, AllowedAddress: bytes.Clone(qualContainmentAddress),
					Delete: deleteMetadata, EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
				})
				require.NoError(t, err)
				out, err := function.ProcessBuiltinFunction(nil, nil, nil)
				require.Nil(t, out)
				require.ErrorIs(t, err, builtInFunctions.ErrNilVmInput)
				hook, _ := qualT42Hook(t, store, 1, false)
				require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(name, function))
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0)}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: name}
				before := make(map[string][]byte)
				metadata := make(map[string]*esdt.MetaData)
				account, err := store.LoadAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				system := account.(state.UserAccountHandler)
				for _, token := range []string{"TOKEN-abcdef", "OTHER-abcdef"} {
					if deleteMetadata {
						input.Arguments = append(input.Arguments, []byte(token), []byte{1}, []byte{1}, []byte{2})
					}
					for nonce := uint64(1); nonce <= 2; nonce++ {
						key := append(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), []byte(token)...), new(big.Int).SetUint64(nonce).Bytes()...)
						if deleteMetadata {
							before[string(key)] = []byte("prior " + token + string(rune('0'+nonce)))
							require.NoError(t, system.SaveKeyValue(key, before[string(key)]))
						} else {
							value := &esdt.MetaData{Nonce: nonce, Name: []byte(token)}
							encoded, marshalErr := marshaller.Marshal(value)
							require.NoError(t, marshalErr)
							input.Arguments = append(input.Arguments, []byte(token), new(big.Int).SetUint64(nonce).Bytes(), encoded)
							before[string(key)], metadata[string(key)] = nil, value
						}
					}
				}
				sentinel := "fixture/transition/unrelated"
				require.NoError(t, system.SaveKeyValue([]byte(sentinel), []byte("retained")))
				require.NoError(t, store.SaveAccount(system))
				root, err := store.Commit()
				require.NoError(t, err)
				journal := store.JournalLen()
				fault := errors.New("qualification late native save")
				if failure == "late save" {
					store.saveErr = fault // Existing fixture faults after real SaveAccount.
				}
				if failure == "later token" {
					index := 6 // Two add triples precede the second token.
					if deleteMetadata {
						index = 4
					}
					input.Arguments[index] = []byte("bad")
				}
				out, err = hook.ProcessBuiltInFunction(input)
				store.saveErr = nil
				if failure == "none" {
					require.NoError(t, err)
					require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, out)
				} else {
					require.Nil(t, out)
					if failure == "late save" {
						require.ErrorIs(t, err, fault)
					} else {
						require.ErrorIs(t, err, builtInFunctions.ErrInvalidTokenID)
					}
					after, rootErr := store.RootHash()
					require.NoError(t, rootErr)
					require.Equal(t, root, after)
					require.Equal(t, journal, store.JournalLen())
					require.Equal(t, 1, store.reverts)
				}
				committed, err := store.Commit()
				require.NoError(t, err)
				if failure != "none" {
					require.Equal(t, root, committed)
				}
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				for key, old := range before {
					actual := qualRegistryValue(t, store, key)
					if failure != "none" {
						require.Equal(t, old, actual)
					} else if deleteMetadata {
						require.Empty(t, actual)
					} else {
						token := &esdt.ESDigitalToken{}
						require.NoError(t, marshaller.Unmarshal(token, actual))
						require.Equal(t, &esdt.ESDigitalToken{Value: big.NewInt(0), Type: uint32(core.NonFungible), TokenMetaData: metadata[key]}, token)
					}
				}
				require.Equal(t, []byte("retained"), qualRegistryValue(t, store, sentinel))
			})
		}
	}
}
