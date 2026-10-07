package drwa

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	nativeTransaction "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAPrivilegedConsentNativeSignatures(t *testing.T) {
	for _, name := range []string{"unguarded", "guarded", "wrong_owner_signature", "wrong_guardian_signature", "missing_guardian_signature", "changed_scope_after_signing", "guardian_fields_unguarded", "relayed_v3_unguarded", "relayed_v3_guarded", "wrong_relayer_signature"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			keygen := integrationTests.TestKeyGenForAccounts
			ownerSK, ownerPK := keygen.GeneratePair()
			guardianSK, guardianPK := keygen.GeneratePair()
			relayerSK, relayerPK := keygen.GeneratePair()
			address, err := ownerPK.ToByteArray()
			require.NoError(t, err)
			guardianAddress, err := guardianPK.ToByteArray()
			require.NoError(t, err)
			relayerAddress, err := relayerPK.ToByteArray()
			require.NoError(t, err)
			require.False(t, core.IsSmartContractAddress(address))
			a, err := ctx.Accounts.LoadAccount(address)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			require.NoError(t, u.AddToBalance(big.NewInt(1000000000)))
			epoch := uint32(0)
			guarded := name != "unguarded" && name != "wrong_owner_signature" && name != "guardian_fields_unguarded" && name != "relayed_v3_unguarded"
			relayed := name == "relayed_v3_unguarded" || name == "relayed_v3_guarded" || name == "wrong_relayer_signature"
			if guarded {
				// Configure the actual native guardian state; the tested consent
				// transaction itself traverses native signature + execution gates.
				require.NoError(t, ctx.GuardedAccountsHandler.SetGuardian(u.(vmcommon.UserAccountHandler), guardianAddress, nil, []byte("fixture-service")))
				epoch = vm.EpochGuardianDelay
				ctx.EpochNotifier.CheckEpoch(&block.Header{Epoch: epoch})
				u.SetCodeMetadata((&vmcommon.CodeMetadata{Guarded: true}).ToBytes())
			}
			require.NoError(t, ctx.Accounts.SaveAccount(u))
			if relayed {
				relayer, loadErr := ctx.Accounts.LoadAccount(relayerAddress)
				require.NoError(t, loadErr)
				require.NoError(t, relayer.(state.UserAccountHandler).AddToBalance(big.NewInt(1000000000)))
				require.NoError(t, ctx.Accounts.SaveAccount(relayer))
			}
			candidate, containment := qualConsentInstall(t, ctx, epoch)
			s := qualConsentScope()
			s.Address = address
			tx := vm.CreateTransaction(u.GetNonce(), big.NewInt(0), address, address, 1, 1000000, qualConsentData(s))
			tx.ChainID = []byte("fixture-chain")
			tx.Version = 2
			if guarded || name == "guardian_fields_unguarded" {
				tx.GuardianAddr = guardianAddress
			}
			if guarded {
				tx.Options = transaction.MaskGuardedTransaction
			}
			if relayed {
				tx.RelayerAddr = relayerAddress
			}
			message, err := tx.GetDataForSigning(integrationTests.TestAddressPubkeyConverter, integrationTests.TestTxSignMarshalizer, integrationTests.TestTxSignHasher)
			require.NoError(t, err)
			tx.Signature, err = integrationTests.TestSingleSigner.Sign(ownerSK, message)
			require.NoError(t, err)
			if guarded {
				tx.GuardianSignature, err = integrationTests.TestSingleSigner.Sign(guardianSK, message)
				require.NoError(t, err)
			}
			if relayed {
				tx.RelayerSignature, err = integrationTests.TestSingleSigner.Sign(relayerSK, message)
				require.NoError(t, err)
			}
			switch name {
			case "wrong_owner_signature":
				tx.Signature[0] ^= 1
			case "wrong_guardian_signature":
				tx.GuardianSignature[0] ^= 1
			case "wrong_relayer_signature":
				tx.RelayerSignature[0] ^= 1
			case "missing_guardian_signature":
				tx.GuardianSignature = nil
			case "changed_scope_after_signing":
				s.Target = []byte("substituted target")
				tx.Data = qualConsentData(s)
			}
			raw, err := ctx.Marshalizer.Marshal(tx)
			require.NoError(t, err)
			intercepted, err := nativeTransaction.NewInterceptedTransaction(raw, ctx.Marshalizer, integrationTests.TestTxSignMarshalizer, integrationTests.TestHasher,
				keygen, integrationTests.TestSingleSigner, integrationTests.TestAddressPubkeyConverter, ctx.ShardCoordinator, ctx.EconomicsData,
				&testscommon.WhiteListHandlerStub{}, smartContract.NewArgumentParser(), tx.ChainID, false, integrationTests.TestTxSignHasher, versioning.NewTxVersionChecker(1), ctx.EnableEpochsHandler)
			require.NoError(t, err)
			err = intercepted.CheckValidity()
			if name == "unguarded" || name == "guarded" || name == "relayed_v3_unguarded" || name == "relayed_v3_guarded" {
				require.NoError(t, err)
				code, err := candidate.ExecuteNativeTransaction(intercepted.Transaction().(*transaction.Transaction), ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, code)
				_, outputs, err := containment.Commit()
				require.NoError(t, err)
				require.Len(t, outputs, 1)
				a, err = ctx.Accounts.GetExistingAccount(address)
				require.NoError(t, err)
				value, _, err := a.(state.UserAccountHandler).RetrieveValue(experimentalPrivilegedConsentKey)
				require.NoError(t, err)
				require.Equal(t, encodeExperimentalConsent(s, 1, epoch), value)
				if relayed {
					// Native fee payer is the relayer (baseProcess.go L244-270).
					// The new protected slot must preserve the owner's balance.
					require.Equal(t, big.NewInt(1000000000), a.(state.UserAccountHandler).GetBalance())
					relayer, loadErr := ctx.Accounts.GetExistingAccount(relayerAddress)
					require.NoError(t, loadErr)
					require.Negative(t, relayer.(state.UserAccountHandler).GetBalance().Cmp(big.NewInt(1000000000)))
				}
			} else {
				require.Error(t, err)
				a, err = ctx.Accounts.GetExistingAccount(address)
				require.NoError(t, err)
				value, _, _ := a.(state.UserAccountHandler).RetrieveValue(experimentalPrivilegedConsentKey)
				require.Empty(t, value)
				require.Zero(t, a.GetNonce())
			}
		})
	}
}
