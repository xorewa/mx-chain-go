package core

import (
	"fmt"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/configs"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	nativeErrors "github.com/multiversx/mx-chain-go/errors"
	cryptoFactory "github.com/multiversx/mx-chain-go/factory/crypto"
	"github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/stretchr/testify/require"
)

// Loaded public candidate files; the holder double exposes actual native
// converter/process-config instances. Key absence is synthetic. Native fresh
// ephemeral keys stay in memory: no private bytes are serialized or retained.
func qualDRWACandidateCryptoArgs(t *testing.T) cryptoFactory.CryptoComponentsFactoryArgs {
	t.Helper()
	cfg, err := common.LoadMainConfig(qualDRWACandidateGenesisPath(t, "config.toml"))
	require.NoError(t, err)
	epochs, err := common.LoadEpochConfig(qualDRWACandidateGenesisPath(t, "enableEpochs.toml"))
	require.NoError(t, err)
	prefs, err := common.LoadPreferencesConfig(qualDRWACandidateGenesisPath(t, "prefs.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.ValidatorPubkeyConverter)
	require.NoError(t, err)
	processCfg, err := configs.NewProcessConfigsHandler(cfg.GeneralSettings.ProcessConfigsByEpoch,
		cfg.GeneralSettings.ProcessConfigsByRound, forking.NewGenericRoundNotifier())
	require.NoError(t, err)
	return cryptoFactory.CryptoComponentsFactoryArgs{
		Config: *cfg, EnableEpochs: epochs.EnableEpochs, PrefsConfig: *prefs,
		ValidatorKeyPemFileName: "synthetic-absent-validator-key.pem",
		CoreComponentsHolder: &mock.CoreComponentsMock{
			ValPubKeyConv: converter, ProcessConfigsHandlerField: processCfg,
		},
		KeyLoader: &mock.KeyLoaderStub{
			LoadKeyCalled:     func(string, int) ([]byte, string, error) { return nil, "", os.ErrNotExist },
			LoadAllKeysCalled: func(string) ([][]byte, []string, error) { return nil, nil, os.ErrNotExist },
		},
		// Empty P2P filename takes the native ephemeral-generation branch.
	}
}

func TestQualDRWACandidateCryptoFactory(t *testing.T) {
	for _, verifyMessages := range []bool{false, true} {
		t.Run(fmt.Sprintf("healthy_message_verification_%t", verifyMessages), func(t *testing.T) {
			args := qualDRWACandidateCryptoArgs(t)
			args.ActivateBLSPubKeyMessageVerification = verifyMessages // explicit experiment, no deployment selection
			require.Equal(t, "bls", args.Config.Consensus.Type)
			require.Equal(t, "blake2b", args.Config.MultisigHasher.Type)
			original := append([]config.MultiSignerConfig(nil), args.EnableEpochs.BLSMultiSignerEnableEpoch...)
			require.Equal(t, []config.MultiSignerConfig{{EnableEpoch: 0, Type: "no-KOSK"}, {EnableEpoch: 1, Type: "KOSK"}}, original)
			factory, err := cryptoFactory.NewCryptoComponentsFactory(args)
			require.NoError(t, err)
			handler, err := cryptoFactory.NewManagedCryptoComponents(factory)
			require.NoError(t, err)
			require.NoError(t, handler.Create())
			t.Cleanup(func() { require.NoError(t, handler.Close()) })
			require.NoError(t, handler.CheckSubcomponents())
			epoch0, err := handler.GetMultiSigner(0)
			require.NoError(t, err)
			epoch1, err := handler.GetMultiSigner(1)
			require.NoError(t, err)
			epoch3, err := handler.GetMultiSigner(3)
			require.NoError(t, err)
			require.NotSame(t, epoch0, epoch1)
			require.Same(t, epoch1, epoch3)
			require.Equal(t, original, args.EnableEpochs.BLSMultiSignerEnableEpoch)
			message := []byte("T09 native crypto construction control")
			signature, err := handler.BlockSigner().Sign(handler.PrivateKey(), message)
			require.NoError(t, err)
			require.NoError(t, handler.BlockSigner().Verify(handler.PublicKey(), message, signature))
			require.Error(t, handler.BlockSigner().Verify(handler.PublicKey(), []byte("altered message"), signature))
		})
	}
	for _, fault := range []string{"consensus", "bls_hasher", "empty_signers", "no_epoch_zero", "future_signer", "cache"} {
		t.Run(fault, func(t *testing.T) {
			args := qualDRWACandidateCryptoArgs(t)
			var want error
			switch fault {
			case "consensus":
				args.Config.Consensus.Type, want = "unsupported", nativeErrors.ErrInvalidConsensusConfig
			case "bls_hasher":
				args.Config.MultisigHasher.Type, want = "sha256", nativeErrors.ErrMultiSigHasherMissmatch
			case "empty_signers":
				args.EnableEpochs.BLSMultiSignerEnableEpoch, want = nil, nativeErrors.ErrMissingMultiSignerConfig
			case "no_epoch_zero":
				args.EnableEpochs.BLSMultiSignerEnableEpoch = []config.MultiSignerConfig{{EnableEpoch: 1, Type: "KOSK"}}
				want = nativeErrors.ErrMissingEpochZeroMultiSignerConfig
			case "future_signer":
				args.EnableEpochs.BLSMultiSignerEnableEpoch[1].Type, want = "unsupported", nativeErrors.ErrSignerNotSupported
			case "cache":
				args.Config.PublicKeyPIDSignature.Type = "unsupported"
			}
			factory, err := cryptoFactory.NewCryptoComponentsFactory(args)
			require.NoError(t, err)
			components, err := factory.Create()
			require.Error(t, err)
			require.Nil(t, components)
			if want != nil {
				require.ErrorIs(t, err, want)
			}
		})
	}
}
