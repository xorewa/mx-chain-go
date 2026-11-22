package transaction

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/guardians"
	txdata "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	triemock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Real account metadata and real guardian selection/decoding. The data tracker
// supplies explicit serialized account bytes; no trie/factory credit is claimed.
func TestQualPartialsG24ActiveGuardianSelection(t *testing.T) {
	codec := &marshal.GogoProtoMarshalizer{}
	older, active, pending := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	encoded, err := codec.Marshal(&guardians.Guardians{Slice: []*guardians.Guardian{
		{Address: pending, ActivationEpoch: 10}, {Address: older, ActivationEpoch: 3}, {Address: active, ActivationEpoch: 5},
	}})
	require.NoError(t, err)
	for _, epoch := range []uint32{2, 3, 5, 9, 10, 11} {
		t.Run(string(rune('a'+epoch)), func(t *testing.T) {
			reads, writes := 0, 0
			tracker := &triemock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				require.Equal(t, []byte(core.ProtectedKeyPrefix+core.GuardiansKeyIdentifier), key)
				reads++
				return bytes.Clone(encoded), 0, nil
			}, SaveKeyValueCalled: func(_, _ []byte) error { writes++; return nil }}
			account, err := accounts.NewUserAccount(bytes.Repeat([]byte{7}, 32), tracker, &triemock.TrieLeafParserStub{})
			require.NoError(t, err)
			account.SetCodeMetadata((&vmcommon.CodeMetadata{Guarded: true}).ToBytes())
			checker, err := guardian.NewGuardedAccount(codec, &epochNotifier.EpochNotifierStub{}, 2)
			require.NoError(t, err)
			checker.EpochConfirmed(epoch, 0)
			processor := &baseTxProcessor{guardianChecker: checker, txVersionChecker: &testscommon.TxVersionCheckerStub{
				IsGuardedTransactionCalled: func(tx *txdata.Transaction) bool { return tx.Options&txdata.MaskGuardedTransaction != 0 },
			}}
			want := older
			if epoch >= 5 {
				want = active
			}
			if epoch >= 10 {
				want = pending
			}
			tx := &txdata.Transaction{Options: txdata.MaskGuardedTransaction, GuardianAddr: bytes.Clone(want)}
			err = processor.VerifyGuardian(tx, account)
			if epoch < 3 {
				require.ErrorIs(t, err, process.ErrTransactionNotExecutable)
				require.Contains(t, err.Error(), process.ErrAccountHasNoActiveGuardian.Error())
			} else {
				require.NoError(t, err)
				selected, selectionErr := checker.GetActiveGuardian(account)
				require.NoError(t, selectionErr)
				require.Equal(t, want, selected)
				tx.GuardianAddr = bytes.Repeat([]byte{9}, 32)
				err = processor.VerifyGuardian(tx, account)
				require.ErrorIs(t, err, process.ErrTransactionNotExecutable)
				require.Contains(t, err.Error(), process.ErrTransactionAndAccountGuardianMismatch.Error())
			}
			require.Positive(t, reads)
			require.Zero(t, writes)
		})
	}
}
