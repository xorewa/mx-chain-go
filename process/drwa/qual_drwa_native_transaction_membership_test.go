package drwa

import (
	"bytes"
	stdsha256 "crypto/sha256"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

type qualNativeMemberHasher struct {
	hashing.Hasher
	beforeSize func()
}

func (h *qualNativeMemberHasher) Size() int {
	h.beforeSize()
	return h.Hasher.Size()
}

func TestQualDRWANativeTransactionMembership(t *testing.T) {
	// These are native protobuf objects and standard-library SHA-256 vectors.
	// The one-byte signature supplies only CheckIntegrity's nonnil shape.
	codec := &marshal.GogoProtoMarshalizer{}
	hasher := sha256.NewSha256()
	reader := &ResultAccountReader{args: ArgsResultAccountReader{Marshaller: codec, Hasher: hasher}}
	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0}
	makeTx := func(nonce uint64) *transaction.Transaction {
		return &transaction.Transaction{
			Nonce: nonce, Value: big.NewInt(0), Signature: []byte{1},
			SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
			GasLimit: 120000, Data: []byte("ESDTTransfer@544f4b454e2d616263646566@01"),
		}
	}
	encode := func(value interface{}) []byte {
		raw, err := codec.Marshal(value)
		require.NoError(t, err)
		return raw
	}
	hash := func(raw []byte) []byte {
		value := stdsha256.Sum256(raw)
		return value[:]
	}
	tx := makeTx(17)
	rawTx := encode(tx)
	txHash := hash(rawTx)
	otherHash := hash(encode(makeTx(18)))
	makeMini := func(hashes ...[]byte) *block.MiniBlock {
		return &block.MiniBlock{Type: block.TxBlock, SenderShardID: 1, ReceiverShardID: 0, TxHashes: hashes}
	}
	rawMini := encode(makeMini(otherHash, txHash))
	miniHash := hash(rawMini)
	budget := len(miniHash) + len(txHash) + len(rawMini) + len(rawTx)

	decode := (*ResultAccountReader).decodeNativeTransactionMember

	t.Run("wrong_position_in_hash_bound_pair", func(t *testing.T) {
		mini, original, err := decode(reader, coordinator, miniHash, txHash, rawMini, rawTx, 1, 0, 0, budget)
		require.ErrorIs(t, err, ErrInvalidAccountWitness)
		require.Nil(t, mini)
		require.Nil(t, original)
	})
	t.Run("exact_position_preserves_full_order", func(t *testing.T) {
		mini, original, err := decode(reader, coordinator, miniHash, txHash, rawMini, rawTx, 1, 0, 1, budget)
		require.NoError(t, err)
		require.Equal(t, [][]byte{otherHash, txHash}, mini.TxHashes)
		require.Equal(t, tx, original)
		mini.TxHashes[1][0] ^= 1
		original.Data[0] ^= 1
		require.Equal(t, miniHash, hash(rawMini))
		require.Equal(t, txHash, hash(rawTx))
	})
	t.Run("freeze_before_native_dependencies", func(t *testing.T) {
		mh, th, mb, tr := bytes.Clone(miniHash), bytes.Clone(txHash), bytes.Clone(rawMini), bytes.Clone(rawTx)
		mutated := false
		probe := &qualNativeMemberHasher{Hasher: hasher, beforeSize: func() {
			mutated = true
			clear(mh)
			clear(th)
			clear(mb)
			clear(tr)
		}}
		r := &ResultAccountReader{args: ArgsResultAccountReader{Marshaller: codec, Hasher: probe}}
		mini, original, err := decode(r, coordinator, mh, th, mb, tr, 1, 0, 1, budget)
		require.NoError(t, err)
		require.True(t, mutated)
		require.Equal(t, [][]byte{otherHash, txHash}, mini.TxHashes)
		require.Equal(t, tx, original)
	})
	t.Run("native_miniblock_decode_does_not_require_remarshal_equality", func(t *testing.T) {
		// Native protobuf decoding accepts the repeated sender-shard singleton.
		// The exact original bytes, including that field, supply the expected hash.
		nativeBytes := append(bytes.Clone(rawMini), 0x18, 0x01)
		mini, original, err := decode(reader, coordinator, hash(nativeBytes), txHash, nativeBytes, rawTx, 1, 0, 1,
			len(nativeBytes)+len(rawTx)+2*stdsha256.Size)
		require.NoError(t, err)
		require.Equal(t, [][]byte{otherHash, txHash}, mini.TxHashes)
		require.Equal(t, tx, original)
	})
	t.Run("duplicate_positions_are_membership_only", func(t *testing.T) {
		nativeBytes := encode(makeMini(txHash, txHash))
		mini, _, err := decode(reader, coordinator, hash(nativeBytes), txHash, nativeBytes, rawTx, 1, 0, 1,
			len(nativeBytes)+len(rawTx)+2*stdsha256.Size)
		require.NoError(t, err)
		require.Equal(t, [][]byte{txHash, txHash}, mini.TxHashes)
	})

	type inputs struct {
		mb, tr, mh, th   []byte
		sender, receiver uint32
		index            int32
		byteLimit        int
	}
	setMini := func(in *inputs, m *block.MiniBlock) {
		in.mb = encode(m)
		in.mh = hash(in.mb)
		in.byteLimit = len(in.mb) + len(in.tr) + 2*stdsha256.Size
	}
	setTx := func(in *inputs, tr []byte) {
		in.tr = tr
		in.th = hash(tr)
		setMini(in, makeMini(otherHash, in.th))
	}
	for _, c := range []struct {
		name   string
		change func(*inputs)
		want   error
	}{
		{"wrong_type", func(in *inputs) {
			m := makeMini(otherHash, txHash)
			m.Type = block.SmartContractResultBlock
			setMini(in, m)
		}, process.ErrInvalidMiniBlockType},
		{"wrong_sender", func(in *inputs) { in.sender = 2 }, process.ErrInvalidShardId},
		{"wrong_receiver", func(in *inputs) { in.receiver = 2 }, process.ErrInvalidShardId},
		{"invalid_native_shard", func(in *inputs) { m := makeMini(otherHash, txHash); m.SenderShardID = 4; setMini(in, m); in.sender = 4 }, process.ErrInvalidShardId},
		{"invalid_native_reserved", func(in *inputs) { m := makeMini(otherHash, txHash); m.Reserved = make([]byte, 11); setMini(in, m) }, process.ErrReservedFieldInvalid},
		{"negative_index", func(in *inputs) { in.index = -1 }, process.ErrIndexIsOutOfBound},
		{"index_past_end", func(in *inputs) { in.index = 2 }, process.ErrIndexIsOutOfBound},
		{"empty_tx_hashes", func(in *inputs) { setMini(in, makeMini()) }, process.ErrIndexIsOutOfBound},
		{"reordered_raw_differs", func(in *inputs) { in.mb = encode(makeMini(txHash, otherHash)) }, ErrInvalidAccountWitness},
		{"reordered_same_index_refused", func(in *inputs) { setMini(in, makeMini(txHash, otherHash)) }, ErrInvalidAccountWitness},
		{"wrong_transaction_hash", func(in *inputs) { in.th[0] ^= 1 }, ErrInvalidAccountWitness},
		{"wrong_miniblock_hash_width", func(in *inputs) { in.mh = in.mh[:1] }, ErrInvalidAccountWitness},
		{"wrong_transaction_hash_width", func(in *inputs) { in.th = in.th[:1] }, ErrInvalidAccountWitness},
		{"empty_miniblock", func(in *inputs) { in.mb = nil }, ErrInvalidAccountWitness},
		{"empty_transaction", func(in *inputs) { in.tr = nil }, ErrInvalidAccountWitness},
		{"corrupt_miniblock", func(in *inputs) { in.mb = []byte{0xff}; in.mh = hash(in.mb) }, nil},
		{"corrupt_transaction", func(in *inputs) { setTx(in, []byte{0xff}) }, nil},
		{"short_budget", func(in *inputs) { in.byteLimit-- }, ErrInvalidAccountWitness},
		{"zero_budget", func(in *inputs) { in.byteLimit = 0 }, ErrInvalidAccountWitness},
		{"nil_signature", func(in *inputs) { tr := makeTx(17); tr.Signature = nil; setTx(in, encode(tr)) }, data.ErrNilSignature},
		{"negative_value", func(in *inputs) { tr := makeTx(17); tr.Value = big.NewInt(-1); setTx(in, encode(tr)) }, data.ErrNegativeValue},
		{"noncanonical_transaction", func(in *inputs) { setTx(in, append(bytes.Clone(rawTx), 0x08, 0x11)) }, process.ErrNonCanonicalTransactionEncoding},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := inputs{mb: bytes.Clone(rawMini), tr: bytes.Clone(rawTx), mh: bytes.Clone(miniHash), th: bytes.Clone(txHash), sender: 1, receiver: 0, index: 1, byteLimit: budget}
			c.change(&in)
			mini, original, err := decode(reader, coordinator, in.mh, in.th, in.mb, in.tr, in.sender, in.receiver, in.index, in.byteLimit)
			if c.want == nil {
				require.Error(t, err)
			} else {
				require.ErrorIs(t, err, c.want)
			}
			require.Nil(t, mini)
			require.Nil(t, original)
		})
	}
}
