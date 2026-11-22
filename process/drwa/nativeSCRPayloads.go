package drwa

import (
	"bytes"
	"math"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
)

// ReadNativeSCRPayloads acquires the existing native miniblock/SCR wire bytes
// from their native storage units and binds each returned value to its requested
// hash. The copies remain owned after a subsequent native cache read.
//
// storageEpoch selects only the native lookup location; it is not proof of the
// original source-era profile, retention, canonicality or transaction outcome.
// No current-epoch/SearchFirst fallback, source/profile selection, free-service
// policy or paid-service admission is installed. A consumer must still verify
// native S/H/M/B membership and every owning first-use/service gate.
// byteLimit bounds key/payload copies and decoding inputs, not native I/O cost.
func (r *ResultAccountReader) ReadNativeSCRPayloads(source dataRetriever.StorageService, storageEpoch uint32,
	miniBlockHash, resultHash []byte, byteLimit int,
) ([]byte, []byte, error) {
	return r.readNativePayloads(source, storageEpoch, storageEpoch, miniBlockHash, resultHash, byteLimit, dataRetriever.UnsignedTransactionUnit)
}

// ReadNativeTransactionPayloads acquires hash-bound native miniblock and
// original transaction bytes using MiniBlockUnit and TransactionUnit.
// Its lookup, byte bound and ownership rules are the same as for SCR payloads.
// The caller still owns canonical membership, source profile and funding.
func (r *ResultAccountReader) ReadNativeTransactionPayloads(source dataRetriever.StorageService, storageEpoch uint32,
	miniBlockHash, transactionHash []byte, byteLimit int,
) ([]byte, []byte, error) {
	return r.readNativeTransactionPayloadsAtEpochs(source, storageEpoch, storageEpoch, miniBlockHash, transactionHash, byteLimit)
}

func (r *ResultAccountReader) readNativeTransactionPayloadsAtEpochs(source dataRetriever.StorageService, miniBlockEpoch, transactionEpoch uint32,
	miniBlockHash, transactionHash []byte, byteLimit int,
) ([]byte, []byte, error) {
	return r.readNativePayloads(source, miniBlockEpoch, transactionEpoch, miniBlockHash, transactionHash, byteLimit, dataRetriever.TransactionUnit)
}

func (r *ResultAccountReader) readNativePayloads(source dataRetriever.StorageService, miniBlockEpoch, payloadEpoch uint32,
	miniBlockHash, payloadHash []byte, byteLimit int, payloadUnit dataRetriever.UnitType,
) ([]byte, []byte, error) {
	if r == nil || check.IfNil(r.args.Hasher) || check.IfNil(source) || byteLimit <= 0 {
		return nil, nil, ErrInvalidAccountWitness
	}
	size := r.args.Hasher.Size()
	if size <= 0 || len(miniBlockHash) != size || len(payloadHash) != size {
		return nil, nil, ErrInvalidAccountWitness
	}
	remaining := byteLimit
	for _, key := range [][]byte{miniBlockHash, payloadHash} {
		if len(key) > remaining {
			return nil, nil, ErrInvalidAccountWitness
		}
		remaining -= len(key)
	}
	miniBlockHash, payloadHash = bytes.Clone(miniBlockHash), bytes.Clone(payloadHash)
	miniBlocks, err := source.GetStorer(dataRetriever.MiniBlockUnit)
	if err != nil {
		return nil, nil, err
	}
	if check.IfNil(miniBlocks) {
		return nil, nil, ErrInvalidAccountWitness
	}
	payloads, err := source.GetStorer(payloadUnit)
	if err != nil {
		return nil, nil, err
	}
	if check.IfNil(payloads) {
		return nil, nil, ErrInvalidAccountWitness
	}
	miniRaw, err := miniBlocks.GetFromEpoch(bytes.Clone(miniBlockHash), miniBlockEpoch)
	if err != nil {
		return nil, nil, err
	}
	if len(miniRaw) == 0 || len(miniRaw) > remaining {
		return nil, nil, ErrInvalidAccountWitness
	}
	miniRaw = bytes.Clone(miniRaw)
	if !bytes.Equal(r.args.Hasher.Compute(string(miniRaw)), miniBlockHash) {
		return nil, nil, ErrInvalidAccountWitness
	}
	remaining -= len(miniRaw)
	payloadRaw, err := payloads.GetFromEpoch(bytes.Clone(payloadHash), payloadEpoch)
	if err != nil {
		return nil, nil, err
	}
	if len(payloadRaw) == 0 || len(payloadRaw) > remaining {
		return nil, nil, ErrInvalidAccountWitness
	}
	payloadRaw = bytes.Clone(payloadRaw)
	if !bytes.Equal(r.args.Hasher.Compute(string(payloadRaw)), payloadHash) {
		return nil, nil, ErrInvalidAccountWitness
	}
	return miniRaw, payloadRaw, nil
}

// decodeNativeTransactionMember checks the exact position in a native TxBlock
// against independently supplied raw hashes and route. The position denotes
// membership only. Native execution, canonicality and classification authority
// still belong to the caller. The bound covers the four copied byte inputs.
func (r *ResultAccountReader) decodeNativeTransactionMember(coordinator sharding.Coordinator,
	miniBlockHash, transactionHash, miniBlockRaw, transactionRaw []byte,
	expectedSender, expectedReceiver uint32, index int32, byteLimit int,
) (*block.MiniBlock, *transaction.Transaction, error) {
	if r == nil || byteLimit <= 0 {
		return nil, nil, ErrInvalidAccountWitness
	}
	remaining := byteLimit
	for _, raw := range [][]byte{miniBlockHash, transactionHash, miniBlockRaw, transactionRaw} {
		if len(raw) == 0 || len(raw) > remaining {
			return nil, nil, ErrInvalidAccountWitness
		}
		remaining -= len(raw)
	}
	// Freeze the bounded inputs even before a configured dependency's size
	// or nil check can call back into the owner.
	miniBlockHash, transactionHash = bytes.Clone(miniBlockHash), bytes.Clone(transactionHash)
	miniBlockRaw, transactionRaw = bytes.Clone(miniBlockRaw), bytes.Clone(transactionRaw)

	hasher, codec := r.args.Hasher, r.args.Marshaller
	if check.IfNil(hasher) || check.IfNil(codec) || check.IfNil(coordinator) {
		return nil, nil, ErrInvalidAccountWitness
	}
	size := hasher.Size()
	if size <= 0 || len(miniBlockHash) != size || len(transactionHash) != size {
		return nil, nil, ErrInvalidAccountWitness
	}
	if !bytes.Equal(hasher.Compute(string(miniBlockRaw)), miniBlockHash) ||
		!bytes.Equal(hasher.Compute(string(transactionRaw)), transactionHash) {
		return nil, nil, ErrInvalidAccountWitness
	}

	miniBlock := &block.MiniBlock{}
	if err := codec.Unmarshal(miniBlock, miniBlockRaw); err != nil {
		return nil, nil, err
	}
	if miniBlock.Type != block.TxBlock {
		return nil, nil, process.ErrInvalidMiniBlockType
	}
	if err := process.CheckMiniBlock(miniBlock, coordinator); err != nil {
		return nil, nil, err
	}
	if miniBlock.SenderShardID != expectedSender || miniBlock.ReceiverShardID != expectedReceiver {
		return nil, nil, process.ErrInvalidShardId
	}
	if len(miniBlock.TxHashes) > math.MaxInt32 {
		return nil, nil, process.ErrIndexIsOutOfBound
	}
	if err := process.CheckIfIndexesAreOutOfBound(index, index, miniBlock); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(miniBlock.TxHashes[index], transactionHash) {
		return nil, nil, ErrInvalidAccountWitness
	}

	tx := &transaction.Transaction{}
	if err := codec.Unmarshal(tx, transactionRaw); err != nil {
		return nil, nil, err
	}
	// Match the native intercepted-transaction canonical encoding test. There
	// is no corresponding new remarshal requirement for native miniblocks.
	canonical, err := codec.Marshal(tx)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonical, transactionRaw) {
		return nil, nil, process.ErrNonCanonicalTransactionEncoding
	}
	if err = tx.CheckIntegrity(); err != nil {
		return nil, nil, err
	}
	return miniBlock, tx, nil
}
