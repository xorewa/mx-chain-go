package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errRootLeafRecord = errors.New("invalid candidate DRWA root leaf record")

// rootLeafRecords interprets structural V1 bytes. The native profile, limits,
// type and amount provenance belong to the enclosing original operation.
type rootLeafRecords struct {
	codec          *registrationRecords
	maxAmountBytes int
}

func newRootLeafRecords(codec *registrationRecords, maxAmountBytes int) (*rootLeafRecords, error) {
	if codec == nil || check.IfNil(codec.marshaller) || codec.maxBytes <= 0 ||
		check.IfNil(codec.hasher) || codec.hasher.Size() != common.HashSize ||
		uint64(codec.maxBytes) > core.MaxLeafSize || maxAmountBytes <= 0 || maxAmountBytes > codec.maxBytes {
		return nil, errRootLeafRecord
	}
	return &rootLeafRecords{codec, maxAmountBytes}, nil
}

func nonceFamily(family core.ESDTType) bool {
	switch family {
	case core.NonFungibleV2, core.DynamicNFT, core.SemiFungible, core.MetaFungible, core.DynamicSFT, core.DynamicMeta:
		return true
	default:
		return false
	}
}

func positionNonceValid(family core.ESDTType, nonce uint64) bool {
	return family == core.Fungible && nonce == 0 || nonceFamily(family) && nonce != 0
}

func (r *rootLeafRecords) positionKey(token []byte, family core.ESDTType, nonce uint64, holder []byte) ([]byte, error) {
	if !vmcommon.ValidateToken(token) || !positionNonceValid(family, nonce) || len(holder) != len(core.SystemAccountAddress) {
		return nil, errRootLeafRecord
	}
	return r.codec.frameBatch(true, token, binary.BigEndian.AppendUint64(nil, nonce), holder)
}

func (r *rootLeafRecords) nonceKey(token []byte, family core.ESDTType, nonce uint64) ([]byte, error) {
	if !vmcommon.ValidateToken(token) || !nonceFamily(family) || nonce == 0 {
		return nil, errRootLeafRecord
	}
	return r.codec.frameBatch(true, token, binary.BigEndian.AppendUint64(nil, nonce))
}

func (r *rootLeafRecords) decodePositionKey(raw, token []byte, family core.ESDTType) (uint64, []byte, error) {
	fields, err := r.codec.unframeBatch(true, raw, 3)
	if err != nil {
		return 0, nil, err
	}
	if !vmcommon.ValidateToken(token) || !bytes.Equal(fields[0], token) || len(fields[1]) != 8 ||
		len(fields[2]) != len(core.SystemAccountAddress) {
		return 0, nil, errRootLeafRecord
	}
	nonce := binary.BigEndian.Uint64(fields[1])
	if !positionNonceValid(family, nonce) {
		return 0, nil, errRootLeafRecord
	}
	return nonce, bytes.Clone(fields[2]), nil
}

func (r *rootLeafRecords) decodeNonceKey(raw, token []byte, family core.ESDTType) (uint64, error) {
	fields, err := r.codec.unframeBatch(true, raw, 2)
	if err != nil {
		return 0, err
	}
	if !vmcommon.ValidateToken(token) || !bytes.Equal(fields[0], token) || !nonceFamily(family) || len(fields[1]) != 8 {
		return 0, errRootLeafRecord
	}
	nonce := binary.BigEndian.Uint64(fields[1])
	if nonce == 0 {
		return 0, errRootLeafRecord
	}
	return nonce, nil
}

// quantityValue uses native Update semantics: an empty value deletes a position
// leaf. An initialized outer record is still required to interpret that absence.
func (r *rootLeafRecords) quantityValue(quantity *big.Int) ([]byte, error) {
	if !supplyIntegerFits(quantity, r.maxAmountBytes) {
		return nil, errRootLeafRecord
	}
	return quantity.Bytes(), nil
}

func (r *rootLeafRecords) decodeQuantityValue(raw []byte) (*big.Int, error) {
	if len(raw) == 0 {
		return nil, errRootLeafRecord
	}
	return r.decodeUnsigned(raw)
}

func (r *rootLeafRecords) decodeUnsigned(raw []byte) (*big.Int, error) {
	if len(raw) > r.maxAmountBytes || len(raw) != 0 && raw[0] == 0 {
		return nil, errRootLeafRecord
	}
	return new(big.Int).SetBytes(raw), nil
}

type nonceSupply struct {
	issued, live *big.Int
}

func uniqueNonceFamily(family core.ESDTType) bool {
	return family == core.NonFungibleV2 || family == core.DynamicNFT
}

func (r *rootLeafRecords) validNonceSupply(family core.ESDTType, value nonceSupply) bool {
	return nonceFamily(family) && supplyIntegerFits(value.issued, r.maxAmountBytes) &&
		supplyIntegerFits(value.live, r.maxAmountBytes) && value.issued.Sign() > 0 &&
		value.live.Cmp(value.issued) <= 0 && (!uniqueNonceFamily(family) || value.issued.IsUint64() && value.issued.Uint64() == 1)
}

func (r *rootLeafRecords) nonceValue(family core.ESDTType, value nonceSupply) ([]byte, error) {
	if !r.validNonceSupply(family, value) {
		return nil, errRootLeafRecord
	}
	if uniqueNonceFamily(family) {
		return []byte{byte(value.live.Uint64())}, nil
	}
	return r.codec.frameBatch(true, value.issued.Bytes(), value.live.Bytes())
}

func (r *rootLeafRecords) decodeNonceValue(family core.ESDTType, raw []byte) (nonceSupply, error) {
	if !nonceFamily(family) || len(raw) > r.codec.maxBytes {
		return nonceSupply{}, errRootLeafRecord
	}
	if uniqueNonceFamily(family) {
		if len(raw) != 1 || raw[0] > 1 {
			return nonceSupply{}, errRootLeafRecord
		}
		return nonceSupply{big.NewInt(1), big.NewInt(int64(raw[0]))}, nil
	}
	fields, err := r.codec.unframeBatch(true, raw, 2)
	if err != nil {
		return nonceSupply{}, err
	}
	issued, err := r.decodeUnsigned(fields[0])
	if err != nil {
		return nonceSupply{}, err
	}
	live, err := r.decodeUnsigned(fields[1])
	if err != nil {
		return nonceSupply{}, err
	}
	value := nonceSupply{issued, live}
	if !r.validNonceSupply(family, value) {
		return nonceSupply{}, errRootLeafRecord
	}
	return value, nil
}
