package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

const (
	supplyStatePrefix      = core.ProtectedKeyPrefix + "DRWA@supply@"
	positionTrackingPrefix = core.ProtectedKeyPrefix + "DRWA@positions@"
	supplyPositionVersion  = uint32(1)
)

var errSupplyPositionRecord = errors.New("invalid DRWA structural V1 supply or position record")

type initializedSupplyState struct {
	token       []byte
	family      core.ESDTType
	origin      []byte
	originShard uint32
	accounting  *supplyAccounting
	nonceRoot   []byte
}

type initializedPositionState struct {
	token    []byte
	family   core.ESDTType
	root     []byte
	quantity *big.Int
	version  uint64
}

// NewSupplyPositionRootDecoder provides the shared V1 interpretation for the
// original AccountsDB protected-child owner. The caller must supply the
// admitted native profile and measured bounds. This decoder authenticates
// neither the AccountsDB/epoch nor the locator set or native root.
func NewSupplyPositionRootDecoder(marshaller marshal.Marshalizer, hasher hashing.Hasher,
	maxRecordBytes, maxAmountBytes int) (state.ProtectedChildRoot, error) {
	r, err := newRootLeafRecords(&registrationRecords{marshaller: marshaller, hasher: hasher, maxBytes: maxRecordBytes}, maxAmountBytes)
	if err != nil {
		return nil, err
	}
	return r.protectedChildRoot, nil
}

func (r *rootLeafRecords) outerKey(prefix string, token []byte) ([]byte, error) {
	if !vmcommon.ValidateToken(token) {
		return nil, errSupplyPositionRecord
	}
	identity, err := r.codec.frameBatch(true, token)
	if err != nil || len(identity) > r.codec.maxBytes-len(prefix) {
		return nil, errSupplyPositionRecord
	}
	return append([]byte(prefix), identity...), nil
}

func (r *rootLeafRecords) protectedChildRoot(address, key, raw []byte) ([]byte, error) {
	if !bytes.Equal(address, core.SystemAccountAddress) || len(key) > r.codec.maxBytes {
		return nil, errSupplyPositionRecord
	}
	if identity, found := bytes.CutPrefix(key, []byte(supplyStatePrefix)); found {
		record, err := r.decodeSupplyRecord(raw)
		if err != nil || record.family == core.Fungible || !r.matchOuterIdentity(identity, record.token) {
			return nil, errSupplyPositionRecord
		}
		return record.nonceRoot, nil
	}
	if identity, found := bytes.CutPrefix(key, []byte(positionTrackingPrefix)); found {
		record, err := r.decodePositionRecord(raw)
		if err != nil || !r.matchOuterIdentity(identity, record.token) {
			return nil, errSupplyPositionRecord
		}
		return record.root, nil
	}
	return nil, errSupplyPositionRecord
}

func (r *rootLeafRecords) matchOuterIdentity(identity, token []byte) bool {
	fields, err := r.codec.unframeBatch(true, identity, 1)
	return err == nil && bytes.Equal(fields[0], token)
}

func recordFamily(version, token, tokenType []byte) (core.ESDTType, error) {
	if len(version) != 4 || binary.BigEndian.Uint32(version) != supplyPositionVersion ||
		!vmcommon.ValidateToken(token) || len(tokenType) != 4 {
		return 0, errSupplyPositionRecord
	}
	family := core.ESDTType(binary.BigEndian.Uint32(tokenType))
	if family != core.Fungible && !nonceFamily(family) {
		return 0, errSupplyPositionRecord
	}
	return family, nil
}

func matchesRootQuantity(root []byte, quantity *big.Int) bool {
	return len(root) == common.HashSize && bytes.Equal(root, common.EmptyTrieHash) == (quantity.Sign() == 0)
}

func (r *rootLeafRecords) validSupplyRecord(s *initializedSupplyState) bool {
	if s == nil || !vmcommon.ValidateToken(s.token) || len(s.origin) != len(core.SystemAccountAddress) ||
		s.accounting == nil || !supplyIntegerFits(s.accounting.cumulativeIssued, r.maxAmountBytes) ||
		!supplyIntegerFits(s.accounting.liveSupply, r.maxAmountBytes) ||
		s.accounting.liveSupply.Cmp(s.accounting.cumulativeIssued) > 0 {
		return false
	}
	if s.family == core.Fungible {
		return len(s.nonceRoot) == 0
	}
	return nonceFamily(s.family) && matchesRootQuantity(s.nonceRoot, s.accounting.cumulativeIssued)
}

func (r *rootLeafRecords) encodeSupplyRecord(s *initializedSupplyState) ([]byte, error) {
	if !r.validSupplyRecord(s) {
		return nil, errSupplyPositionRecord
	}
	return r.codec.frameBatch(true, binary.BigEndian.AppendUint32(nil, supplyPositionVersion), s.token,
		binary.BigEndian.AppendUint32(nil, uint32(s.family)), s.origin,
		binary.BigEndian.AppendUint32(nil, s.originShard), s.accounting.cumulativeIssued.Bytes(),
		s.accounting.liveSupply.Bytes(), s.nonceRoot, binary.BigEndian.AppendUint64(nil, s.accounting.nextSupplyNonce))
}

func (r *rootLeafRecords) decodeSupplyRecord(raw []byte) (*initializedSupplyState, error) {
	f, err := r.codec.unframeBatch(true, raw, 9)
	if err != nil {
		return nil, errSupplyPositionRecord
	}
	family, err := recordFamily(f[0], f[1], f[2])
	if err != nil || len(f[4]) != 4 || len(f[8]) != 8 {
		return nil, errSupplyPositionRecord
	}
	issued, err := r.decodeUnsigned(f[5])
	if err != nil {
		return nil, errSupplyPositionRecord
	}
	live, err := r.decodeUnsigned(f[6])
	if err != nil {
		return nil, errSupplyPositionRecord
	}
	s := &initializedSupplyState{
		token: f[1], family: family, origin: f[3], originShard: binary.BigEndian.Uint32(f[4]), nonceRoot: f[7],
		accounting: &supplyAccounting{issued, live, binary.BigEndian.Uint64(f[8])},
	}
	if !r.validSupplyRecord(s) {
		return nil, errSupplyPositionRecord
	}
	s.token, s.origin, s.nonceRoot = bytes.Clone(s.token), bytes.Clone(s.origin), bytes.Clone(s.nonceRoot)
	return s, nil
}

func (r *rootLeafRecords) validPositionRecord(p *initializedPositionState) bool {
	return p != nil && vmcommon.ValidateToken(p.token) && (p.family == core.Fungible || nonceFamily(p.family)) &&
		supplyIntegerFits(p.quantity, r.maxAmountBytes) && matchesRootQuantity(p.root, p.quantity)
}

func (r *rootLeafRecords) encodePositionRecord(p *initializedPositionState) ([]byte, error) {
	if !r.validPositionRecord(p) {
		return nil, errSupplyPositionRecord
	}
	return r.codec.frameBatch(true, binary.BigEndian.AppendUint32(nil, supplyPositionVersion), p.token,
		binary.BigEndian.AppendUint32(nil, uint32(p.family)), []byte{1}, p.root, p.quantity.Bytes(),
		binary.BigEndian.AppendUint64(nil, p.version))
}

func (r *rootLeafRecords) decodePositionRecord(raw []byte) (*initializedPositionState, error) {
	f, err := r.codec.unframeBatch(true, raw, 7)
	if err != nil {
		return nil, errSupplyPositionRecord
	}
	family, err := recordFamily(f[0], f[1], f[2])
	if err != nil || !bytes.Equal(f[3], []byte{1}) || len(f[6]) != 8 {
		return nil, errSupplyPositionRecord
	}
	quantity, err := r.decodeUnsigned(f[5])
	if err != nil {
		return nil, errSupplyPositionRecord
	}
	p := &initializedPositionState{token: f[1], family: family, root: f[4], quantity: quantity,
		version: binary.BigEndian.Uint64(f[6])}
	if !r.validPositionRecord(p) {
		return nil, errSupplyPositionRecord
	}
	p.token, p.root = bytes.Clone(p.token), bytes.Clone(p.root)
	return p, nil
}
