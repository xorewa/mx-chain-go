package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errInvalidRegistryTransport = errors.New("invalid DRWA registry transport")

// Experimental metachain registry domain, disjoint from the shard-local
// membership materializer. RT-01: local application must not create a counted
// registry entry. Only the future atomic DRWARegisterToken/count producer owns
// this domain (Part A L4845-4846/L2211-2216); no writer is exposed here.
// This construction candidate is not a Part B L346 format allocation.
const registryMemberKeyPrefix = core.ProtectedKeyPrefix + "DRWA@registry@member@"

// registryMemberWitness contains untrusted transport data. The token identifier
// only selects the internally derived permanent-membership key; native account
// and data proofs must authenticate that key at the selected native root.
type registryMemberWitness struct {
	tokenID []byte
	proof   AccountItemWitness
}

// registryProjection is an authenticated reconstruction result, not an installed
// classifier. Native context admission, local materialization and native-journal
// lifecycle ownership must precede installation. No caller may publish a partial
// result or reuse this result after candidate replacement/rollback.
type registryProjection struct {
	anchor  metaRegistryAnchor
	members map[string]struct{}
}

// registryTransport reconstructs the bounded permanent registry at startup,
// state-sync or pre-execution integrity recovery (Part A L4863-4876), never as an
// O(ever-regulated-count) per-block lookup. Count plus distinct authenticated
// permanent members proves completeness only under the owning registration
// invariant: count increments atomically with each sole new entry and never
// decreases (Part A L981/L2211-2216). T19 must construct that producer.
//
// The existing experimental count record is proposed here as exactly eight
// big-endian bytes. This is a construction candidate, NOT a Part B L346 format
// allocation. No production consumer, new key prefix, index or registration
// authority is installed. Owning codec/producer qualification is still required.
type registryTransport struct {
	reader         *ResultAccountReader
	maxEver        uint64
	proofByteLimit int
}

func newRegistryTransport(reader *ResultAccountReader, maxEver uint64, proofByteLimit int) (*registryTransport, error) {
	if reader == nil || proofByteLimit <= 0 {
		return nil, errInvalidRegistryTransport
	}
	return &registryTransport{reader: reader, maxEver: maxEver, proofByteLimit: proofByteLimit}, nil
}

// registryProofBytes checks BOTH proof families with overflow-safe subtraction.
// The transport applies this cumulatively to count and every entry; there is no
// per-entry reset that could bypass the caller's actual configured resource bound.
func registryProofBytes(w AccountItemWitness, limit int) (int, error) {
	used := 0
	for _, nodes := range [][][]byte{w.AccountProof, w.DataProof} {
		if len(nodes) == 0 {
			return 0, ErrInvalidAccountWitness
		}
		for _, node := range nodes {
			if len(node) == 0 || used > limit || len(node) > limit-used {
				return 0, ErrInvalidAccountWitness
			}
			used += len(node)
		}
	}
	return used, nil
}

// reconstruct reads only a dedicated native proof cache. It never writes the
// executing account store or teaches ordinary execution to read DRWA state.
// Input bytes/native dependencies must remain stable throughout reconstruction.
// maxEver/proofByteLimit are caller-owned configuration; no default is selected.
func (t *registryTransport) reconstruct(anchor *metaRegistryAnchor, countProof AccountItemWitness,
	members []registryMemberWitness) (*registryProjection, error) {
	if uint64(len(members)) > t.maxEver {
		return nil, errInvalidRegistryTransport
	}
	remaining := t.proofByteLimit
	read := func(key []byte, w AccountItemWitness) ([]byte, error) {
		n, err := registryProofBytes(w, remaining)
		if err != nil {
			return nil, err
		}
		value, err := t.reader.readRegistryItem(anchor, key, w, remaining)
		if err != nil {
			return nil, err
		}
		remaining -= n
		return value, nil
	}
	value, err := read([]byte(registryCountKey), countProof)
	if err != nil {
		return nil, err
	}
	if len(value) != 8 {
		return nil, errInvalidRegistryTransport
	}
	count := binary.BigEndian.Uint64(value)
	// Equality plus the pre-read member bound also establishes count <= maxEver.
	if count != uint64(len(members)) {
		return nil, errInvalidRegistryTransport
	}
	set := make(map[string]struct{}, len(members))
	for _, member := range members {
		if !vmcommon.ValidateToken(member.tokenID) {
			return nil, errInvalidRegistryTransport
		}
		id := string(member.tokenID)
		if _, duplicate := set[id]; duplicate {
			return nil, errInvalidRegistryTransport
		}
		key := append([]byte(registryMemberKeyPrefix), member.tokenID...)
		value, err = read(key, member.proof)
		if err != nil {
			return nil, err
		}
		if len(value) != 1 || value[0] != 1 {
			return nil, errInvalidRegistryTransport
		}
		set[id] = struct{}{}
	}
	return &registryProjection{anchor: metaRegistryAnchor{
		candidateHash: bytes.Clone(anchor.candidateHash), metaHash: bytes.Clone(anchor.metaHash),
		executedHash: bytes.Clone(anchor.executedHash), root: bytes.Clone(anchor.root),
		nonce: anchor.nonce, round: anchor.round, epoch: anchor.epoch}, members: set}, nil
}
