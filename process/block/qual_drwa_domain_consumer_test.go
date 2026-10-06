package block

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	coreBlock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE SPG-TQ-001 / Part A 3.3 and 3.4 construction.
// This composes native authenticated item reading with the existing G3 model's
// ACK consumer. It is NOT a production domain store, codec, certificate verifier,
// AccountsDB adapter, finality proof or a complete network-domain consumer map.
// The fixture-only item layout is domain[32] || actionID[32] || actionDigest.
// The fixture GAS body below is provisional literal data, NOT a selected codec.
// Trusted H commitments and the G3 model's canonical inputs remain assumptions.
// No transaction is submitted: there are no native fee, sender nonce, balance,
// supply, intent, effect or restriction writes in this isolated construction.
const qualDomainKAT = "3aebbd45145e5030dc43e4fa531893136981c17b5901f0ead6adfd690f665aa1"
const qualDomainActionKAT = "6857315ae49aeae5d846578681bf45a50557dee3db9af7c3bb2c189e04244334"
const qualDomainBodyHex = "746f6b656e2d417c4345425f43555252454e54495a4154494f4e7c00000000000000077c616374696f6e2d6469676573742d41"

func qualDomainHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	require.NoError(t, err)
	return value
}

type qualDomainItemWitness struct {
	hHash, h, s, key []byte
	nodes            [][]byte
	shard            uint32
	limit            int
}

func qualDomainItemProof(t *testing.T, value []byte, shard uint32) qualDomainItemWitness {
	t.Helper()
	key := []byte("fixture/domain-bound-ack")
	tr := qualItemTrie(t, testscommon.NewMemDbMock())
	require.NoError(t, tr.Update(key, value))
	root, err := tr.RootHash()
	require.NoError(t, err)
	proof, _, err := tr.GetProof(key)
	require.NoError(t, err)
	mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	s := &coreBlock.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: shard}
	sBytes, err := mar.Marshal(s)
	require.NoError(t, err)
	result := createDummyShardExecutionResult()
	result.BaseExecutionResult.HeaderHash = hash.Compute(string(sBytes))
	result.BaseExecutionResult.HeaderNonce = s.Nonce
	result.BaseExecutionResult.HeaderRound = s.Round
	result.BaseExecutionResult.HeaderEpoch = s.Epoch
	result.BaseExecutionResult.RootHash = root
	h := &coreBlock.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: shard,
		ExecutionResults: []*coreBlock.ExecutionResult{result}}
	hBytes, err := mar.Marshal(h)
	require.NoError(t, err)
	w := qualDomainItemWitness{hHash: hash.Compute(string(hBytes)), h: hBytes, s: sBytes,
		key: key, nodes: proof, shard: shard}
	for _, node := range proof {
		w.limit += len(node)
	}
	return w
}

func qualObserveDomainItem(t *testing.T, m *qualConvergenceModel, e qualApplicationEvidence,
	localDomain, immutableActionBody []byte, w qualDomainItemWitness) error {
	t.Helper()
	if len(localDomain) != 32 || bytes.Equal(localDomain, make([]byte, 32)) {
		return errQualAckRejected
	}
	value, err := qualImportResultItem(t, w.hHash, w.h, w.s, w.key, w.nodes, w.shard, w.limit)
	if err != nil {
		return err
	}
	if len(value) != 64+len(e.ack.actionDigest) {
		return errQualAckRejected
	}
	if !bytes.Equal(value[:32], localDomain) {
		return errQualAckRejected
	}
	preimage := append([]byte("DRWA/GAS/v1"), localDomain...)
	preimage = append(preimage, immutableActionBody...)
	expectedID := blake2b.NewBlake2b().Compute(string(preimage))
	if !bytes.Equal(value[32:64], expectedID) ||
		hex.EncodeToString(expectedID) != m.inputs.action.actionID ||
		!bytes.Equal(value[64:], []byte(e.ack.actionDigest)) || w.shard != e.ack.shard {
		return errQualAckRejected
	}
	// No ACK/replay state is touched before all item/domain/action checks.
	return m.observe(e)
}

func qualDomainConvergenceFixture(t *testing.T) (*qualConvergenceModel, map[uint32]qualApplicationEvidence) {
	t.Helper()
	m, evidence := qualNewConvergenceFixture()
	m.inputs.action.actionID = qualDomainActionKAT
	m.inputs.action.binding.instance = qualDomainActionKAT
	for shard, e := range evidence {
		e.ack.actionID = qualDomainActionKAT
		e.ack.binding.instance = qualDomainActionKAT
		e.witness.fullResult.ack = e.ack
		carrier := m.inputs.carriers[e.witness.carryingHeader]
		carrier.results[e.witness.executionResult] = e.witness.fullResult
		m.inputs.carriers[carrier.identity] = carrier
		evidence[shard] = e
	}
	return m, evidence
}

func TestQualDRWANetworkDomainKnownAnswers(t *testing.T) {
	// Expected literals were independently computed with Python hashlib
	// BLAKE2b-256, not emitted by the Go implementation under test.
	genesis := qualDomainHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	hash := blake2b.NewBlake2b()
	derive := func(chain string, g []byte) []byte {
		return hash.Compute(string(append([]byte("DRWA/NETWORK/v1"+chain), g...)))
	}
	domain := derive("local-test", genesis)
	require.Equal(t, qualDomainKAT, hex.EncodeToString(domain))
	require.Equal(t, "18b1496c62cb0c68bd36b47e21a0ecdd639fe72ff822e32a5a5f7f2bde9d0ff8",
		hex.EncodeToString(derive("OTHER", genesis)))
	reversed := bytes.Clone(genesis)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	require.Equal(t, "a33e6e9e724bae375615ef204e3513c43dfdb4dfc5f6e55db00f1911fd01ce81",
		hex.EncodeToString(derive("local-test", reversed)))
	// Same chain ID and genesis intentionally share a domain, including forks.
	require.Equal(t, domain, derive("local-test", bytes.Clone(genesis)))
	preimage := append([]byte("DRWA/GAS/v1"), domain...)
	preimage = append(preimage, qualDomainHex(t, qualDomainBodyHex)...)
	require.Equal(t, qualDomainActionKAT, hex.EncodeToString(hash.Compute(string(preimage))))
}

func TestQualDRWADomainItemConsumer(t *testing.T) {
	domain, action := qualDomainHex(t, qualDomainKAT), qualDomainHex(t, qualDomainActionKAT)
	body := qualDomainHex(t, qualDomainBodyHex)
	for shard := uint32(0); shard < 3; shard++ {
		for _, name := range []string{"valid", "foreign_domain_local_ID", "other_genesis_local_ID",
			"zero_domain_local_ID", "missing_domain", "local_domain_foreign_ID",
			"wrong_action_body", "wrong_digest", "missing_local_domain", "zero_local_domain"} {
			t.Run(fmt.Sprintf("shard_%d/%s", shard, name), func(t *testing.T) {
				m, evidence := qualDomainConvergenceFixture(t)
				other := (shard + 1) % 3
				require.NoError(t, m.observe(evidence[other]))
				local, actionBody := bytes.Clone(domain), bytes.Clone(body)
				value := append(bytes.Clone(domain), action...)
				value = append(value, []byte(evidence[shard].ack.actionDigest)...)
				validValue := bytes.Clone(value)
				switch name {
				case "foreign_domain_local_ID":
					copy(value[:32], qualDomainHex(t, "18b1496c62cb0c68bd36b47e21a0ecdd639fe72ff822e32a5a5f7f2bde9d0ff8"))
				case "other_genesis_local_ID":
					copy(value[:32], qualDomainHex(t, "a33e6e9e724bae375615ef204e3513c43dfdb4dfc5f6e55db00f1911fd01ce81"))
				case "zero_domain_local_ID":
					clear(value[:32])
				case "missing_domain":
					value = bytes.Clone(value[32:])
				case "local_domain_foreign_ID":
					value[32] ^= 1
				case "wrong_action_body":
					actionBody[len(actionBody)-1] ^= 1
				case "wrong_digest":
					value[len(value)-1] ^= 1
				case "missing_local_domain":
					local = nil
				case "zero_local_domain":
					clear(local)
				}
				// Each bad item gets a fully valid native proof and matching H
				// commitment: rejection cannot be credited to corrupt transport.
				w := qualDomainItemProof(t, value, shard)
				got := qualObserveDomainItem(t, m, evidence[shard], local, actionBody, w)
				if name == "valid" {
					require.NoError(t, got)
				} else {
					require.ErrorIs(t, got, errQualAckRejected)
					require.Equal(t, map[uint32]bool{other: true}, m.acknowledged)
					// Same local action ID remains usable after the colliding
					// foreign-domain item; rejection must not consume its bit.
					validWitness := qualDomainItemProof(t, validValue, shard)
					require.NoError(t, qualObserveDomainItem(t, m, evidence[shard], domain, body, validWitness))
				}
				require.Equal(t, map[uint32]bool{other: true, shard: true}, m.acknowledged)
				require.False(t, m.complete())
			})
		}
	}
}
