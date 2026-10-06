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

func qualDomainItemProof(t *testing.T, value []byte, shard uint32, key []byte) qualDomainItemWitness {
	t.Helper()
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
	if !qualDomainValueMatches(m, e, localDomain, immutableActionBody, value, w.shard) {
		return errQualAckRejected
	}
	return m.observe(e)
}

// Shared qualification-only domain predicate for synthetic and account-backed
// item readers. Neither predicate writes progress; observe remains the writer.
func qualDomainValueMatches(m *qualConvergenceModel, e qualApplicationEvidence,
	localDomain, immutableActionBody, value []byte, shard uint32) bool {
	if len(localDomain) != 32 || bytes.Equal(localDomain, make([]byte, 32)) ||
		len(value) != 64+len(e.ack.actionDigest) || !bytes.Equal(value[:32], localDomain) {
		return false
	}
	preimage := append([]byte("DRWA/GAS/v1"), localDomain...)
	preimage = append(preimage, immutableActionBody...)
	expectedID := blake2b.NewBlake2b().Compute(string(preimage))
	return bytes.Equal(value[32:64], expectedID) && hex.EncodeToString(expectedID) == m.inputs.action.actionID &&
		bytes.Equal(value[64:], []byte(e.ack.actionDigest)) && shard == e.ack.shard
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
				w := qualDomainItemProof(t, value, shard, []byte("fixture/domain-bound-ack"))
				got := qualObserveDomainItem(t, m, evidence[shard], local, actionBody, w)
				if name == "valid" {
					require.NoError(t, got)
				} else {
					require.ErrorIs(t, got, errQualAckRejected)
					require.Equal(t, map[uint32]bool{other: true}, m.acknowledged)
					// Same local action ID remains usable after the colliding
					// foreign-domain item; rejection must not consume its bit.
					validWitness := qualDomainItemProof(t, validValue, shard, []byte("fixture/domain-bound-ack"))
					require.NoError(t, qualObserveDomainItem(t, m, evidence[shard], domain, body, validWitness))
				}
				require.Equal(t, map[uint32]bool{other: true, shard: true}, m.acknowledged)
				require.False(t, m.complete())
			})
		}
	}
}

// NON-NORMATIVE AR-01/G3 native-byte join. The complete ACK is committed in
// the fixture trie KEY; its value carries the network domain, action ID and
// digest. fmt's struct representation is a test-only key, never a DRWA codec.
// Canonical M/B ancestry and finality remain supplied model assumptions. This
// closes only item -> ACK -> native S/result/root/H equality before observe.
func qualDomainAckKey(ack qualAckPayload) []byte {
	return []byte(fmt.Sprintf("fixture/ack/%#v", ack))
}

func qualObserveResultBoundDomainItem(t *testing.T, m *qualConvergenceModel, e qualApplicationEvidence,
	localDomain, body []byte, w qualDomainItemWitness) error {
	t.Helper()
	if !bytes.Equal(w.key, qualDomainAckKey(e.ack)) || !qualNativeResultMatches(e, w) {
		return errQualAckRejected
	}
	return qualObserveDomainItem(t, m, e, localDomain, body, w)
}

// Byte identities only: membership and canonical M/B remain separate gates.
// This bounded join accepts single-result H only. Multi-result native import
// is supported by qualImportResultItem but is deliberately outside this join.
func qualNativeResultMatches(e qualApplicationEvidence, w qualDomainItemWitness) bool {
	mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	h := &coreBlock.HeaderV3{}
	if mar.Unmarshal(h, w.h) != nil || len(h.ExecutionResults) != 1 {
		return false
	}
	r := h.ExecutionResults[0]
	if r == nil || r.BaseExecutionResult == nil {
		return false
	}
	rb, err := mar.Marshal(r)
	if err != nil {
		return false
	}
	sID, hID := hex.EncodeToString(hash.Compute(string(w.s))), hex.EncodeToString(hash.Compute(string(w.h)))
	rID, root := hex.EncodeToString(hash.Compute(string(rb))), hex.EncodeToString(r.BaseExecutionResult.RootHash)
	return e.witness.executedHeader == sID && e.witness.carryingHeader == hID &&
		e.witness.executionResult == rID && e.witness.fullResult.identity == rID &&
		e.witness.fullResult.executedHeader == sID && e.witness.fullResult.rootHash == root
}

// Bind the EXPECTED canonical model inputs to one native fixture, before any
// candidate substitution. No verifier calls this helper or rewrites inputs.
func qualBindDomainResultFixture(t *testing.T, m *qualConvergenceModel, e qualApplicationEvidence,
	w qualDomainItemWitness) qualApplicationEvidence {
	t.Helper()
	mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	h := &coreBlock.HeaderV3{}
	require.NoError(t, mar.Unmarshal(h, w.h))
	require.Len(t, h.ExecutionResults, 1)
	result := h.ExecutionResults[0]
	rb, err := mar.Marshal(result)
	require.NoError(t, err)
	witness := e.witness
	witness.executedHeader = hex.EncodeToString(hash.Compute(string(w.s)))
	witness.carryingHeader = hex.EncodeToString(w.hHash)
	witness.executionResult = hex.EncodeToString(hash.Compute(string(rb)))
	witness.fullResult = qualExecutionResult{identity: witness.executionResult,
		executedHeader: witness.executedHeader, rootHash: hex.EncodeToString(result.BaseExecutionResult.RootHash), ack: e.ack}
	e.witness = witness
	m.inputs.executedHeaders[witness.executedHeader] = qualExecutedHeader{identity: witness.executedHeader, shard: w.shard}
	m.inputs.carriers[witness.carryingHeader] = qualCarryingHeader{identity: witness.carryingHeader,
		shard: w.shard, results: map[string]qualExecutionResult{witness.executionResult: witness.fullResult}}
	reference := m.inputs.references[witness.metachainReference]
	reference.entries = []qualReferenceEntry{{carryingHeader: witness.carryingHeader,
		executedHeader: witness.executedHeader, executionResult: witness.executionResult, shard: w.shard}}
	m.inputs.references[reference.identity] = reference
	return e
}

func TestQualDRWADomainResultJoin(t *testing.T) {
	for shard := uint32(0); shard < 3; shard++ {
		for _, name := range []string{"valid", "other_authenticated_ACK", "ack_family", "ack_instance", "ack_subject",
			"ack_target", "ack_dependencies", "ack_shard_set", "ack_action_id", "ack_action_digest", "ack_shard",
			"ack_local_execution", "ack_applied_state", "other_native_S", "other_native_H",
			"other_native_root", "other_complete_result", "other_model_root", "other_model_S"} {
			t.Run(fmt.Sprintf("shard_%d/%s", shard, name), func(t *testing.T) {
				m, evidence := qualDomainConvergenceFixture(t)
				other := (shard + 1) % 3
				require.NoError(t, m.observe(evidence[other]))
				e := evidence[shard]
				domain, body := qualDomainHex(t, qualDomainKAT), qualDomainHex(t, qualDomainBodyHex)
				value := append(bytes.Clone(domain), qualDomainHex(t, qualDomainActionKAT)...)
				value = append(value, []byte(e.ack.actionDigest)...)
				w := qualDomainItemProof(t, value, shard, qualDomainAckKey(e.ack))
				e = qualBindDomainResultFixture(t, m, e, w)
				valid := w
				validEvidence := e
				mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
				encode := func(v interface{}) []byte { b, err := mar.Marshal(v); require.NoError(t, err); return b }
				switch name {
				case "other_authenticated_ACK", "ack_family", "ack_instance", "ack_subject", "ack_target",
					"ack_dependencies", "ack_shard_set", "ack_action_id", "ack_action_digest", "ack_shard",
					"ack_local_execution", "ack_applied_state":
					ack := e.ack
					switch name {
					case "other_authenticated_ACK":
						ack.binding.phase = "PREPARED_ACK"
					case "ack_family":
						ack.binding.family = "OTHER_FAMILY"
					case "ack_instance":
						ack.binding.instance = "other-instance"
					case "ack_subject":
						ack.binding.subject = "token-B"
					case "ack_target":
						ack.binding.target = "target-B"
					case "ack_dependencies":
						ack.binding.dependencies = "dependencies-B"
					case "ack_shard_set":
						ack.binding.requiredShardSet = "shard-set-B"
					case "ack_action_id":
						ack.actionID = "action-B"
					case "ack_action_digest":
						ack.actionDigest = "digest-B"
					case "ack_shard":
						ack.shard = other
					case "ack_local_execution":
						ack.localExecutionIdentity = "other-apply"
					case "ack_applied_state":
						ack.appliedStateHash = "other-state"
					}
					w = qualDomainItemProof(t, value, shard, qualDomainAckKey(ack))
					// Admit the candidate's actual native identities in the model,
					// while retaining its expected ACK. Only authenticated ACK/key
					// equality may distinguish this payload substitution.
					e = qualBindDomainResultFixture(t, m, e, w)
				case "other_native_S":
					s, h := &coreBlock.HeaderV3{}, &coreBlock.HeaderV3{}
					require.NoError(t, mar.Unmarshal(s, w.s))
					require.NoError(t, mar.Unmarshal(h, w.h))
					s.PrevHash = []byte("different-origin")
					w.s = encode(s)
					h.ExecutionResults[0].BaseExecutionResult.HeaderHash = hash.Compute(string(w.s))
					w.h = encode(h)
					w.hHash = hash.Compute(string(w.h))
				case "other_native_H":
					h := &coreBlock.HeaderV3{}
					require.NoError(t, mar.Unmarshal(h, w.h))
					h.PrevHash = []byte("different-carrier")
					w.h = encode(h)
					w.hHash = hash.Compute(string(w.h))
				case "other_native_root":
					// Same item, with a second unrelated trie entry: membership
					// is valid but its native result root belongs to another result.
					tr := qualItemTrie(t, testscommon.NewMemDbMock())
					require.NoError(t, tr.Update(w.key, value))
					require.NoError(t, tr.Update([]byte("unrelated"), []byte("another-root")))
					root, err := tr.RootHash()
					require.NoError(t, err)
					w.nodes, _, err = tr.GetProof(w.key)
					require.NoError(t, err)
					w.limit = 0
					for _, node := range w.nodes {
						w.limit += len(node)
					}
					h := &coreBlock.HeaderV3{}
					require.NoError(t, mar.Unmarshal(h, w.h))
					h.ExecutionResults[0].BaseExecutionResult.RootHash = root
					w.h = encode(h)
					w.hHash = hash.Compute(string(w.h))
				case "other_complete_result":
					h := &coreBlock.HeaderV3{}
					require.NoError(t, mar.Unmarshal(h, w.h))
					h.ExecutionResults[0].BaseExecutionResult.GasUsed++
					w.h = encode(h)
					w.hHash = hash.Compute(string(w.h))
					// Keep canonical H and all opaque model relations consistent;
					// only the native complete result differs from the model result.
					carrier := m.inputs.carriers[e.witness.carryingHeader]
					e.witness.carryingHeader = hex.EncodeToString(w.hHash)
					carrier.identity = e.witness.carryingHeader
					m.inputs.carriers[carrier.identity] = carrier
					ref := m.inputs.references[e.witness.metachainReference]
					ref.entries[0].carryingHeader = carrier.identity
					m.inputs.references[ref.identity] = ref
				case "other_model_root":
					e.witness.fullResult.rootHash = "different-model-root"
					carrier := m.inputs.carriers[e.witness.carryingHeader]
					carrier.results[e.witness.executionResult] = e.witness.fullResult
					m.inputs.carriers[carrier.identity] = carrier
				case "other_model_S":
					// All opaque model relations remain internally valid, while
					// native S/H/result/root bytes are unchanged. Only the S join
					// comparisons distinguish this substitution (GJ-01).
					e.witness.executedHeader = "different-model-S"
					e.witness.fullResult.executedHeader = e.witness.executedHeader
					m.inputs.executedHeaders[e.witness.executedHeader] = qualExecutedHeader{
						identity: e.witness.executedHeader, shard: shard,
					}
					carrier := m.inputs.carriers[e.witness.carryingHeader]
					carrier.results[e.witness.executionResult] = e.witness.fullResult
					m.inputs.carriers[carrier.identity] = carrier
					ref := m.inputs.references[e.witness.metachainReference]
					ref.entries[0].executedHeader = e.witness.executedHeader
					m.inputs.references[ref.identity] = ref
				}
				// Baseline control: both the native membership and opaque model
				// admit these substitutions separately. The join must reject them.
				control := *m
				control.acknowledged = map[uint32]bool{other: true}
				require.NoError(t, qualObserveDomainItem(t, &control, e, domain, body, w))
				got := qualObserveResultBoundDomainItem(t, m, e, domain, body, w)
				if name == "valid" {
					require.NoError(t, got)
					require.NoError(t, qualObserveResultBoundDomainItem(t, m, e, domain, body, w))
					require.Equal(t, map[uint32]bool{other: true, shard: true}, m.acknowledged)
				} else {
					require.ErrorIs(t, got, errQualAckRejected)
					require.Equal(t, map[uint32]bool{other: true}, m.acknowledged)
					// Restore only trusted fixture inputs, never progress. This is
					// a valid-retry control, not persistence or recovery evidence.
					e = qualBindDomainResultFixture(t, m, validEvidence, valid)
					require.NoError(t, qualObserveResultBoundDomainItem(t, m, e, domain, body, valid))
					require.Equal(t, map[uint32]bool{other: true, shard: true}, m.acknowledged)
				}
				require.False(t, m.complete())
			})
		}
	}
}

// GJ-02: disclose and exercise the single-result join's admission boundary.
// A valid native item import with several results does not imply that this
// bounded model join supports them. M/B ancestry and finality remain assumed.
func TestQualDRWADomainResultCardinality(t *testing.T) {
	for _, name := range []string{"valid", "zero_results", "two_results", "empty_result", "malformed_header"} {
		t.Run(name, func(t *testing.T) {
			m, evidence := qualDomainConvergenceFixture(t)
			e := evidence[1]
			domain, body := qualDomainHex(t, qualDomainKAT), qualDomainHex(t, qualDomainBodyHex)
			value := append(bytes.Clone(domain), qualDomainHex(t, qualDomainActionKAT)...)
			value = append(value, []byte(e.ack.actionDigest)...)
			w := qualDomainItemProof(t, value, 1, qualDomainAckKey(e.ack))
			e = qualBindDomainResultFixture(t, m, e, w)
			mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
			h := &coreBlock.HeaderV3{}
			require.NoError(t, mar.Unmarshal(h, w.h))
			switch name {
			case "zero_results":
				h.ExecutionResults = nil
			case "two_results":
				other := createDummyShardExecutionResult()
				other.BaseExecutionResult.HeaderHash = []byte("unrelated-origin")
				h.ExecutionResults = append(h.ExecutionResults, other)
			case "empty_result":
				// Protobuf represents an empty result as a non-nil entry with
				// nil BaseExecutionResult; no nil repeated-message is encoded.
				h.ExecutionResults = []*coreBlock.ExecutionResult{{}}
			}
			var err error
			w.h, err = mar.Marshal(h)
			require.NoError(t, err)
			if name == "malformed_header" {
				w.h = []byte{0xff}
			}
			w.hHash = hash.Compute(string(w.h))
			// Keep only H's opaque model identity consistent with the new H.
			// Do not fabricate another native result or change its expected ID.
			carrier := m.inputs.carriers[e.witness.carryingHeader]
			e.witness.carryingHeader = hex.EncodeToString(w.hHash)
			carrier.identity = e.witness.carryingHeader
			m.inputs.carriers[carrier.identity] = carrier
			ref := m.inputs.references[e.witness.metachainReference]
			ref.entries[0].carryingHeader = carrier.identity
			m.inputs.references[ref.identity] = ref
			if name == "two_results" {
				got, importErr := qualImportResultItem(t, w.hHash, w.h, w.s, w.key, w.nodes, 1, w.limit)
				require.NoError(t, importErr)
				require.Equal(t, value, got, "native import supports unrelated additional results")
			}
			err = qualObserveResultBoundDomainItem(t, m, e, domain, body, w)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, map[uint32]bool{1: true}, m.acknowledged)
			} else {
				require.ErrorIs(t, err, errQualAckRejected)
				require.Empty(t, m.acknowledged)
			}
		})
	}
}
