package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Independent, pre-code Python vectors. Every owner and application is
// synthetic; in particular CANCELLED is an input fixture, never an execution
// of legal cancellation. Family/phase strings allocate no protocol values.
type convergenceVector struct {
	Family, Phase, Lineage, Predecessor, Action string
	ActionDigestJSON                            string `json:"action_digest"`
	Target, Dependencies, Identity, Binding     string
	RequiredSetJSON                             string `json:"required_set"`
	OriginalOutcome                             string `json:"original_outcome"`
	Synthetic                                   bool
	Ack                                         []string
	States                                      map[string]struct{ Value, Commitment string }
}

func convergenceVectors(t *testing.T) []convergenceVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/convergence_identity_vectors.json")
	require.NoError(t, err)
	var fixture struct {
		Experimental, Synthetic bool
		Vectors                 []convergenceVector
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	require.True(t, fixture.Experimental)
	require.True(t, fixture.Synthetic)
	require.Len(t, fixture.Vectors, 12)
	return fixture.Vectors
}

func convergenceHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	require.NoError(t, err)
	return b
}

func (v convergenceVector) transition(t *testing.T) convergenceTransition {
	t.Helper()
	require.True(t, v.Synthetic)
	return convergenceTransition{action: convergenceHex(t, v.Action), digest: convergenceHex(t, v.ActionDigestJSON),
		token: []byte("TOKEN-abcdef"), target: convergenceHex(t, v.Target), dependencies: convergenceHex(t, v.Dependencies),
		requiredSet: convergenceHex(t, v.RequiredSetJSON), version: 7, shards: []uint32{0, 1, 2},
		context: &convergencePhaseContext{family: []byte(v.Family), phase: []byte(v.Phase),
			lineage: convergenceHex(t, v.Lineage), predecessor: convergenceHex(t, v.Predecessor)}}
}

func convergenceEncodingRecords() *convergenceRecords {
	return &convergenceRecords{codec: &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{},
		hasher: blake2b.NewBlake2b(), maxBytes: 4096}, maxShards: 16}
}

func TestConvergenceRecords_Encode(t *testing.T) {
	r := convergenceEncodingRecords()
	seen := make(map[string]bool)
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should match independent bytes", func(t *testing.T) {
			key, binding, err := r.encode(v.transition(t))
			require.NoError(t, err)
			require.Equal(t, append([]byte(convergencePrefix), convergenceHex(t, v.Identity)...), key)
			require.Equal(t, convergenceHex(t, v.Binding), binding)
			require.False(t, seen[string(key)], "equal action/target never aliases another family or phase")
			seen[string(key)] = true
		})
	}
	for _, field := range []string{"family", "phase", "lineage", "predecessor", "predecessor width", "oversized family", "oversized phase", "oversized lineage"} {
		t.Run(field+" should deny partial or unbounded context", func(t *testing.T) {
			tr := convergenceVectors(t)[0].transition(t)
			switch field {
			case "family":
				tr.context.family = nil
			case "phase":
				tr.context.phase = nil
			case "lineage":
				tr.context.lineage = nil
			case "predecessor":
				tr.context.predecessor = nil
			case "predecessor width":
				tr.context.predecessor = []byte{1}
			case "oversized family":
				tr.context.family = bytes.Repeat([]byte{1}, 4097)
			case "oversized phase":
				tr.context.phase = bytes.Repeat([]byte{1}, 4097)
			case "oversized lineage":
				tr.context.lineage = bytes.Repeat([]byte{1}, 4097)
			}
			_, _, err := r.encode(tr)
			require.Error(t, err)
			binding, progress, err := r.observe(tr)
			require.Error(t, err)
			require.Nil(t, binding)
			require.Nil(t, progress)
		})
	}
}

func TestConvergenceRecords_Value(t *testing.T) {
	r := convergenceEncodingRecords()
	for _, v := range convergenceVectors(t) {
		t.Run(v.Family+"/"+v.Phase+" should preserve exact progress commitments", func(t *testing.T) {
			binding := convergenceHex(t, v.Binding)
			for _, name := range []string{"initial", "one", "full", "terminal"} {
				p := &convergenceProgress{status: "PENDING", bitmap: []byte{0}, acks: make([][]byte, 3)}
				if name == "one" {
					p.bitmap[0] = 1
					p.acks[0] = r.codec.hasher.Compute(string(convergenceHex(t, v.Ack[0])))
				}
				if name == "full" || name == "terminal" {
					p.bitmap[0] = 7
					for i, ack := range v.Ack {
						p.acks[i] = r.codec.hasher.Compute(string(convergenceHex(t, ack)))
					}
				}
				if name == "terminal" {
					p.status = "COMPLETE"
				}
				value, err := r.value(binding, p)
				require.NoError(t, err)
				require.Equal(t, convergenceHex(t, v.States[name].Value), value)
				require.Equal(t, convergenceHex(t, v.States[name].Commitment), p.commitment)
			}
		})
	}
}
