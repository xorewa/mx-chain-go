package trie

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
)

// These helpers exist solely to support deliberate fault-injection in
// the trie test suite (see TestNode_NodeExtension and
// TestSnapshotGetTestPoint in node_test.go). They previously lived in
// node_extension.go — a production source file — where every audit
// pass flagged the math/rand usage and the unguarded 1-in-`faultyChance`
// failure trigger as a security concern. Reachability analysis confirmed
// no production caller; moving them into a _test.go file makes the
// test-only intent explicit and keeps the production build free of
// fault-injection state. See issues/ISSUE-034.

const faultyChance = 1000000

func shouldTestNode(n node, key []byte) bool {
	hasher := n.getHasher()
	randomness := string(key) + core.GetAnonymizedMachineID("") + fmt.Sprintf("%d", time.Now().UnixNano())
	buff := hasher.Compute(randomness)
	checkVal := binary.BigEndian.Uint32(buff)
	if checkVal%faultyChance == 0 {
		log.Debug("deliberately not saving hash", "hash", key)
		return true
	}

	return false
}

func snapshotGetTestPoint(key []byte, faultyChance int) error {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	checkVal := rnd.Intn(math.MaxInt)
	if checkVal%faultyChance == 0 {
		log.Debug("deliberately not returning hash", "hash", key)
		return fmt.Errorf("snapshot get error")
	}

	return nil
}
