package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/stretchr/testify/require"
)

// Qualification-only candidate. The accepted design is 3ef65176..., reviewed
// by Claude 5d8890ce.... Exact parameters remain unreviewed in
// W03_network_governance_synthetic_parameters_01.json: DO NOT EXECUTE YET.
// No real NG authority, successor consumer, loader or epoch callback is added.
// Native epoch observation is neither adoption nor canonical finality.
// The abstract fence below exercises ordering only, not T08 transport, native
// account persistence, rollback, finality or the real FAIL_SAFE allowlist.
var w03ErrSyntheticNG = errors.New("denied synthetic W03 NG fixture")

type w03SyntheticNGContext struct {
	domain, release, predecessor, successor, members [32]byte
	reviewer, adopter                                [32]byte
	transition, lineage                              string
	oldVersion, newVersion, threshold                uint64
	activation                                       uint32
}

func w03NGMessage(c w03SyntheticNGContext, purpose string) ([]byte, error) {
	message := append([]byte("W03/NG/FIXTURE/v1"), c.domain[:]...)
	field := func(value []byte) error {
		if len(value) > 128 {
			return w03ErrSyntheticNG
		}
		message = binary.BigEndian.AppendUint32(message, uint32(len(value)))
		message = append(message, value...)
		return nil
	}
	for _, value := range [][]byte{[]byte(purpose), []byte(c.transition), c.release[:], []byte(c.lineage)} {
		if err := field(value); err != nil {
			return nil, err
		}
	}
	message = binary.BigEndian.AppendUint64(message, c.oldVersion)
	_ = field(c.predecessor[:]) // Fixed-width arrays cannot exceed the fixture bound.
	message = binary.BigEndian.AppendUint64(message, c.newVersion)
	_ = field(c.successor[:])
	message = binary.BigEndian.AppendUint32(message, c.activation)
	_ = field(c.members[:])
	message = binary.BigEndian.AppendUint64(message, c.threshold)
	_ = field(c.reviewer[:])
	_ = field(c.adopter[:])
	// Three variable fields are bounded to 128; six fields are [32]byte.
	// With this fixed grammar the maximum is 689 bytes. A second 1024-byte
	// rejection would be unreachable and supply no additional guarantee.
	return message, nil
}

func w03NGDigest(c w03SyntheticNGContext, purpose string) ([]byte, error) {
	message, err := w03NGMessage(c, purpose)
	if err != nil {
		return nil, err
	}
	return sha256.NewSha256().Compute(string(message)), nil
}

type w03SyntheticNGProofs struct {
	release, adoption []byte
	indices           []uint64
	possession        [][]byte
}

type w03SyntheticNGFixture struct {
	context                                       w03SyntheticNGContext
	reviewer, adopter, oldNG                      crypto.PublicKey
	reviewerPrivate, adopterPrivate, oldNGPrivate crypto.PrivateKey
	members                                       []crypto.PublicKey
	memberPrivate                                 []crypto.PrivateKey
	staged                                        bool
}

func w03NewNGFixture(t *testing.T) *w03SyntheticNGFixture {
	t.Helper()
	f := &w03SyntheticNGFixture{context: w03SyntheticNGContext{
		transition: "w03-synthetic-ng-1-to-2", lineage: "W03_SYNTHETIC_NG",
		oldVersion: 1, newVersion: 2, threshold: 2, activation: 7,
	}}
	for i := range f.context.domain {
		f.context.domain[i] = 0xd1
	}
	keygen := signing.NewKeyGenerator(ed25519.NewEd25519())
	f.reviewerPrivate, f.reviewer = keygen.GeneratePair()
	f.adopterPrivate, f.adopter = keygen.GeneratePair()
	f.oldNGPrivate, f.oldNG = keygen.GeneratePair()
	seen := make(map[string]bool)
	publicBytes := func(key crypto.PublicKey) []byte {
		value, err := key.ToByteArray()
		require.NoError(t, err)
		require.Len(t, value, 32)
		require.False(t, seen[string(value)], "all six synthetic actor/member keys must differ")
		seen[string(value)] = true
		return value
	}
	copy(f.context.reviewer[:], publicBytes(f.reviewer))
	copy(f.context.adopter[:], publicBytes(f.adopter))
	hash := sha256.NewSha256()
	copy(f.context.release[:], hash.Compute("W03 synthetic reviewed release; no executable artifact"))
	oldBody := append([]byte("W03/NG/OLD/v1"), publicBytes(f.oldNG)...)
	copy(f.context.predecessor[:], hash.Compute(string(oldBody)))
	roster := binary.BigEndian.AppendUint32([]byte("W03/NG/ROSTER/v1"), 3)
	for i := 0; i < 3; i++ {
		private, public := keygen.GeneratePair()
		f.members = append(f.members, public)
		f.memberPrivate = append(f.memberPrivate, private)
		roster = append(roster, publicBytes(public)...)
	}
	roster = binary.BigEndian.AppendUint64(roster, 2)
	copy(f.context.members[:], hash.Compute(string(roster)))
	newBody := append([]byte("W03/NG/NEW/v1"), f.context.members[:]...)
	copy(f.context.successor[:], hash.Compute(string(newBody)))
	return f
}

func w03NGSign(t *testing.T, key crypto.PrivateKey, c w03SyntheticNGContext, purpose string) []byte {
	t.Helper()
	digest, err := w03NGDigest(c, purpose)
	require.NoError(t, err)
	proof, err := (&singlesig.Ed25519Signer{}).Sign(key, digest)
	require.NoError(t, err)
	return proof
}

func (f *w03SyntheticNGFixture) proofs(t *testing.T, c w03SyntheticNGContext, indices []uint64) w03SyntheticNGProofs {
	t.Helper()
	p := w03SyntheticNGProofs{
		release:  w03NGSign(t, f.reviewerPrivate, c, "W03/SYNTHETIC_NG_RELEASE/v1"),
		adoption: w03NGSign(t, f.adopterPrivate, c, "W03/SYNTHETIC_NG_ADOPTION/v1"),
		indices:  append([]uint64(nil), indices...),
	}
	for _, index := range indices {
		p.possession = append(p.possession, w03NGSign(t, f.memberPrivate[index], c, "W03/SYNTHETIC_SUCCESSOR_SET_PROOF/v1"))
	}
	return p
}

func (f *w03SyntheticNGFixture) stage(observedEpoch uint32, p w03SyntheticNGProofs) error {
	// The fixed fixture is the authority source; request signatures cannot select
	// a domain, body, actor, epoch or roster. These are synthetic actors only.
	if observedEpoch < f.context.activation || f.context.reviewer == f.context.adopter {
		return w03ErrSyntheticNG
	}
	signer := &singlesig.Ed25519Signer{}
	for _, item := range []struct {
		purpose string
		key     crypto.PublicKey
		proof   []byte
	}{
		{"W03/SYNTHETIC_NG_RELEASE/v1", f.reviewer, p.release},
		{"W03/SYNTHETIC_NG_ADOPTION/v1", f.adopter, p.adoption},
	} {
		digest, err := w03NGDigest(f.context, item.purpose)
		if err != nil || signer.Verify(item.key, digest, item.proof) != nil {
			return w03ErrSyntheticNG
		}
	}
	if len(p.indices) != len(p.possession) || uint64(len(p.indices)) < f.context.threshold {
		return w03ErrSyntheticNG
	}
	// The same fixed context has already passed both message encodings above;
	// the possession purpose is also shorter than the 128-byte field bound.
	digest, _ := w03NGDigest(f.context, "W03/SYNTHETIC_SUCCESSOR_SET_PROOF/v1")
	for i, index := range p.indices {
		if index >= uint64(len(f.members)) || (i > 0 && index <= p.indices[i-1]) {
			return w03ErrSyntheticNG
		}
		if signer.Verify(f.members[index], digest, p.possession[i]) != nil {
			return w03ErrSyntheticNG
		}
	}
	f.staged = true // Exact repeat leaves one fixed staged transition.
	return nil
}

// Ordered abstract transitions from Part A L1411-1419. Each state is copied by
// value for the synthetic restart case. No persisted replay, native journal,
// authenticated cross-shard ACK or real authority context is supplied by this.
type w03SyntheticRootFence struct {
	transition string
	target     [32]byte
	phase      uint8
	acks       [4][2]bool
	localFence [2]bool
	newPointer bool
	localNew   [2]bool
}

func (f *w03SyntheticRootFence) step(kind string) error {
	var from, to uint8
	switch kind {
	case "FENCE_ACTIVE":
		from, to = 0, 1
	case "POINTER_SWITCH":
		from, to = 3, 4
	case "FENCE_CLEAR":
		from, to = 5, 6
	case "TERMINAL":
		from, to = 7, 8
	default:
		return w03ErrSyntheticNG
	}
	if f.phase != from {
		return w03ErrSyntheticNG
	}
	if kind == "POINTER_SWITCH" {
		f.newPointer = true
	}
	f.phase = to
	return nil
}

func (f *w03SyntheticRootFence) ack(kind string, shard uint32, transition string, target [32]byte) error {
	var row int
	var phase uint8
	switch kind {
	case "ROOT_FENCE_ACK":
		row, phase = 0, 1
	case "ROOT_TARGET_READY_ACK":
		row, phase = 1, 2
	case "ROOT_CURRENT_ACK":
		row, phase = 2, 4
	case "ROOT_FENCE_CLEAR_ACK":
		row, phase = 3, 6
	default:
		return w03ErrSyntheticNG
	}
	if f.phase != phase || shard >= 2 || transition != f.transition || target != f.target {
		return w03ErrSyntheticNG
	}
	f.acks[row][shard] = true // Duplicate does not create another shard ACK.
	if row == 0 {
		f.localFence[shard] = true
	}
	if row == 2 {
		f.localNew[shard] = true
	}
	if row == 3 {
		f.localFence[shard] = false
	}
	if f.acks[row][0] && f.acks[row][1] {
		f.phase++
	}
	return nil
}

func (f *w03SyntheticRootFence) ordinary(shard uint32, plane string) bool {
	return shard < 2 && plane == "NORMAL" && !f.localFence[shard]
}

func TestQualDRWAAuthorityNGSyntheticProofs(t *testing.T) {
	f := w03NewNGFixture(t)
	p := f.proofs(t, f.context, []uint64{0, 1})
	epochs := forking.NewGenericEpochNotifier()
	require.Zero(t, epochs.CurrentEpoch())
	epochs.CheckEpoch(&block.MetaBlock{Epoch: 6})
	require.Error(t, f.stage(epochs.CurrentEpoch(), p))
	require.False(t, f.staged)
	epochs.CheckEpoch(&block.MetaBlock{Epoch: 7})
	require.NoError(t, f.stage(epochs.CurrentEpoch(), p))
	require.True(t, f.staged)
	epochs.CheckEpoch(&block.MetaBlock{Epoch: 7})
	require.NoError(t, f.stage(epochs.CurrentEpoch(), p))
	epochs.CheckEpoch(&block.MetaBlock{Epoch: 8})
	require.NoError(t, f.stage(epochs.CurrentEpoch(), p))
	require.Equal(t, "w03-synthetic-ng-1-to-2", f.context.transition)
	// Native proposed-v3 notification can observe the next epoch. Even that
	// observation cannot supply the two synthetic authorizations or finality.
	proposed := forking.NewGenericEpochNotifier()
	proposed.CheckEpoch(&block.MetaBlockV3{Epoch: 6, EpochChangeProposed: true})
	require.Equal(t, uint32(7), proposed.CurrentEpoch())
	withoutProofs := w03NewNGFixture(t)
	require.Error(t, withoutProofs.stage(proposed.CurrentEpoch(), w03SyntheticNGProofs{}))
	require.False(t, withoutProofs.staged)
	for _, row := range []struct {
		name   string
		change func(*testing.T, *w03SyntheticNGFixture, *w03SyntheticNGProofs)
	}{
		{"epoch_alone", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { *p = w03SyntheticNGProofs{} }},
		{"release_only", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.adoption = nil }},
		{"adoption_only", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.release = nil }},
		{"ng_compromise_alone", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.release = w03NGSign(t, f.oldNGPrivate, f.context, "W03/SYNTHETIC_NG_RELEASE/v1")
			p.adoption = w03NGSign(t, f.oldNGPrivate, f.context, "W03/SYNTHETIC_NG_ADOPTION/v1")
		}},
		{"swapped_purpose", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.release, p.adoption = p.adoption, p.release
		}},
		{"cross_purpose_same_key", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.release = w03NGSign(t, f.reviewerPrivate, f.context, "W03/SYNTHETIC_NG_ADOPTION/v1")
		}},
		{"same_actor", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			f.context.adopter = f.context.reviewer
			f.adopter, f.adopterPrivate = f.reviewer, f.reviewerPrivate
			*p = f.proofs(t, f.context, []uint64{0, 1})
		}},
		{"invalid_release", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.release[0] ^= 1 }},
		{"invalid_adoption", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.adoption[0] ^= 1 }},
		{"insufficient_possession", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			p.indices = p.indices[:1]
			p.possession = p.possession[:1]
		}},
		{"count_mismatch", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.indices = p.indices[:1] }},
		{"out_of_roster", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.indices[1] = 3 }},
		{"wrong_member", func(_ *testing.T, _ *w03SyntheticNGFixture, p *w03SyntheticNGProofs) { p.indices = []uint64{1, 2} }},
		{"duplicate_indices", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			*p = f.proofs(t, f.context, []uint64{0, 0})
		}},
		{"unordered_indices", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			*p = f.proofs(t, f.context, []uint64{1, 0})
		}},
		{"invalid_extra", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			*p = f.proofs(t, f.context, []uint64{0, 1, 2})
			p.possession[2][0] ^= 1
		}},
		{"too_many", func(t *testing.T, f *w03SyntheticNGFixture, p *w03SyntheticNGProofs) {
			*p = f.proofs(t, f.context, []uint64{0, 1, 2, 0})
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := w03NewNGFixture(t)
			p := f.proofs(t, f.context, []uint64{0, 1})
			row.change(t, f, &p)
			require.Error(t, f.stage(7, p))
			require.False(t, f.staged)
		})
	}
	for _, row := range []struct {
		name   string
		change func(*w03SyntheticNGContext)
	}{
		{"wrong_domain", func(c *w03SyntheticNGContext) { c.domain[0] ^= 1 }},
		{"missing_domain", func(c *w03SyntheticNGContext) { c.domain = [32]byte{} }},
		{"wrong_release_artifact", func(c *w03SyntheticNGContext) { c.release[0] ^= 1 }},
		{"wrong_predecessor", func(c *w03SyntheticNGContext) { c.predecessor[0] ^= 1 }},
		{"wrong_successor", func(c *w03SyntheticNGContext) { c.successor[0] ^= 1 }},
		{"wrong_roster", func(c *w03SyntheticNGContext) { c.members[0] ^= 1 }},
		{"wrong_reviewer", func(c *w03SyntheticNGContext) { c.reviewer[0] ^= 1 }},
		{"wrong_adopter", func(c *w03SyntheticNGContext) { c.adopter[0] ^= 1 }},
		{"wrong_transition", func(c *w03SyntheticNGContext) { c.transition += "wrong" }},
		{"wrong_lineage", func(c *w03SyntheticNGContext) { c.lineage += "wrong" }},
		{"wrong_old_version", func(c *w03SyntheticNGContext) { c.oldVersion++ }},
		{"wrong_new_version", func(c *w03SyntheticNGContext) { c.newVersion++ }},
		{"wrong_threshold", func(c *w03SyntheticNGContext) { c.threshold++ }},
		{"wrong_activation", func(c *w03SyntheticNGContext) { c.activation++ }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := w03NewNGFixture(t)
			altered := f.context
			row.change(&altered)
			p := f.proofs(t, altered, []uint64{0, 1})
			require.Error(t, f.stage(7, p)) // Valid signatures, wrong fixed body.
			require.False(t, f.staged)
		})
	}
	// Honest selection is not guaranteed after both artificial authorizers are
	// compromised. Acceptance still requires the fixture's exact fixed body;
	// passing verification cannot establish that it was an honest selection.
	all := w03NewNGFixture(t)
	require.NoError(t, all.stage(7, all.proofs(t, all.context, []uint64{0, 1, 2})))
}

func TestQualDRWAAuthorityNGSyntheticFormats(t *testing.T) {
	f := w03NewNGFixture(t)
	message, err := w03NGMessage(f.context, "W03/SYNTHETIC_NG_RELEASE/v1")
	require.NoError(t, err)
	for _, otherBytes := range [][]byte{
		message,
		append([]byte("W03 synthetic personal-message-like prefix:"), message...),
		[]byte(`{"nonce":1,"data":"synthetic transaction-shaped bytes"}`),
	} {
		p := f.proofs(t, f.context, []uint64{0, 1})
		p.release, err = (&singlesig.Ed25519Signer{}).Sign(f.reviewerPrivate, otherBytes)
		require.NoError(t, err)
		require.Error(t, f.stage(7, p))
	}
	for _, field := range []string{"purpose", "transition", "lineage"} {
		c := f.context
		purpose := "W03/SYNTHETIC_NG_RELEASE/v1"
		oversized := string(bytes.Repeat([]byte{'x'}, 129))
		switch field {
		case "purpose":
			purpose = oversized
		case "transition":
			c.transition = oversized
		case "lineage":
			c.lineage = oversized
		}
		_, err = w03NGMessage(c, purpose)
		require.Error(t, err)
		_, err = w03NGDigest(c, purpose)
		require.Error(t, err)
	}
	c := f.context
	c.transition, c.lineage = string(bytes.Repeat([]byte{'x'}, 128)), string(bytes.Repeat([]byte{'x'}, 128))
	bounded, err := w03NGMessage(c, string(bytes.Repeat([]byte{'x'}, 128)))
	require.NoError(t, err)
	require.Len(t, bounded, 689)
	// A malformed fixed context must not turn an encoding error into acceptance
	// of otherwise valid native signatures over empty bytes. This isolates the
	// stage's encoding-error propagation from native cryptographic rejection.
	bad := w03NewNGFixture(t)
	bad.context.transition = string(bytes.Repeat([]byte{'x'}, 129))
	signer := &singlesig.Ed25519Signer{}
	p := w03SyntheticNGProofs{indices: []uint64{0, 1}}
	p.release, err = signer.Sign(bad.reviewerPrivate, nil)
	require.NoError(t, err)
	p.adoption, err = signer.Sign(bad.adopterPrivate, nil)
	require.NoError(t, err)
	for _, key := range bad.memberPrivate[:2] {
		proof, err := signer.Sign(key, nil)
		require.NoError(t, err)
		p.possession = append(p.possession, proof)
	}
	require.Error(t, bad.stage(7, p))
	require.False(t, bad.staged)
}

func TestQualDRWAAuthorityNGSyntheticFence(t *testing.T) {
	proofFixture := w03NewNGFixture(t)
	require.NoError(t, proofFixture.stage(7, proofFixture.proofs(t, proofFixture.context, []uint64{0, 1})))
	for first, name := range []string{"shard0_first", "shard1_first"} {
		t.Run(name, func(t *testing.T) {
			w03AssertSyntheticFence(t, proofFixture, uint32(first), 1-uint32(first))
		})
	}
}

func w03AssertSyntheticFence(t *testing.T, proofFixture *w03SyntheticNGFixture, first, second uint32) {
	t.Helper()
	f := w03SyntheticRootFence{transition: proofFixture.context.transition, target: proofFixture.context.successor}
	require.True(t, f.ordinary(0, "NORMAL"))
	require.False(t, f.ordinary(0, "FAIL_SAFE"))
	require.NoError(t, f.step("FENCE_ACTIVE"))
	for _, row := range []struct {
		ack       string
		next      string
		reordered string
	}{
		{"ROOT_FENCE_ACK", "", "ROOT_TARGET_READY_ACK"},
		{"ROOT_TARGET_READY_ACK", "POINTER_SWITCH", "ROOT_CURRENT_ACK"},
		{"ROOT_CURRENT_ACK", "FENCE_CLEAR", "ROOT_FENCE_CLEAR_ACK"},
		{"ROOT_FENCE_CLEAR_ACK", "TERMINAL", "ROOT_FENCE_ACK"},
	} {
		before := f
		for _, early := range []string{"POINTER_SWITCH", "FENCE_CLEAR", "TERMINAL"} {
			require.Error(t, f.step(early))
		}
		wrong := f.target
		wrong[0] ^= 1
		require.Error(t, f.ack(row.ack, 2, f.transition, f.target))
		require.Error(t, f.ack(row.ack, 0, "wrong transition", f.target))
		require.Error(t, f.ack(row.ack, 0, f.transition, wrong))
		require.Error(t, f.ack("UNKNOWN_ACK", 0, f.transition, f.target))
		require.Error(t, f.ack(row.reordered, 0, f.transition, f.target))
		require.Equal(t, before, f)
		require.NoError(t, f.ack(row.ack, first, f.transition, f.target))
		partial := f
		require.NoError(t, f.ack(row.ack, first, f.transition, f.target))
		require.Equal(t, partial, f)
		if row.ack == "ROOT_FENCE_ACK" {
			require.False(t, f.ordinary(first, "NORMAL"))
			require.True(t, f.ordinary(second, "NORMAL")) // Propagation window, predecessor remains current.
		} else if row.ack == "ROOT_FENCE_CLEAR_ACK" {
			require.True(t, f.ordinary(first, "NORMAL"))
			require.False(t, f.ordinary(second, "NORMAL")) // Lagging locus remains restrictive.
		} else {
			require.False(t, f.ordinary(0, "NORMAL"))
			require.False(t, f.ordinary(1, "NORMAL"))
		}
		require.False(t, f.ordinary(0, "FAIL_SAFE"))
		require.False(t, f.ordinary(1, "FAIL_SAFE"))
		if row.next != "" {
			require.Error(t, f.step(row.next)) // One shard never satisfies ALL.
			require.Equal(t, partial, f)
		}
		// Value-copy restart retains the pending exact transition and both shard
		// observations. It is deliberately not a disk/native restart test.
		f = partial
		require.NoError(t, f.ack(row.ack, second, f.transition, f.target))
		if row.next != "" {
			require.NoError(t, f.step(row.next))
		}
	}
	require.Equal(t, uint8(8), f.phase)
	require.True(t, f.newPointer)
	require.Equal(t, [2]bool{true, true}, f.localNew)
	require.True(t, f.ordinary(0, "NORMAL"))
	require.False(t, f.ordinary(0, "FAIL_SAFE")) // Clear never exits plane.
	require.False(t, f.ordinary(2, "NORMAL"))
	before := f
	require.Error(t, f.step("POINTER_SWITCH"))
	require.Error(t, f.step("UNKNOWN"))
	require.Error(t, f.ack("ROOT_CURRENT_ACK", 0, f.transition, f.target))
	require.Equal(t, before, f)
}
