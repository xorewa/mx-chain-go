package drwa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/stretchr/testify/require"
)

// UNREVIEWED, compile-only synthetic candidate under L40. This composes proofs
// over an already trusted fixture context. No claim, enrollment, current root,
// possession, funding, admission, writer or real appointment is established.
// Native private keys exist only in memory and are never serialized or logged.
type w03D03RoleRoster struct {
	authority w03D03CertificateAuthority
	members   [][]byte
	private   []crypto.PrivateKey
}
type w03D03RoleProof struct {
	indices    []uint64
	signatures [][]byte
}
type w03D03CompositionProof struct {
	proposal, admission w03D03RoleProof
	execution           [6]w03D03RoleProof
}
type w03D03CompositionRule struct {
	proposer, admission byte
	execution           byte
}

// This exact L40 table selects a synthetic coalition, not a loss predicate.
func w03D03CompositionMapping(c w03D03CertificateContext) (w03D03CompositionRule, error) {
	if c.impact > 1 || (c.operation != "RECOVER_SCOPED_ROLE" && c.operation != "REBIND_WIND_DOWN") {
		return w03D03CompositionRule{}, w03ErrD03Certificate
	}
	var rule w03D03CompositionRule
	switch c.branch {
	case 1: // M19: OTHER, SA, ATA or EA; healthy PA/PR are prerequisites.
		rule = w03D03CompositionRule{proposer: 1, admission: 0, execution: 1 | 2 | 4}
		switch c.targets {
		case 4: // SA target: use ATA, plus EA for high impact.
			rule.execution = 1 | 2 | 8
			if c.impact == 1 {
				rule.execution |= 16
			}
		case 8: // ATA target: use SA, plus EA for high impact.
			if c.impact == 1 {
				rule.execution |= 16
			}
		case 16, 32: // EA or OTHER target: add ATA for high impact.
			if c.impact == 1 {
				rule.execution |= 8
			}
		default:
			return w03D03CompositionRule{}, w03ErrD03Certificate
		}
	case 2: // M20: PA unavailable.
		if c.targets != 1 {
			return w03D03CompositionRule{}, w03ErrD03Certificate
		}
		rule = w03D03CompositionRule{proposer: 1, admission: 2, execution: 2 | 4 | 8}
	case 3: // M21: PR unavailable, healthy PA.
		if c.targets != 2 {
			return w03D03CompositionRule{}, w03ErrD03Certificate
		}
		rule = w03D03CompositionRule{proposer: 0, admission: 2, execution: 1 | 4 | 8}
	case 4: // M22: PA and PR unavailable.
		if c.targets != 3 {
			return w03D03CompositionRule{}, w03ErrD03Certificate
		}
		rule = w03D03CompositionRule{proposer: 2, admission: 3, execution: 4 | 8 | 16}
	default:
		return w03D03CompositionRule{}, w03ErrD03Certificate
	}
	return rule, nil
}

func w03D03CompositionVerify(c w03D03CertificateContext, rosters [6]w03D03RoleRoster, proof w03D03CompositionProof) error {
	rule, err := w03D03CompositionMapping(c)
	if err != nil {
		return err
	}
	// Repeated admission/execution use of one role is one factor. Distinct
	// required roles must have distinct IDs and disjoint complete key material.
	needed := rule.execution | (1 << rule.proposer) | (1 << rule.admission)
	for i := range rosters {
		if needed&(1<<i) == 0 {
			continue
		}
		for j := i + 1; j < len(rosters); j++ {
			if needed&(1<<j) == 0 {
				continue
			}
			if rosters[i].authority.id == rosters[j].authority.id {
				return w03ErrD03Certificate
			}
			for _, left := range rosters[i].members {
				for _, right := range rosters[j].members {
					if bytes.Equal(left, right) {
						return w03ErrD03Certificate
					}
				}
			}
		}
	}
	verify := func(role byte, purpose string, certificate w03D03RoleProof) error {
		roster := rosters[role]
		digest, digestErr := w03D03CertificateDigest(c, roster.authority, purpose)
		if digestErr != nil {
			return digestErr
		}
		return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, roster.members,
			certificate.indices, certificate.signatures, digest, 5, 32)
	}
	if err = verify(rule.proposer, "W03_D03_PROPOSE", proof.proposal); err != nil {
		return err
	}
	if err = verify(rule.admission, "W03_D03_ADMIT", proof.admission); err != nil {
		return err
	}
	for role, certificate := range proof.execution {
		if rule.execution&(1<<role) == 0 {
			if len(certificate.indices) != 0 || len(certificate.signatures) != 0 {
				return w03ErrD03Certificate
			}
			continue
		}
		if err = verify(byte(role), "W03_D03_EXECUTE", certificate); err != nil {
			return err
		}
	}
	return nil
}

func w03D03CompositionRosters(t *testing.T) [6]w03D03RoleRoster {
	t.Helper()
	var rosters [6]w03D03RoleRoster
	keygen := signing.NewKeyGenerator(ed25519.NewEd25519())
	for role := range rosters {
		rosters[role].authority.role = byte(role)
		rosters[role].authority.version = 1
		rosters[role].authority.id[0] = byte(role + 1)
		for member := 0; member < 5; member++ {
			private, public := keygen.GeneratePair()
			encoded, err := public.ToByteArray()
			require.NoError(t, err)
			rosters[role].members = append(rosters[role].members, encoded)
			rosters[role].private = append(rosters[role].private, private)
		}
		w03D03CompositionRosterDigest(&rosters[role])
	}
	return rosters
}

func w03D03CompositionRosterDigest(roster *w03D03RoleRoster) {
	body := binary.BigEndian.AppendUint64(nil, 3)
	for _, member := range roster.members {
		body = append(body, member...)
	}
	copy(roster.authority.roster[:], sha256.NewSha256().Compute(string(body)))
}

func w03D03CompositionSign(t *testing.T, c w03D03CertificateContext, roster w03D03RoleRoster, purpose string, indices []uint64) w03D03RoleProof {
	t.Helper()
	digest, err := w03D03CertificateDigest(c, roster.authority, purpose)
	require.NoError(t, err)
	proof := w03D03RoleProof{indices: append([]uint64(nil), indices...)}
	signer := &singlesig.Ed25519Signer{}
	for _, index := range indices {
		signature, signErr := signer.Sign(roster.private[index], digest)
		require.NoError(t, signErr)
		proof.signatures = append(proof.signatures, signature)
	}
	return proof
}

func w03D03CompositionBundle(t *testing.T, c w03D03CertificateContext, rosters [6]w03D03RoleRoster, proposer, admission byte, roles []byte) w03D03CompositionProof {
	t.Helper()
	indices := []uint64{0, 1, 2}
	proof := w03D03CompositionProof{
		proposal:  w03D03CompositionSign(t, c, rosters[proposer], "W03_D03_PROPOSE", indices),
		admission: w03D03CompositionSign(t, c, rosters[admission], "W03_D03_ADMIT", indices),
	}
	for _, role := range roles {
		proof.execution[role] = w03D03CompositionSign(t, c, rosters[role], "W03_D03_EXECUTE", indices)
	}
	return proof
}

func TestQualDRWAAuthorityD03CompositionMappings(t *testing.T) {
	// Independent expected roles are literal L40 mapping02 rows, not results
	// returned by w03D03CompositionMapping or counted within a threshold set.
	for _, row := range []struct {
		branch, target, impact, proposer, admission byte
		roles                                       []byte
	}{
		{1, 32, 0, 1, 0, []byte{1, 0, 2}}, {1, 32, 1, 1, 0, []byte{1, 0, 2, 3}},
		{1, 4, 0, 1, 0, []byte{1, 0, 3}}, {1, 4, 1, 1, 0, []byte{1, 0, 3, 4}},
		{1, 8, 0, 1, 0, []byte{1, 0, 2}}, {1, 8, 1, 1, 0, []byte{1, 0, 2, 4}},
		{1, 16, 0, 1, 0, []byte{1, 0, 2}}, {1, 16, 1, 1, 0, []byte{1, 0, 2, 3}},
		{2, 1, 0, 1, 2, []byte{1, 2, 3}}, {3, 2, 0, 0, 2, []byte{0, 2, 3}},
		{4, 3, 0, 2, 3, []byte{2, 3, 4}},
	} {
		for _, operation := range []string{"RECOVER_SCOPED_ROLE", "REBIND_WIND_DOWN"} {
			t.Run(fmt.Sprintf("b%d_target%d_impact%d/%s", row.branch, row.target, row.impact, operation), func(t *testing.T) {
				c, _ := w03D03CertificatePublicContext()
				c.branch, c.targets, c.impact, c.operation = row.branch, row.target, row.impact, operation
				rosters := w03D03CompositionRosters(t)
				proof := w03D03CompositionBundle(t, c, rosters, row.proposer, row.admission, row.roles)
				require.NoError(t, w03D03CompositionVerify(c, rosters, proof))
				missing := proof
				missing.proposal = w03D03RoleProof{}
				require.Error(t, w03D03CompositionVerify(c, rosters, missing))
				missing = proof
				missing.admission = w03D03RoleProof{}
				require.Error(t, w03D03CompositionVerify(c, rosters, missing))
				for _, role := range row.roles {
					missing = proof
					missing.execution[role] = w03D03RoleProof{}
					require.Error(t, w03D03CompositionVerify(c, rosters, missing))
				}
				// Each exact purpose is distinct even for an overlapping role.
				missing = proof
				missing.execution[row.admission] = proof.admission
				require.Error(t, w03D03CompositionVerify(c, rosters, missing))
				missing = proof
				missing.admission = proof.proposal
				require.Error(t, w03D03CompositionVerify(c, rosters, missing))
			})
		}
	}
}

func TestQualDRWAAuthorityD03CompositionDenials(t *testing.T) {
	c, _ := w03D03CertificatePublicContext() // M20: PR proposer, SA admission; PR/SA/ATA execution.
	rosters := w03D03CompositionRosters(t)
	proof := w03D03CompositionBundle(t, c, rosters, 1, 2, []byte{1, 2, 3})
	require.NoError(t, w03D03CompositionVerify(c, rosters, proof))
	for _, change := range []func(*w03D03CertificateContext){
		func(c *w03D03CertificateContext) { c.domain[0] ^= 1 }, func(c *w03D03CertificateContext) { c.owner[0] ^= 1 },
		func(c *w03D03CertificateContext) { c.programme += "B" }, func(c *w03D03CertificateContext) { c.token = "TOKEN-000002" },
		func(c *w03D03CertificateContext) { c.operation = "REBIND_WIND_DOWN" }, func(c *w03D03CertificateContext) { c.impact = 1 },
		func(c *w03D03CertificateContext) { c.nonce++ }, func(c *w03D03CertificateContext) { c.action[0] ^= 1 },
		func(c *w03D03CertificateContext) { c.predecessor[0] ^= 1 }, func(c *w03D03CertificateContext) { c.claim[0] ^= 1 },
		func(c *w03D03CertificateContext) { c.successor[0] ^= 1 }, func(c *w03D03CertificateContext) { c.notBefore++ },
		func(c *w03D03CertificateContext) { c.notAfter++ },
	} {
		changed := c
		change(&changed)
		require.Error(t, w03D03CompositionVerify(changed, rosters, proof))
	}
	for _, change := range []func(*w03D03CertificateAuthority){
		func(a *w03D03CertificateAuthority) { a.id[1] ^= 1 }, func(a *w03D03CertificateAuthority) { a.version++ },
		func(a *w03D03CertificateAuthority) { a.roster[0] ^= 1 }, func(a *w03D03CertificateAuthority) { a.role = 5 },
	} {
		changed := rosters
		change(&changed[2].authority)
		require.Error(t, w03D03CompositionVerify(c, changed, proof))
	}
	for _, changed := range []w03D03CertificateContext{
		{operation: c.operation, branch: 0}, {operation: c.operation, branch: 5},
		{operation: "OTHER", branch: 2, targets: 1}, {operation: c.operation, branch: 2, targets: 1, impact: 2},
		{operation: c.operation, branch: 1, targets: 1}, {operation: c.operation, branch: 2, targets: 2},
		{operation: c.operation, branch: 3, targets: 1}, {operation: c.operation, branch: 4, targets: 1},
	} {
		_, err := w03D03CompositionMapping(changed)
		require.ErrorIs(t, err, w03ErrD03Certificate)
	}
	bad := c
	bad.branch = 0
	require.ErrorIs(t, w03D03CompositionVerify(bad, rosters, proof), w03ErrD03Certificate)
	bad = c
	bad.programme = "\u0080"
	require.ErrorIs(t, w03D03CompositionVerify(bad, rosters, proof), w03ErrD03Certificate)
	wrong := proof
	wrong.admission = w03D03CompositionSign(t, c, rosters[0], "W03_D03_ADMIT", []uint64{0, 1, 2})
	require.Error(t, w03D03CompositionVerify(c, rosters, wrong))
	wrong = proof
	wrong.admission = w03D03CompositionSign(t, c, rosters[2], "W03_D03_ADMIT", []uint64{0, 1, 2, 3})
	require.NoError(t, w03D03CompositionVerify(c, rosters, wrong))
	wrong.admission.signatures[3][0] ^= 1
	require.Error(t, w03D03CompositionVerify(c, rosters, wrong))
	wrong = proof
	wrong.admission.indices = []uint64{0, 1, 2, 3} // Three valid signatures remain; no quorum masking.
	require.Error(t, w03D03CompositionVerify(c, rosters, wrong))
	for _, extra := range []w03D03RoleProof{{indices: []uint64{0}}, {signatures: [][]byte{{1}}}} {
		wrong = proof
		wrong.execution[0] = extra // Unmapped PA cannot add an execution certificate.
		require.ErrorIs(t, w03D03CompositionVerify(c, rosters, wrong), w03ErrD03Certificate)
	}
	// Re-sign valid bodies after changing trusted fixture geometry; only the
	// independent-role checks deny these, not a stale digest or invalid signature.
	for _, overlap := range []string{"id", "unused_key"} {
		changed := rosters
		if overlap == "id" {
			changed[3].authority.id = changed[2].authority.id
		} else {
			changed[3].members = append([][]byte(nil), rosters[3].members...)
			changed[3].members[4] = changed[2].members[4]
			w03D03CompositionRosterDigest(&changed[3])
		}
		valid := w03D03CompositionBundle(t, c, changed, 1, 2, []byte{1, 2, 3})
		require.ErrorIs(t, w03D03CompositionVerify(c, changed, valid), w03ErrD03Certificate)
	}
	// Independence applies to required roles in this composition. An unused
	// role is never consumed or counted as a floor factor. Both loop directions
	// are isolated with otherwise valid proofs, rather than a stale signature.
	for _, unused := range []byte{0, 4} {
		changed := rosters
		changed[unused].authority.id = changed[2].authority.id
		changed[unused].members = append([][]byte(nil), rosters[unused].members...)
		changed[unused].members[4] = changed[2].members[4]
		w03D03CompositionRosterDigest(&changed[unused])
		require.NoError(t, w03D03CompositionVerify(c, changed, proof))
	}
}
