package drwa

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// UNREVIEWED: compile-only qualification of a prerequisite predicate. All facts
// below are authenticated synthetic observations supplied by the test owner.
// No signature, appointment, native writer, T06 proof, canonical selection,
// finality, lifecycle, PA/coapproval or resource admission is implemented.
// These structs and labels are not a production codec or allocated protocol API.
var w03ErrAdmissionOrdering = errors.New("denied synthetic W03 admission ordering")

type w03AdmissionScope struct {
	domain, creatingOwner [32]byte
	programme             string
}
type w03AdmissionReference struct {
	id, hash [32]byte
	version  uint64
}
type w03AdmissionStatement struct {
	scope                      w03AdmissionScope
	issuer, intent, commitment [32]byte
	decisionVersion            uint64
	authority                  w03AdmissionReference
	notBefore, validUntil      uint64
}
type w03AdmissionDecisionObservation struct {
	root   [32]byte
	status string
	body   w03AdmissionStatement
}
type w03AdmissionLineageObservation struct {
	root    [32]byte
	scope   w03AdmissionScope
	current w03AdmissionReference
}
type w03AdmissionActivationBinding struct {
	scope                                         w03AdmissionScope
	issuer, token, intent, commitment, genesisCEB [32]byte
	authority                                     w03AdmissionReference
}
type w03AdmissionActivationObservation struct {
	root                  [32]byte
	purpose               string
	binding               w03AdmissionActivationBinding
	notBefore, validUntil uint64
}
type w03AdmissionContext struct {
	root                              [32]byte
	time                              uint64
	scope                             w03AdmissionScope
	issuer, intent, token, genesisCEB [32]byte
}

func w03AdmissionWindow(now, notBefore, validUntil uint64) bool {
	// Inclusive bounds establish order before subtraction; no addition can overflow. The
	// constant10 is the explicitly proposed toy class bound, not a default.
	return notBefore <= now && now <= validUntil && validUntil-notBefore <= 10
}

func w03AdmissionConsume(instant string, c w03AdmissionContext, statement w03AdmissionStatement,
	decision *w03AdmissionDecisionObservation, lineage *w03AdmissionLineageObservation,
	activation *w03AdmissionActivationObservation) error {
	switch instant {
	case "INTENT", "REGISTRATION", "ACTIVATION":
	default:
		return w03ErrAdmissionOrdering
	}
	if decision == nil || lineage == nil {
		return w03ErrAdmissionOrdering
	}
	if decision.root != c.root || lineage.root != c.root {
		return w03ErrAdmissionOrdering
	}
	if decision.status != "AFFIRMATIVE" {
		return w03ErrAdmissionOrdering
	}
	if decision.body != statement {
		return w03ErrAdmissionOrdering
	}
	if statement.scope != c.scope || lineage.scope != c.scope || statement.issuer != c.issuer || statement.intent != c.intent {
		return w03ErrAdmissionOrdering
	}
	if statement.authority != lineage.current {
		return w03ErrAdmissionOrdering
	}
	if !w03AdmissionWindow(c.time, statement.notBefore, statement.validUntil) {
		return w03ErrAdmissionOrdering
	}
	if instant == "ACTIVATION" {
		if activation == nil {
			return w03ErrAdmissionOrdering
		}
		expected := w03AdmissionActivationBinding{scope: c.scope, issuer: c.issuer, token: c.token,
			intent: c.intent, commitment: statement.commitment, genesisCEB: c.genesisCEB, authority: lineage.current}
		if activation.root != c.root || activation.purpose != "ACTIVATE_PROGRAM_ADMISSION" || activation.binding != expected {
			return w03ErrAdmissionOrdering
		}
		if !w03AdmissionWindow(c.time, activation.notBefore, activation.validUntil) {
			return w03ErrAdmissionOrdering
		}
	}
	return nil
}

func w03AdmissionOrderingFixture() (w03AdmissionContext, w03AdmissionStatement,
	w03AdmissionDecisionObservation, w03AdmissionLineageObservation, w03AdmissionActivationObservation) {
	scope := w03AdmissionScope{domain: [32]byte{1}, creatingOwner: [32]byte{2}, programme: "PROGRAM-A"}
	authority := w03AdmissionReference{id: [32]byte{3}, hash: [32]byte{4}, version: 1}
	c := w03AdmissionContext{root: [32]byte{5}, time: 10, scope: scope,
		issuer: [32]byte{6}, intent: [32]byte{7}, token: [32]byte{8}, genesisCEB: [32]byte{9}}
	s := w03AdmissionStatement{scope: scope, issuer: c.issuer, intent: c.intent, commitment: [32]byte{10},
		decisionVersion: 1, authority: authority, notBefore: 5, validUntil: 15}
	d := w03AdmissionDecisionObservation{root: c.root, status: "AFFIRMATIVE", body: s}
	l := w03AdmissionLineageObservation{root: c.root, scope: scope, current: authority}
	a := w03AdmissionActivationObservation{root: c.root, purpose: "ACTIVATE_PROGRAM_ADMISSION",
		binding: w03AdmissionActivationBinding{scope: scope, issuer: c.issuer, token: c.token,
			intent: c.intent, commitment: s.commitment, genesisCEB: c.genesisCEB, authority: authority}, notBefore: 5, validUntil: 15}
	return c, s, d, l, a
}

func TestQualDRWAAuthorityAdmissionOrdering(t *testing.T) {
	for _, instant := range []string{"INTENT", "REGISTRATION", "ACTIVATION"} {
		t.Run(instant, func(t *testing.T) {
			c, s, d, l, a := w03AdmissionOrderingFixture()
			require.NoError(t, w03AdmissionConsume(instant, c, s, &d, &l, &a))
			// Merely observing an off-chain withdrawal request changes none of the
			// selected authoritative facts. No writer or consensus effect is claimed.
			require.NoError(t, w03AdmissionConsume(instant, c, s, &d, &l, &a))
			before := d
			c.root[0]++
			d.root, l.root, a.root = c.root, c.root, c.root
			d.status = "WITHDRAWN"
			require.ErrorIs(t, w03AdmissionConsume(instant, c, s, &d, &l, &a), w03ErrAdmissionOrdering)
			// Outstanding valid statement and a fresh activation proof do not revive it.
			require.ErrorIs(t, w03AdmissionConsume(instant, c, s, &before, &l, &a), w03ErrAdmissionOrdering)
			d.status = "AFFIRMATIVE"
			l.current.version++
			l.current.hash[0]++
			require.ErrorIs(t, w03AdmissionConsume(instant, c, s, &d, &l, &a), w03ErrAdmissionOrdering)
			require.Equal(t, uint64(1), s.authority.version) // Immutable intent is not rewritten.
		})
	}
}

func TestQualDRWAAuthorityAdmissionFacts(t *testing.T) {
	c, s, d, l, a := w03AdmissionOrderingFixture()
	require.ErrorIs(t, w03AdmissionConsume("ORDINARY_TRANSFER", c, s, &d, &l, &a), w03ErrAdmissionOrdering)
	require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, nil, &l, nil), w03ErrAdmissionOrdering)
	require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &d, nil, nil), w03ErrAdmissionOrdering)
	for _, status := range []string{"", "WITHDRAWN", "UNKNOWN"} {
		changed := d
		changed.status = status
		require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &changed, &l, nil), w03ErrAdmissionOrdering)
	}
	changedDecision := d
	changedDecision.root[0]++
	require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &changedDecision, &l, nil), w03ErrAdmissionOrdering)
	changedLineage := l
	changedLineage.root[0]++
	require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &d, &changedLineage, nil), w03ErrAdmissionOrdering)
	// Both authoritative record and certificate share each changed body. Their
	// equality cannot mask the selected scope/issuer/intent checks.
	for _, change := range []func(*w03AdmissionStatement){
		func(s *w03AdmissionStatement) { s.scope.domain[0]++ },
		func(s *w03AdmissionStatement) { s.scope.creatingOwner[0]++ },
		func(s *w03AdmissionStatement) { s.scope.programme += "B" },
		func(s *w03AdmissionStatement) { s.issuer[0]++ },
		func(s *w03AdmissionStatement) { s.intent[0]++ },
	} {
		wrong := s
		change(&wrong)
		observed := d
		observed.body = wrong
		require.ErrorIs(t, w03AdmissionConsume("INTENT", c, wrong, &observed, &l, nil), w03ErrAdmissionOrdering)
	}
	changedLineage = l
	changedLineage.scope.programme += "B"
	require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &d, &changedLineage, nil), w03ErrAdmissionOrdering)
	// Every immutable statement field is covered independently against retained
	// body equality, with the certificate and all other trusted facts unchanged.
	for _, change := range []func(*w03AdmissionStatement){
		func(s *w03AdmissionStatement) { s.scope.domain[0]++ }, func(s *w03AdmissionStatement) { s.scope.creatingOwner[0]++ },
		func(s *w03AdmissionStatement) { s.scope.programme += "B" }, func(s *w03AdmissionStatement) { s.issuer[0]++ },
		func(s *w03AdmissionStatement) { s.intent[0]++ }, func(s *w03AdmissionStatement) { s.commitment[0]++ },
		func(s *w03AdmissionStatement) { s.decisionVersion++ }, func(s *w03AdmissionStatement) { s.authority.id[0]++ },
		func(s *w03AdmissionStatement) { s.authority.hash[0]++ }, func(s *w03AdmissionStatement) { s.authority.version++ },
		func(s *w03AdmissionStatement) { s.notBefore++ }, func(s *w03AdmissionStatement) { s.validUntil++ },
	} {
		observed := d
		change(&observed.body)
		require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &observed, &l, nil), w03ErrAdmissionOrdering)
	}
	for _, change := range []func(*w03AdmissionReference){
		func(r *w03AdmissionReference) { r.id[0]++ }, func(r *w03AdmissionReference) { r.hash[0]++ }, func(r *w03AdmissionReference) { r.version++ },
	} {
		observed := l
		change(&observed.current)
		require.ErrorIs(t, w03AdmissionConsume("INTENT", c, s, &d, &observed, nil), w03ErrAdmissionOrdering)
	}
}

func TestQualDRWAAuthorityAdmissionActivation(t *testing.T) {
	c, s, d, l, a := w03AdmissionOrderingFixture()
	require.ErrorIs(t, w03AdmissionConsume("ACTIVATION", c, s, &d, &l, nil), w03ErrAdmissionOrdering)
	// Fresh attestation is an additional predicate. An unrelated extra attestation
	// is not required at the earlier two instants in this fixture.
	require.NoError(t, w03AdmissionConsume("INTENT", c, s, &d, &l, nil))
	require.NoError(t, w03AdmissionConsume("REGISTRATION", c, s, &d, &l, nil))
	for _, change := range []func(*w03AdmissionActivationObservation){
		func(a *w03AdmissionActivationObservation) { a.root[0]++ }, func(a *w03AdmissionActivationObservation) { a.purpose = "UNKNOWN_PURPOSE" },
		func(a *w03AdmissionActivationObservation) { a.binding.scope.domain[0]++ }, func(a *w03AdmissionActivationObservation) { a.binding.scope.creatingOwner[0]++ },
		func(a *w03AdmissionActivationObservation) { a.binding.scope.programme += "B" }, func(a *w03AdmissionActivationObservation) { a.binding.issuer[0]++ },
		func(a *w03AdmissionActivationObservation) { a.binding.token[0]++ }, func(a *w03AdmissionActivationObservation) { a.binding.intent[0]++ },
		func(a *w03AdmissionActivationObservation) { a.binding.commitment[0]++ }, func(a *w03AdmissionActivationObservation) { a.binding.genesisCEB[0]++ },
		func(a *w03AdmissionActivationObservation) { a.binding.authority.id[0]++ }, func(a *w03AdmissionActivationObservation) { a.binding.authority.hash[0]++ },
		func(a *w03AdmissionActivationObservation) { a.binding.authority.version++ },
	} {
		wrong := a
		change(&wrong)
		require.ErrorIs(t, w03AdmissionConsume("ACTIVATION", c, s, &d, &l, &wrong), w03ErrAdmissionOrdering)
	}
	for _, window := range [][2]uint64{{11, 15}, {5, 9}, {15, 5}, {5, 16}} {
		wrong := a
		wrong.notBefore, wrong.validUntil = window[0], window[1]
		require.ErrorIs(t, w03AdmissionConsume("ACTIVATION", c, s, &d, &l, &wrong), w03ErrAdmissionOrdering)
	}
	// A still-valid fresh attestation cannot replace expired immutable admission.
	c.time = 16
	a.notBefore, a.validUntil = 10, 20
	require.ErrorIs(t, w03AdmissionConsume("ACTIVATION", c, s, &d, &l, &a), w03ErrAdmissionOrdering)
}

func TestQualDRWAAuthorityAdmissionWindows(t *testing.T) {
	for _, row := range []struct {
		now, start, end uint64
		accept          bool
	}{
		{5, 5, 15, true}, {15, 5, 15, true}, {10, 5, 15, true}, {10, 10, 10, true},
		{4, 5, 15, false}, {16, 5, 15, false}, {10, 15, 5, false}, {10, 5, 16, false},
		{math.MaxUint64, math.MaxUint64 - 10, math.MaxUint64, true},
		{math.MaxUint64 - 10, math.MaxUint64 - 10, math.MaxUint64, true},
		{math.MaxUint64, math.MaxUint64 - 11, math.MaxUint64, false},
		{math.MaxUint64, math.MaxUint64, 0, false},
	} {
		require.Equal(t, row.accept, w03AdmissionWindow(row.now, row.start, row.end))
		c, s, d, l, a := w03AdmissionOrderingFixture()
		c.time = row.now
		s.notBefore, s.validUntil = row.start, row.end
		d.body = s
		if row.accept {
			require.NoError(t, w03AdmissionConsume("REGISTRATION", c, s, &d, &l, &a))
		} else {
			require.ErrorIs(t, w03AdmissionConsume("REGISTRATION", c, s, &d, &l, &a), w03ErrAdmissionOrdering)
		}
	}
}
