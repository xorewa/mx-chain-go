package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
)

// sealShardLifecycleObservation is a detached local lifecycle readback from
// the owning phase provider, not an ACK, authority or wire format. The provider
// must establish native provenance, exact phase generation and current CEB
// for each member before composing these observations.
type sealShardLifecycleObservation struct {
	shard uint32
	view  lifecycleReadView
}

// sealPhaseAccounting counts execution loci in the three phases of the setup
// segment or the two phases of the terminal sealing segment. It cannot be used
// as an ACK bitmap, canonicality assertion, or authorization to advance.
type sealPhaseAccounting struct {
	before, sealed, advanced uint32
}

// accountSealLifecyclePhases checks same-CEB, complete canonical-roster phase
// accounting. It describes only the setup segment (after local initialization
// of lifecycle) and terminal sealing segment (after WIND_DOWN is applied at
// every locus). Requalification/recovery and initial retirement entry have
// their own containing transitions; retired terminal commit is separately
// owned. In particular, OPEN propagation may lag only at SETUP_SEALED, while
// the terminal seal may lag at WIND_DOWN until its own full ACK set exists.
// The caller supplies admitted current observations; no state is written.
func accountSealLifecyclePhases(meta lifecycleReadView, configured uint32, local []sealShardLifecycleObservation) (sealPhaseAccounting, error) {
	if configured == 0 || uint64(len(local)) != uint64(configured) || meta.cebEpoch == 0 ||
		len(meta.token) == 0 || len(meta.cebHash) == 0 || !validCurrentLifecyclePair(meta.activation, meta.lifecycle) {
		return sealPhaseAccounting{}, errSetupLifecycle
	}
	var phases [3]string
	var first, last int
	switch meta.lifecycle {
	case "SETUP", "SETUP_SEALED", "OPEN":
		phases = [3]string{"SETUP", "SETUP_SEALED", "OPEN"}
		if meta.lifecycle == "SETUP_SEALED" {
			last = 1
		} else if meta.lifecycle == "OPEN" {
			first, last = 1, 2
		}
	case "WIND_DOWN", "WIND_DOWN_SEALED":
		phases = [3]string{"WIND_DOWN", "WIND_DOWN_SEALED"}
		if meta.lifecycle == "WIND_DOWN_SEALED" {
			last = 1
		}
	default:
		return sealPhaseAccounting{}, errSetupLifecycle
	}
	var counts [3]uint32
	for i, observation := range local {
		v := observation.view
		if observation.shard != uint32(i) || v.activation != meta.activation || v.cebEpoch != meta.cebEpoch ||
			!bytes.Equal(v.token, meta.token) || !bytes.Equal(v.cebHash, meta.cebHash) {
			return sealPhaseAccounting{}, errSetupLifecycle
		}
		rank := first
		for rank <= last && v.lifecycle != phases[rank] {
			rank++
		}
		if rank > last {
			return sealPhaseAccounting{}, errSetupLifecycle
		}
		counts[rank]++
	}
	return sealPhaseAccounting{before: counts[0], sealed: counts[1], advanced: counts[2]}, nil
}

// sealZeroEffectObservation is a readback of an already authenticated local
// quiescence or terminal-attestation fact. binding is the exact owning
// phase/fence identity, not the proof itself. The owner must verify the native
// result and its open-effect root and the applicable complete seal ACK set.
type sealZeroEffectObservation struct {
	shard           uint32
	binding         []byte
	openEffectCount uint64
}

// checkSealZeroEffectAccounting requires a separate zero count on every
// configured execution shard and on the metachain, bound to the phase supplied
// by the owner. A global aggregate or execution-only count is not evidence.
// This is for setup opening and post-seal terminal attestation accounting. It
// is NOT a new pre-seal requirement for WIND_DOWN and supplies no proof of
// seal application, canonicality, root integrity or terminal commit.
func checkSealZeroEffectAccounting(binding []byte, configured uint32, meta sealZeroEffectObservation, local []sealZeroEffectObservation) error {
	if len(binding) == 0 || configured == 0 || uint64(len(local)) != uint64(configured) ||
		meta.shard != core.MetachainShardId || !bytes.Equal(meta.binding, binding) || meta.openEffectCount != 0 {
		return errSetupLifecycle
	}
	for i, observation := range local {
		if observation.shard != uint32(i) || !bytes.Equal(observation.binding, binding) || observation.openEffectCount != 0 {
			return errSetupLifecycle
		}
	}
	return nil
}
