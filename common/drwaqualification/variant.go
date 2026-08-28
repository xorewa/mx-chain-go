package drwaqualification

import (
	"fmt"
	"sync"
)

// Variant identifies one non-production S1 qualification build closure.
type Variant string

const (
	VariantTransport   Variant = "drwa_s1_qual_transport"
	VariantBarrier     Variant = "drwa_s1_qual_barrier"
	VariantReplacement Variant = "drwa_s1_qual_replacement"
	VariantPostAuth    Variant = "drwa_s1_qual_postauth"
	VariantF1T         Variant = "drwa_s1_f1t_measure"
)

var variantRegistry = struct {
	sync.Mutex
	active Variant
}{}

// RegisterVariant is called by tagged files during initialization. More than one linked
// qualification variant is a startup-fatal build error, not a precedence decision.
func RegisterVariant(variant Variant) {
	if !validVariant(variant) {
		panic(fmt.Sprintf("drwa S1 qualification: invalid variant %q", variant))
	}

	variantRegistry.Lock()
	defer variantRegistry.Unlock()
	if variantRegistry.active != "" && variantRegistry.active != variant {
		panic(fmt.Sprintf("drwa S1 qualification: mutually exclusive variants %q and %q linked",
			variantRegistry.active, variant))
	}
	variantRegistry.active = variant
}

// ActiveVariant returns the linked qualification variant, or the empty value for a normal build.
func ActiveVariant() Variant {
	variantRegistry.Lock()
	defer variantRegistry.Unlock()
	return variantRegistry.active
}

// ProductionEligible is intentionally false whenever qualification code is active.
func ProductionEligible() bool {
	return ActiveVariant() == ""
}

func validVariant(variant Variant) bool {
	switch variant {
	case VariantTransport, VariantBarrier, VariantReplacement, VariantPostAuth, VariantF1T:
		return true
	default:
		return false
	}
}
