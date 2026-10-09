package core

import (
	"fmt"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
)

// CheckDRWAExclusionHistory checks only E11's predecessor-record retention.
// Both snapshots must be actual loaded immutable inputs whose approved identity
// and applicability the deployment admission owner establishes separately. Nil
// never means approved empty history. This unwired check grants no deployment,
// recovery mode, checkpoint, changed history or new-interval approval.
func CheckDRWAExclusionHistory(predecessor, proposed *config.Config) error {
	if predecessor == nil || proposed == nil {
		return fmt.Errorf("DRWA exclusion history requires predecessor and proposed configuration")
	}
	if _, err := common.NewConfiguredRoundExclusionHandler(predecessor); err != nil {
		return fmt.Errorf("DRWA predecessor configuration: %w", err)
	}
	if _, err := common.NewConfiguredRoundExclusionHandler(proposed); err != nil {
		return fmt.Errorf("DRWA proposed configuration: %w", err)
	}
	retained := make(map[config.HardforkRoundExclusionConfig]struct{}, len(proposed.HardforkRoundExclusions))
	for _, interval := range proposed.HardforkRoundExclusions {
		retained[interval] = struct{}{}
	}
	for _, interval := range predecessor.HardforkRoundExclusions {
		if _, exists := retained[interval]; !exists {
			return fmt.Errorf("DRWA missing predecessor exclusion [%d,%d]", interval.StartRound, interval.EndRound)
		}
	}
	return nil
}
