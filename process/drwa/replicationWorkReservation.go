package drwa

import "github.com/multiversx/mx-chain-core-go/core"

// replicationShardWork supplies the admitted profile price for one configured
// shard's fan-out, ACK production and metachain ACK processing. There are no
// default prices. The native carrier owner supplies the ordered configured
// shard set and prices from its admitted profile, not from the request.
type replicationShardWork struct {
	fanout, acknowledgement, processing uint64
}

// reserveReplicationWork computes the entire prepaid replication cost before
// the owner may commit the depended-on version. It owns no fee, state, payer,
// retry trigger or funding representation; those remain in the protected
// native carrier. The caller must reserve the returned amount in its original
// journal operation before any authoritative mutation.
func reserveReplicationWork(available, source uint64, configuredShards uint32, work []replicationShardWork) (reserved, remaining uint64, err error) {
	if configuredShards == 0 || uint64(len(work)) != uint64(configuredShards) {
		return 0, 0, errCurrentLocalDependency
	}
	total := source
	for _, shard := range work {
		for _, cost := range [...]uint64{shard.fanout, shard.acknowledgement, shard.processing} {
			total, err = core.SafeAddUint64(total, cost)
			if err != nil {
				return 0, 0, err
			}
		}
	}
	if total == 0 {
		return 0, 0, errCurrentLocalDependency
	}
	remaining, err = core.SafeSubUint64(available, total)
	if err != nil {
		return 0, 0, err
	}
	return total, remaining, nil
}
