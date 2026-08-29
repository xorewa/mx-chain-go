package f1t

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/sharding"
)

func TestCanonicalSourceConstructorUsesRealThreeShardAssignments(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	coordinator, err := sharding.NewMultiShardCoordinator(3, constructor.ReceiverShard)
	require.NoError(t, err)
	require.Equal(t, uint32(1), constructor.SenderShard)
	require.Equal(t, uint32(2), constructor.ReceiverShard)
	require.Equal(t, constructor.SenderShard, coordinator.ComputeId(constructor.SourceHolder[:]))
	require.Equal(t, constructor.ReceiverShard, coordinator.ComputeId(constructor.Destination[:]))
}

func TestCanonicalSourceConstructorProducesDifferentProfileFixtures(t *testing.T) {
	constructor := DefaultCanonicalSourceConstructor()
	legacy, _, err := BuildCalibrationFixture(constructor, ProfileLegacy, "SELECTED", 1, "fixture", "/drwa/f1t", "peer-remote", true)
	require.NoError(t, err)
	v2, _, err := BuildCalibrationFixture(constructor, ProfileV2, "SELECTED", 1, "fixture", "/drwa/f1t", "peer-remote", true)
	require.NoError(t, err)
	require.NotEqual(t, legacy, v2)
}

func TestApprovedPhaseIIControlCatalogsPassRealLoaderPreflight(t *testing.T) {
	const root = "/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA"
	profiles, err := LoadAndVerifyProfileCatalog(root,
		root+"/NewArc/drwa-qualification/manifests/S1_F1T_PHASE_II_PROFILE_CATALOG.json",
		"f6fdfd2429f1e2fabfe17ae443473b21827364866536e0164223a262ee45d36a")
	require.NoError(t, err)
	require.Len(t, profiles, 2)
	_, err = LoadAndVerifyFixtureCatalog(root,
		root+"/NewArc/drwa-qualification/manifests/S1_F1T_PHASE_II_FIXTURE_CATALOG.json",
		"366db502da59b9d36541052b4a9954897da977b87373ab5d197ce58d873c3bbd",
		"92ae62315d5c7e5a939888bc3049f80fef77a9bc")
	require.NoError(t, err)
}
