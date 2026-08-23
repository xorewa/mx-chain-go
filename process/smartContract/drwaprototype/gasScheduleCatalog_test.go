package drwaprototype

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestSealGasScheduleCatalogPrototypeDeterministicFixture(t *testing.T) {
	t.Parallel()

	profiles := prototypeGasScheduleProfiles()
	catalog, err := SealGasScheduleCatalog([]GasScheduleProfile{profiles[1], profiles[0]})
	require.NoError(t, err)

	firstIdentity, err := GasScheduleIdentity(profiles[0].Schedule)
	require.NoError(t, err)
	secondIdentity, err := GasScheduleIdentity(profiles[1].Schedule)
	require.NoError(t, err)
	require.Equal(t, "24085eea60a7f13e6c4bd5ea1546a317c906e948b716a2b18a9b16bd41dcc2d8", hex.EncodeToString(firstIdentity[:]))
	require.Equal(t, "48c14b0855126aa12f486b220df3808de2461fbff306f29ba67d0e56f3475c65", hex.EncodeToString(secondIdentity[:]))
	catalogIdentity, err := catalog.Identity()
	require.NoError(t, err)
	require.Equal(t, "6ab5ca8a1e552cc48a11495de6143740bcda125576bfb82cf4a9a2550e42b073", hex.EncodeToString(catalogIdentity[:]))

	selected, err := catalog.IdentityAtEpoch(0)
	require.NoError(t, err)
	require.Equal(t, firstIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(6)
	require.NoError(t, err)
	require.Equal(t, firstIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(7)
	require.NoError(t, err)
	require.Equal(t, secondIdentity, selected)
	selected, err = catalog.IdentityAtEpoch(^uint32(0))
	require.NoError(t, err)
	require.Equal(t, secondIdentity, selected)
}

func TestGasScheduleCatalogPrototypeCanonicalizesMapOrderAndCopiesState(t *testing.T) {
	t.Parallel()

	profiles := prototypeGasScheduleProfiles()
	reordered := GasScheduleMap{
		"BuiltInCost": {
			"DRWASourceCompletion": 41,
			"DRWARefundGeneration": 31,
		},
		"BaseOperationCost": {
			"DRWASuccessReceipt":  21,
			"DRWADestinationGate": 11,
		},
	}
	identity, err := GasScheduleIdentity(profiles[0].Schedule)
	require.NoError(t, err)
	reorderedIdentity, err := GasScheduleIdentity(reordered)
	require.NoError(t, err)
	require.Equal(t, identity, reorderedIdentity)

	catalog, err := SealGasScheduleCatalog(profiles)
	require.NoError(t, err)
	profiles[0].Schedule["BaseOperationCost"]["DRWADestinationGate"] = 999
	retained, err := catalog.Schedule(identity)
	require.NoError(t, err)
	require.Equal(t, uint64(11), retained["BaseOperationCost"]["DRWADestinationGate"])
	retained["BaseOperationCost"]["DRWADestinationGate"] = 888
	retainedAgain, err := catalog.Schedule(identity)
	require.NoError(t, err)
	require.Equal(t, uint64(11), retainedAgain["BaseOperationCost"]["DRWADestinationGate"])
}

func TestSealGasScheduleCatalogPrototypeRejectsMalformedOrAmbiguousInput(t *testing.T) {
	t.Parallel()

	valid := prototypeGasScheduleProfiles()
	tests := []struct {
		name     string
		profiles []GasScheduleProfile
	}{
		{name: "empty", profiles: nil},
		{name: "first epoch not zero", profiles: []GasScheduleProfile{{StartEpoch: 1, Schedule: valid[0].Schedule}}},
		{name: "duplicate epoch", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: valid[0].Schedule}, {StartEpoch: 0, Schedule: valid[1].Schedule}}},
		{name: "empty schedule", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{}}}},
		{name: "empty section", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"": {"operation": 1}}}}},
		{name: "empty section body", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"section": {}}}}},
		{name: "empty operation", profiles: []GasScheduleProfile{{StartEpoch: 0, Schedule: GasScheduleMap{"section": {"": 1}}}}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			catalog, err := SealGasScheduleCatalog(test.profiles)
			require.Nil(t, catalog)
			require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
		})
	}
}

func TestGasScheduleCatalogPrototypeRejectsUnknownAndNilAccess(t *testing.T) {
	t.Parallel()

	var nilCatalog *GasScheduleCatalog
	_, err := nilCatalog.Identity()
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
	_, err = nilCatalog.IdentityAtEpoch(0)
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)
	_, err = nilCatalog.Schedule([prototypeDigestLength]byte{})
	require.ErrorIs(t, err, ErrInvalidGasScheduleCatalog)

	catalog, err := SealGasScheduleCatalog(prototypeGasScheduleProfiles())
	require.NoError(t, err)
	_, err = catalog.Schedule(sequentialPrototypeDigest(1))
	require.ErrorIs(t, err, ErrGasScheduleNotFound)
}

func prototypeGasScheduleProfiles() []GasScheduleProfile {
	return []GasScheduleProfile{
		{
			StartEpoch: 0,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {
					"DRWADestinationGate": 11,
					"DRWASuccessReceipt":  21,
				},
				"BuiltInCost": {
					"DRWARefundGeneration": 31,
					"DRWASourceCompletion": 41,
				},
			},
		},
		{
			StartEpoch: 7,
			Schedule: GasScheduleMap{
				"BaseOperationCost": {
					"DRWADestinationGate": 12,
					"DRWASuccessReceipt":  22,
				},
				"BuiltInCost": {
					"DRWARefundGeneration": 32,
					"DRWASourceCompletion": 42,
				},
			},
		},
	}
}
