package f1t

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func validCampaignIdentity() CampaignIdentity {
	return CampaignIdentity{
		Schema:                CampaignIdentitySchema,
		ProfileCatalogSHA256:  strings.Repeat("11", 32),
		OrderedProfileDigests: []string{strings.Repeat("21", 32), strings.Repeat("22", 32), strings.Repeat("31", 32), strings.Repeat("32", 32)},
		FixtureCatalogSHA256:  strings.Repeat("41", 32), CampaignExecutableSHA256: strings.Repeat("42", 32),
		ModuleGraphSHA256: strings.Repeat("43", 32), HostKernelCPUStorageFactsSHA256: strings.Repeat("44", 32),
		PopulationManifestSHA256: strings.Repeat("45", 32), OwnerAuthorizationSHA256: strings.Repeat("46", 32),
	}
}

func TestCampaignIdentityDigestBindsEveryField(t *testing.T) {
	identity := validCampaignIdentity()
	digest, err := identity.Digest()
	require.NoError(t, err)
	require.Len(t, digest, 64)

	mutations := []func(*CampaignIdentity){
		func(v *CampaignIdentity) { v.ProfileCatalogSHA256 = strings.Repeat("51", 32) },
		func(v *CampaignIdentity) { v.OrderedProfileDigests[0] = strings.Repeat("52", 32) },
		func(v *CampaignIdentity) { v.FixtureCatalogSHA256 = strings.Repeat("53", 32) },
		func(v *CampaignIdentity) { v.CampaignExecutableSHA256 = strings.Repeat("54", 32) },
		func(v *CampaignIdentity) { v.ModuleGraphSHA256 = strings.Repeat("55", 32) },
		func(v *CampaignIdentity) { v.HostKernelCPUStorageFactsSHA256 = strings.Repeat("56", 32) },
		func(v *CampaignIdentity) { v.PopulationManifestSHA256 = strings.Repeat("57", 32) },
		func(v *CampaignIdentity) { v.OwnerAuthorizationSHA256 = strings.Repeat("58", 32) },
	}
	for _, mutate := range mutations {
		candidate := identity
		candidate.OrderedProfileDigests = append([]string(nil), identity.OrderedProfileDigests...)
		mutate(&candidate)
		other, digestErr := candidate.Digest()
		require.NoError(t, digestErr)
		require.NotEqual(t, digest, other)
	}
}

func TestCampaignIdentityRejectsUnknownAndDuplicateDigestClasses(t *testing.T) {
	identity := validCampaignIdentity()
	raw, err := json.Marshal(identity)
	require.NoError(t, err)
	raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	_, err = DecodeCampaignIdentity(raw)
	require.Error(t, err)

	identity = validCampaignIdentity()
	identity.OrderedProfileDigests[1] = identity.OrderedProfileDigests[0]
	require.ErrorIs(t, identity.Validate(), ErrCampaignIdentity)
	identity = validCampaignIdentity()
	identity.OrderedProfileDigests[2] = identity.OrderedProfileDigests[0]
	require.ErrorIs(t, identity.Validate(), ErrCampaignIdentity)
	require.ErrorIs(t, RequireCampaignContext(strings.Repeat("61", 32), strings.Repeat("62", 32)), ErrCampaignIdentity)
}
