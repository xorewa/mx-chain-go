package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const CampaignIdentitySchema = "DRWA_S1_F1T_CAMPAIGN_IDENTITY_V1"

var ErrCampaignIdentity = errors.New("invalid F1-T campaign identity")

// CampaignIdentity is the closed, immutable identity shared by every Phase-II
// participant and evidence record. Runtime-derived fields are values, never
// labels: changing any one of them necessarily changes Digest().
type CampaignIdentity struct {
	Schema                          string   `json:"schema"`
	ProfileCatalogSHA256            string   `json:"profile_catalog_sha256"`
	OrderedProfileDigests           []string `json:"ordered_external_and_selector_profile_digests"`
	FixtureCatalogSHA256            string   `json:"fixture_catalog_sha256"`
	CampaignExecutableSHA256        string   `json:"campaign_executable_sha256"`
	ModuleGraphSHA256               string   `json:"module_graph_sha256"`
	HostKernelCPUStorageFactsSHA256 string   `json:"host_kernel_cpu_storage_facts_sha256"`
	PopulationManifestSHA256        string   `json:"exact_population_manifest_sha256"`
	OwnerAuthorizationSHA256        string   `json:"phase_ii_owner_authorization_sha256"`
}

func (identity CampaignIdentity) Validate() error {
	if identity.Schema != CampaignIdentitySchema || len(identity.OrderedProfileDigests) != 4 {
		return ErrCampaignIdentity
	}
	values := []string{
		identity.ProfileCatalogSHA256,
		identity.FixtureCatalogSHA256,
		identity.CampaignExecutableSHA256,
		identity.ModuleGraphSHA256,
		identity.HostKernelCPUStorageFactsSHA256,
		identity.PopulationManifestSHA256,
		identity.OwnerAuthorizationSHA256,
	}
	values = append(values, identity.OrderedProfileDigests...)
	for _, value := range values {
		if !isHexDigest(value) {
			return ErrCampaignIdentity
		}
	}
	unique := make(map[string]struct{}, len(identity.OrderedProfileDigests))
	for _, value := range identity.OrderedProfileDigests {
		unique[value] = struct{}{}
	}
	if len(unique) != len(identity.OrderedProfileDigests) {
		return fmt.Errorf("%w: external and selector digests must be distinct", ErrCampaignIdentity)
	}
	return nil
}

func (identity CampaignIdentity) Digest() (string, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("%w: marshal: %v", ErrCampaignIdentity, err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func DecodeCampaignIdentity(raw []byte) (CampaignIdentity, error) {
	var identity CampaignIdentity
	if err := decodeExactPayload(raw, &identity); err != nil {
		return CampaignIdentity{}, fmt.Errorf("%w: decode: %v", ErrCampaignIdentity, err)
	}
	if err := identity.Validate(); err != nil {
		return CampaignIdentity{}, err
	}
	return identity, nil
}

func RequireCampaignContext(actual, expected string) error {
	if !isHexDigest(actual) || !isHexDigest(expected) || actual != expected {
		return ErrCampaignIdentity
	}
	return nil
}
