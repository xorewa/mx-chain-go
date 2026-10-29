package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

func FuzzSP1CoverageRegistrationBody(f *testing.F) {
	body, encoded, _, _ := qualRecordBody()
	f.Add(encoded)
	f.Add([]byte(nil))
	f.Add([]byte{0x0a, 0xff})
	f.Add([]byte{0x0a, 0x01, 0x00})
	seed := func(issuer, family []byte) []byte {
		return qualRecordFrame(body.networkDomain, issuer, body.programID, body.intentNonce, family, body.creationProfile, body.nameCommitment, body.tickerCommitment, body.propertyCommitment, body.publicSchemaProfile, body.issuerProgramAdmissionDecision, qualRecordFrame(body.proposedProgramAuthoritySetBodies...), qualRecordFrame(body.proposedProgramAuthoritySetHashes...), body.closurePlan, body.networkProfile, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	}
	f.Add(seed([]byte{1}, body.requestedTokenFamily))
	f.Add(seed(body.issuer, []byte(core.NonFungibleESDT)))
	codec := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096}
	allowed := map[string]bool{core.FungibleESDT: true, core.NonFungibleESDTv2: true, core.SemiFungibleESDT: true, core.MetaESDT: true, core.DynamicNFTESDT: true, core.DynamicSFTESDT: true, core.DynamicMetaESDT: true}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := codec.decodeBody(input)
		if len(input) == 0 || len(input) > codec.maxBytes {
			require.Error(t, err)
			return
		}
		if err != nil {
			return
		}
		require.Len(t, got.issuer, len(core.SystemAccountAddress))
		for _, field := range [][]byte{got.networkDomain, got.programID, got.intentNonce, got.requestedTokenFamily, got.creationProfile, got.nameCommitment, got.tickerCommitment, got.propertyCommitment, got.publicSchemaProfile, got.issuerProgramAdmissionDecision, got.networkProfile} {
			require.NotEmpty(t, field)
		}
		require.True(t, allowed[string(got.requestedTokenFamily)], "decoder accepted an unsupported new issuance family")
		require.Contains(t, []string{"burn-and-retire", "preserve-and-close"}, string(got.closurePlan))
		require.NotEmpty(t, got.proposedProgramAuthoritySetBodies)
		require.Equal(t, len(got.proposedProgramAuthoritySetBodies), len(got.proposedProgramAuthoritySetHashes))
		for _, authority := range got.proposedProgramAuthoritySetBodies {
			require.NotEmpty(t, authority)
		}
		for _, hash := range got.proposedProgramAuthoritySetHashes {
			require.Len(t, hash, codec.hasher.Size())
		}
	})
}
