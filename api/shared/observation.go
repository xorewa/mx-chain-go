package shared

// ObservationVersionV1 identifies the isolated public presentation schema.
const ObservationVersionV1 = "drwa-observation-v1"

// The following types represent public presentation values, not native evidence.
type ObservationHash string
type ObservationTokenID string
type ObservationAddress string
type ObservationUInt64 string
type ObservationUInt string
type ObservationUnixMs string
type ObservationPublicLabel string
type ObservationOpaqueRef string
type ObservationAvailability string
type ObservationKind string
type ObservationState string
type ObservationMembershipKind string
type ObservationRefundClass string
type ObservationUnit string

const (
	ObservationAvailable   ObservationAvailability = "AVAILABLE"
	ObservationUnknown     ObservationAvailability = "UNKNOWN"
	ObservationUnavailable ObservationAvailability = "UNAVAILABLE"
	ObservationStale       ObservationAvailability = "STALE"
	ObservationMalformed   ObservationAvailability = "MALFORMED"
	ObservationConflicting ObservationAvailability = "CONFLICTING"
	ObservationUnsupported ObservationAvailability = "UNSUPPORTED"
)

// ObservationReportV1 is additive. No field has omitempty: null and an empty
// list have different presentation meanings. It is not an authority object.
type ObservationReportV1 struct {
	SchemaVersion string                    `json:"schemaVersion"`
	Availability  ObservationAvailability   `json:"availability"`
	Subject       *PublicObservationSubject `json:"subject"`
	Observations  []PublicObservation       `json:"observations"`
	ReportedAtMs  *ObservationUnixMs        `json:"reportedAtMs"`
}

type PublicObservationSubject struct {
	RecordRef               *ObservationOpaqueRef   `json:"recordRef"`
	EffectRef               *ObservationOpaqueRef   `json:"effectRef"`
	ContextRef              *ObservationOpaqueRef   `json:"contextRef"`
	TransactionHash         *ObservationHash        `json:"transactionHash"`
	OriginalTransactionHash *ObservationHash        `json:"originalTransactionHash"`
	OriginalBatchID         *ObservationPublicLabel `json:"originalBatchId"`
	OriginalBatchRef        *ObservationOpaqueRef   `json:"originalBatchRef"`
	TokenID                 *ObservationTokenID     `json:"tokenId"`
	TokenNonce              *ObservationUInt64      `json:"tokenNonce"`
	HolderAddress           *ObservationAddress     `json:"holderAddress"`
	BeneficiaryAddress      *ObservationAddress     `json:"beneficiaryAddress"`
	PolicyVersionRef        *ObservationPublicLabel `json:"policyVersionRef"`
	PolicyEpoch             *uint32                 `json:"policyEpoch"`
}

type PublicObservation struct {
	ObservationRef *ObservationOpaqueRef           `json:"observationRef"`
	Kind           ObservationKind                 `json:"kind"`
	Availability   ObservationAvailability         `json:"availability"`
	State          ObservationState                `json:"state"`
	Subject        *PublicObservationSubject       `json:"subject"`
	Provenance     *PublicObservationProvenance    `json:"provenance"`
	FinalityBasis  *PublicObservationFinalityBasis `json:"finalityBasis"`
	Values         []PublicObservationValue        `json:"values"`
	OriginalValues []PublicObservationValue        `json:"originalValues"`
	GasRefund      *PublicObservationGasRefund     `json:"gasRefund"`
}

type PublicObservationProvenance struct {
	ProducerID          *ObservationPublicLabel `json:"producerId"`
	ProducerVersion     *ObservationPublicLabel `json:"producerVersion"`
	ProducerCommitID    *ObservationPublicLabel `json:"producerCommitId"`
	BasisRef            *ObservationOpaqueRef   `json:"basisRef"`
	ExecutionObjectHash *ObservationHash        `json:"executionObjectHash"`
	ExecutionShard      *uint32                 `json:"executionShard"`
	AsOfBlockHash       *ObservationHash        `json:"asOfBlockHash"`
	AsOfBlockNonce      *ObservationUInt64      `json:"asOfBlockNonce"`
	AsOfBlockRound      *ObservationUInt64      `json:"asOfBlockRound"`
	AsOfShard           *uint32                 `json:"asOfShard"`
	ObservedAtMs        *ObservationUnixMs      `json:"observedAtMs"`
}

type PublicObservationFinalityBasis struct {
	MembershipKind       ObservationMembershipKind `json:"membershipKind"`
	BlockHash            *ObservationHash          `json:"blockHash"`
	BlockNonce           *ObservationUInt64        `json:"blockNonce"`
	BlockRound           *ObservationUInt64        `json:"blockRound"`
	BlockEpoch           *uint32                   `json:"blockEpoch"`
	BlockShard           *uint32                   `json:"blockShard"`
	MiniblockHash        *ObservationHash          `json:"miniblockHash"`
	TransactionHash      *ObservationHash          `json:"transactionHash"`
	SubjectResultHash    *ObservationHash          `json:"subjectResultHash"`
	ExecutionHeaderHash  *ObservationHash          `json:"executionHeaderHash"`
	ExecutionHeaderNonce *ObservationUInt64        `json:"executionHeaderNonce"`
	ExecutionHeaderRound *ObservationUInt64        `json:"executionHeaderRound"`
	ExecutionHeaderEpoch *uint32                   `json:"executionHeaderEpoch"`
	FinalityAtBlockHash  *ObservationHash          `json:"finalityAtBlockHash"`
}

type PublicObservationValue struct {
	TokenID        ObservationTokenID `json:"tokenId"`
	TokenNonce     *ObservationUInt64 `json:"tokenNonce"`
	QuantityAtomic ObservationUInt    `json:"quantityAtomic"`
	Unit           ObservationUnit    `json:"unit"`
}

type PublicObservationGasRefund struct {
	TokenID           *ObservationTokenID    `json:"tokenId"`
	AmountAtomic      *ObservationUInt       `json:"amountAtomic"`
	AmountUnit        *ObservationUnit       `json:"amountUnit"`
	GasUnits          *ObservationUInt       `json:"gasUnits"`
	GasUnit           *ObservationUnit       `json:"gasUnit"`
	PresentationClass ObservationRefundClass `json:"presentationClass"`
}
