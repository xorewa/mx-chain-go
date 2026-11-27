package shared

import "encoding/json"

// ObservationPresentationEnvelope renders an already supplied v1 display report
// under the ordinary API envelope. The envelope's success describes encoding
// only. It does not supply or change the report's availability, sources, or
// outcomes, and it does not register an endpoint.
//
// A caller must handle a returned error; no response is constructed for an
// unsupported schema or invalid presentation.
func ObservationPresentationEnvelope(report ObservationReportV1) (GenericAPIResponse, error) {
	wire, err := EncodeObservationReport(report)
	if err != nil {
		return GenericAPIResponse{}, err
	}

	return GenericAPIResponse{
		Data: json.RawMessage(wire),
		Code: ReturnCodeSuccess,
	}, nil
}
