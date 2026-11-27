package systemSmartContracts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryESDTReportCounts(t *testing.T) {
	t.Parallel()

	// Inert informational numbers only; no token operation or state access.
	require.Equal(t, uint32(7), (&ESDTDataV1{NumWiped: 7}).GetNumWiped())
	require.Equal(t, uint32(23), (&ESDTDataV2{NumWiped: 23}).GetNumWiped())

	var absentV1 *ESDTDataV1
	var absentV2 *ESDTDataV2
	require.Zero(t, absentV1.GetNumWiped())
	require.Zero(t, absentV2.GetNumWiped())
}
