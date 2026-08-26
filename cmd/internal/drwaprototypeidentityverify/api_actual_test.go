package drwaprototypeidentityverify

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test is opt-in because it binds a closed, externally prepared 16-node archive.
// It is read-only: VerifyPlanBoundary has no evidence-output or database-write branch.
func TestActualClosedArchiveAllSixteenMutationBoundaryPlans(t *testing.T) {
	planPath := os.Getenv("DRWA_S1_ACTUAL_PLAN_PATH")
	expectedPlanSHA := os.Getenv("DRWA_S1_ACTUAL_PLAN_SHA256")
	if planPath == "" || expectedPlanSHA == "" {
		t.Skip("closed-archive plan identity not supplied")
	}

	planBytes, err := os.ReadFile(planPath)
	require.NoError(t, err)
	var plan migrationPlanDocument
	require.NoError(t, strictDecodeJSON(planBytes, &plan))
	require.Len(t, plan.Nodes, 16)

	for _, node := range plan.Nodes {
		node := node
		t.Run(node.ID, func(t *testing.T) {
			evidence, verifyErr := VerifyPlanBoundary(planRequestFromDocument(planPath, expectedPlanSHA, plan, node))
			require.NoError(t, verifyErr)
			require.Equal(t, node.ID, selectedNodeID(plan, evidence))
			require.True(t, evidence.TargetAbsentBefore)
			require.Zero(t, evidence.AuthoritativeRunCredit)
		})
	}

	// A changed binding identity must fail before any target can be opened for creation.
	request := planRequestFromDocument(planPath, expectedPlanSHA, plan, plan.Nodes[0])
	request.ExpectedBindingSHA = "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = VerifyPlanBoundary(request)
	require.Error(t, err)
	for _, node := range plan.Nodes {
		require.NoDirExists(t, node.TargetDBPath)
	}
}

func planRequestFromDocument(
	planPath string,
	expectedPlanSHA string,
	plan migrationPlanDocument,
	node migrationPlanNode,
) PlanRequest {
	return PlanRequest{
		ChainID: plan.ChainID, Epoch: plan.CanonicalEpoch,
		ExpectedCanonicalHash: plan.CanonicalHash, ExpectedDomain: plan.NetworkDomain,
		BindingPath: plan.BindingPath, ExpectedBindingSHA: plan.BindingSHA256,
		HeaderPath: plan.HeaderPath, TargetDBPath: node.TargetDBPath,
		NodeRoot: node.NodeRoot, ShardID: node.ShardID,
		MigrationPlanPath: planPath, ExpectedMigrationPlanSHA: expectedPlanSHA,
		ExtractionEvidencePath:        plan.ExtractionEvidencePath,
		ExpectedExtractionEvidenceSHA: plan.ExtractionEvidenceSHA256,
		RehearsalRoot:                 plan.RehearsalRoot,
	}
}

func selectedNodeID(plan migrationPlanDocument, evidence PlanEvidence) string {
	for _, node := range plan.Nodes {
		if node.NodeRoot == evidence.NodeRoot && node.TargetDBPath == evidence.TargetDBPath && node.ShardID == evidence.ShardID {
			return node.ID
		}
	}
	return ""
}
