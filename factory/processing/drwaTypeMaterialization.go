package processing

import (
	"github.com/multiversx/mx-chain-go/process/drwa"
)

// newDRWATypeMaterialization creates, for the metachain node of a DRWA
// deployment, the owner of the protected type materialization exception over
// the node's own admin-effect owner and enable-epochs handler. Its caller is
// the protected metachain operation of the registration ingress (SP2-38).
func (pcf *processComponentsFactory) newDRWATypeMaterialization(owner *drwaMetaFinalityImport) (*drwa.TypeMaterialization, error) {
	if owner == nil {
		return nil, drwa.ErrInvalidTypeMaterialization
	}

	return drwa.NewTypeMaterialization(owner.DRWAAdminEffects(), pcf.coreData.EnableEpochsHandler())
}
