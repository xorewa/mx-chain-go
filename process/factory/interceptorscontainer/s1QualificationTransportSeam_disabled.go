//go:build !drwa_s1_qual_transport

package interceptorscontainer

import (
	"github.com/multiversx/mx-chain-go/process"
)

func s1QualificationTransportSeam(_ string, interceptor process.Interceptor) (process.Interceptor, error) {
	return interceptor, nil
}
