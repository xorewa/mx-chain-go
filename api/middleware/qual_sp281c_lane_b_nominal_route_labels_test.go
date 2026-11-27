package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Only the public read-only route labels are classified. The local Gin
// callbacks do not invoke any product HTTP handler or middleware.
func TestQualSP281CNominalReadOnlyRouteClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		listing bool
	}{
		{name: "token listing", path: "/network/esdts", listing: true},
		{name: "configuration display", path: "/network/config", listing: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			observed := false
			r.GET(tc.path, func(c *gin.Context) {
				observed = true
				require.Equal(t, tc.path, c.FullPath())
				require.Equal(t, tc.listing, isTrieListing(c))
				c.Status(http.StatusNoContent)
			})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			require.True(t, observed)
			require.Equal(t, http.StatusNoContent, w.Code)
		})
	}
}
