package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Preserve the ordinary success envelope's distinction between an absent
// payload and a known-empty object. No endpoint or new schema is involved.
func TestQualSP280OrdinaryResponsePayloadPresence(t *testing.T) {
	var nilReport map[string]string
	for _, tc := range []struct {
		name string
		data interface{}
		want string
	}{
		{"absent payload", nil, `{"data":null,"error":"","code":"successful"}`},
		{"typed absent object", nilReport, `{"data":null,"error":"","code":"successful"}`},
		{"known empty object", map[string]string{}, `{"data":{},"error":"","code":"successful"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			RespondWithSuccess(context, tc.data)
			require.Equal(t, http.StatusOK, recorder.Code)
			require.JSONEq(t, tc.want, recorder.Body.String())
		})
	}
}
