package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestQualSP218OrdinarySuccessPresentation(t *testing.T) {
	type displayItem struct {
		Label string `json:"label"`
		Count int    `json:"count"`
	}
	for _, tc := range []struct {
		name string
		data []displayItem
		want string
	}{
		{
			name: "supplied labels and counts",
			data: []displayItem{{Label: "sample", Count: 0}, {Label: "second", Count: 3}},
			want: `{"data":[{"label":"sample","count":0},{"label":"second","count":3}],"error":"","code":"successful"}`,
		},
		{
			name: "empty display list",
			data: []displayItem{},
			want: `{"data":[],"error":"","code":"successful"}`,
		},
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
