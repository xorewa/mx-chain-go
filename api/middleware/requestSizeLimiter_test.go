package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRequestSizeLimiter_LimitsRequestBody(t *testing.T) {
	t.Parallel()

	ws := gin.New()
	ws.Use(NewRequestSizeLimiter().MiddlewareHandlerFunc())
	ws.POST("/test", func(c *gin.Context) {
		var payload []string
		err := c.ShouldBindJSON(&payload)
		require.Error(t, err)
		c.Status(http.StatusBadRequest)
	})

	req, _ := http.NewRequest(http.MethodPost, "/test", strings.NewReader(`["`+strings.Repeat("a", maxRequestBodySize)+`"]`))
	resp := httptest.NewRecorder()
	ws.ServeHTTP(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
}
