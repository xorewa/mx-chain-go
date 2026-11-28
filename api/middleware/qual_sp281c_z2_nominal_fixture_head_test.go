package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// A successful HEAD request to an inert local fixture is not a listing.
// This router has no product endpoints, handlers, or middleware installed.
func TestQualSP281CZ2NominalFixtureHeadClassification(t *testing.T) {
	const path = "/fixture/status"
	router := gin.New()
	called := false
	router.HEAD(path, func(c *gin.Context) {
		called = true
		require.Equal(t, path, c.FullPath())
		require.Equal(t, http.MethodHead, c.Request.Method)
		require.False(t, isTrieListing(c))
		c.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodHead, path, nil))
	require.True(t, called)
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Empty(t, response.Body.Bytes())
}
