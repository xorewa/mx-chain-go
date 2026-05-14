package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestIsAllowedCORSOrigin(t *testing.T) {
	t.Run("loopback origins are allowed", func(t *testing.T) {
		require.True(t, isAllowedCORSOrigin("http://localhost:8080"))
		require.True(t, isAllowedCORSOrigin("http://127.0.0.1:8080"))
		require.True(t, isAllowedCORSOrigin("http://[::1]:8080"))
	})

	t.Run("remote and malformed origins are rejected", func(t *testing.T) {
		require.False(t, isAllowedCORSOrigin("https://example.com"))
		require.False(t, isAllowedCORSOrigin("://bad-origin"))
	})
}

func TestIsAllowedWebSocketOrigin(t *testing.T) {
	t.Run("same host origin is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://seednode.local/log", nil)
		req.Header.Set("Origin", "http://seednode.local")

		require.True(t, isAllowedWebSocketOrigin(req))
	})

	t.Run("empty and cross host origins are rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://seednode.local/log", nil)
		require.False(t, isAllowedWebSocketOrigin(req))

		req.Header.Set("Origin", "http://attacker.local")
		require.False(t, isAllowedWebSocketOrigin(req))
	})
}

func TestRegisterRoutesShouldExposePrometheusOnlyWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("enabled", func(t *testing.T) {
		engine := gin.New()
		registerRoutes(engine, nil, true)

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/debug/metrics/prometheus", nil)
		engine.ServeHTTP(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("disabled", func(t *testing.T) {
		engine := gin.New()
		registerRoutes(engine, nil, false)

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/debug/metrics/prometheus", nil)
		engine.ServeHTTP(resp, req)

		require.Equal(t, http.StatusNotFound, resp.Code)
	})
}
