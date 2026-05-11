package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const maxRequestBodySize = 4 << 20

// requestSizeLimiter caps request bodies before handlers parse JSON payloads.
type requestSizeLimiter struct {
	maxBodySize int64
}

// NewRequestSizeLimiter returns a middleware that enforces a maximum request body size.
func NewRequestSizeLimiter() *requestSizeLimiter {
	return &requestSizeLimiter{
		maxBodySize: maxRequestBodySize,
	}
}

// MiddlewareHandlerFunc returns the handler func used by the gin server when processing requests.
func (rsl *requestSizeLimiter) MiddlewareHandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, rsl.maxBodySize)
		}

		c.Next()
	}
}

// IsInterfaceNil returns true if there is no value under the interface.
func (rsl *requestSizeLimiter) IsInterfaceNil() bool {
	return rsl == nil
}
