package bomhort

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is returned for every non-2xx response from BOMHort.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Message is BOMHort's {"error": "..."} text, or the (truncated) body.
	Message string
	// Method and Path identify the failed call (path without query).
	Method string
	Path   string
}

func (e *APIError) Error() string {
	if e.Method == "" {
		return fmt.Sprintf("bomhort: HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("bomhort: %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

const maxErrorMessage = 300

func newAPIError(method, path string, status int, data []byte) *APIError {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(data))
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	if len(msg) > maxErrorMessage {
		msg = msg[:maxErrorMessage] + "…"
	}
	return &APIError{StatusCode: status, Message: msg, Method: method, Path: path}
}

// StatusCode returns the HTTP status of err if it is (or wraps) an
// *APIError, otherwise 0.
func StatusCode(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}

// IsNotFound reports whether err is a 404 from BOMHort. Note that BOMHort
// also answers 404 for routes an older gateway does not know.
func IsNotFound(err error) bool { return StatusCode(err) == http.StatusNotFound }

// IsBadRequest reports whether err is a 400 (validation failure).
func IsBadRequest(err error) bool { return StatusCode(err) == http.StatusBadRequest }

// IsUnauthorized reports whether err is a 401 (missing/invalid credentials).
func IsUnauthorized(err error) bool { return StatusCode(err) == http.StatusUnauthorized }

// IsForbidden reports whether err is a 403. BOMHort returns it for the
// write endpoints (upload, PATCH) when AUTH_ENABLED=false.
func IsForbidden(err error) bool { return StatusCode(err) == http.StatusForbidden }

// IsRateLimited reports whether err is a 429 that survived all retries.
func IsRateLimited(err error) bool { return StatusCode(err) == http.StatusTooManyRequests }

// IsUnavailable reports whether err is a 503 (e.g. /readyz without
// ClickHouse, or upload without storage).
func IsUnavailable(err error) bool { return StatusCode(err) == http.StatusServiceUnavailable }
