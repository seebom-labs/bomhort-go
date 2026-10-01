package bomhort

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTrimsBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://h:8080":         "http://h:8080",
		"http://h:8080/":        "http://h:8080",
		"http://h:8080/api/v1":  "http://h:8080",
		"http://h:8080/api/v1/": "http://h:8080",
		"https://h/prefix":      "https://h/prefix",
	} {
		if got := New(in).BaseURL(); got != want {
			t.Errorf("New(%q).BaseURL() = %q, want %q", in, got, want)
		}
	}
}

func TestHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	if err := New(srv.URL, WithAPIKey("k1"), WithServiceToken("tok")).Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-API-Key") != "k1" || got.Get("Authorization") != "Bearer tok" {
		t.Errorf("credentials not sent: %v", got)
	}
	if got.Get("User-Agent") != DefaultUserAgent || got.Get("Accept") != "application/json" {
		t.Errorf("default headers: %v", got)
	}

	if err := New(srv.URL, WithUserAgent("vexviper/1.2")).Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Get("User-Agent") != "vexviper/1.2" || got.Get("X-API-Key") != "" || got.Get("Authorization") != "" {
		t.Errorf("anonymous client sent %v", got)
	}
}

func TestRetryOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"Rate limit exceeded"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body) // echo: proves the body is resent on retry
	}))
	defer srv.Close()

	c := New(srv.URL)
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	var out map[string]string
	if _, err := c.do(context.Background(), request{method: http.MethodPost, path: "/x", body: []byte(`{"a":"b"}`)}, &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != "b" || calls.Load() != 3 {
		t.Fatalf("out=%v calls=%d", out, calls.Load())
	}
	if len(slept) != 2 || slept[0] != 7*time.Second {
		t.Fatalf("slept %v, want Retry-After honoured", slept)
	}
}

func TestRetryExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(2))
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	err := c.Healthy(context.Background())
	if !IsRateLimited(err) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 1 + 2 retries", calls.Load())
	}
	if want := []time.Duration{time.Second, 2 * time.Second}; len(slept) != 2 || slept[0] != want[0] || slept[1] != want[1] {
		t.Fatalf("back-off %v, want %v", slept, want)
	}
	if !strings.Contains(err.Error(), "Too Many Requests") {
		t.Errorf("empty body should fall back to status text: %v", err)
	}
}

func TestRetrySleepHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := New(srv.URL).Healthy(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("retry sleep ignored the context")
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		check  func(error) bool
		msg    string
	}{
		{404, `{"error":"SBOM not found"}`, IsNotFound, "SBOM not found"},
		{400, `{"error":"Invalid SBOM ID"}`, IsBadRequest, "Invalid SBOM ID"},
		{401, `{"error":"Authentication required"}`, IsUnauthorized, "Authentication required"},
		{403, `{"error":"Upload requires AUTH_ENABLED=true"}`, IsForbidden, "AUTH_ENABLED"},
		{503, `{"status":"unavailable","reason":"clickhouse"}`, IsUnavailable, "clickhouse"},
		{500, "plain text failure", func(err error) bool { return StatusCode(err) == 500 }, "plain text failure"},
		{502, strings.Repeat("x", 1000), func(err error) bool { return StatusCode(err) == 502 }, "…"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		_, err := New(srv.URL).SBOMDetail(context.Background(), "abc")
		srv.Close()
		if !tc.check(err) {
			t.Errorf("%d: unexpected error classification: %v", tc.status, err)
			continue
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Method != http.MethodGet || apiErr.Path != "/api/v1/sboms/abc/detail" {
			t.Errorf("%d: %#v", tc.status, err)
		}
		if !strings.Contains(err.Error(), tc.msg) || len(apiErr.Message) > maxErrorMessage+len("…") {
			t.Errorf("%d: message %q", tc.status, err.Error())
		}
	}
	if StatusCode(errors.New("x")) != 0 || IsNotFound(nil) {
		t.Error("non-API errors must have status 0")
	}
	if (&APIError{StatusCode: 418, Message: "teapot"}).Error() != "bomhort: HTTP 418: teapot" {
		t.Error("APIError without method")
	}
}

func TestStrictDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"sbom_id":"x","brand_new_field":1}`)
	}))
	defer srv.Close()
	if _, err := New(srv.URL).SBOMDetail(context.Background(), "x"); err != nil {
		t.Fatalf("lenient decoding must ignore unknown fields: %v", err)
	}
	_, err := New(srv.URL, WithStrictDecoding()).SBOMDetail(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "brand_new_field") {
		t.Fatalf("strict decoding must report unknown fields, got %v", err)
	}
}

func TestDecodeErrorAndTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not json`)
	}))
	if _, err := New(srv.URL).Fleet(context.Background()); err == nil || !strings.Contains(err.Error(), "decode GET /api/v1/fleet") {
		t.Fatalf("err = %v", err)
	}
	srv.Close()
	if _, err := New(srv.URL).Fleet(context.Background()); err == nil || StatusCode(err) != 0 {
		t.Fatalf("closed server: %v", err)
	}
}

func TestRateLimiterIsApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	l := NewRateLimiter(1, time.Hour)
	c := New(srv.URL, WithRateLimiter(l))
	if err := c.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Healthy(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second request must wait for the limiter, got %v", err)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	if retryAfter("5", 0) != 5*time.Second || retryAfter(" 2 ", 3) != 2*time.Second {
		t.Error("seconds")
	}
	if retryAfter("", 0) != time.Second || retryAfter("Wed, 21 Oct 2015 07:28:00 GMT", 2) != 4*time.Second || retryAfter("-1", 1) != 2*time.Second {
		t.Error("fallback back-off")
	}
}

func TestLooksLikeUUID(t *testing.T) {
	for s, want := range map[string]bool{
		"11111111-2222-3333-4444-555555555555": true,
		"ABCDEF01-2222-3333-4444-555555555555": true,
		"11111111-2222-3333-4444-55555555555g": false,
		"11111111_2222-3333-4444-555555555555": false,
		"bomhort":                              false,
	} {
		if looksLikeUUID(s) != want {
			t.Errorf("looksLikeUUID(%q) != %v", s, want)
		}
	}
}

func TestUploadResultDuplicate(t *testing.T) {
	var r UploadResult
	if err := json.Unmarshal([]byte(`{"status":"duplicate","sha256_hash":"h","message":"Content already ingested, skipping"}`), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Duplicate() || r.Message == "" {
		t.Fatalf("%+v", r)
	}
}
