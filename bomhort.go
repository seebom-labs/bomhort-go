// Package bomhort is a Go client for the BOMHort REST API
// (https://docs.bomhort.dev/docs/api-reference/).
//
// It is stdlib-only and covers the complete public API of the BOMHort
// api-gateway: SBOMs and their findings, dependency trees, licenses and VEX
// statements, projects, clusters, namespaces, fleet, statistics, search, the
// push-model upload endpoint and the source-attribution PATCH.
//
// A Client is safe for concurrent use. Create one per BOMHort instance:
//
//	c := bomhort.New("https://bomhort.example.com",
//		bomhort.WithAPIKey(os.Getenv("BOMHORT_API_KEY")),
//		bomhort.WithRateLimit(90, 10*time.Second),
//	)
//	sboms, err := c.AllSBOMs(ctx, nil)
//
// Non-2xx responses are returned as *APIError; use IsNotFound,
// IsUnauthorized and friends to branch on them. 429 responses are retried
// with Retry-After / exponential back-off (see WithMaxRetries).
//
// The package bomhorttest provides an in-memory fake gateway for tests.
package bomhort

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the client library version, sent in the default User-Agent.
const Version = "0.1.0-dev"

// DefaultUserAgent is sent unless WithUserAgent overrides it.
const DefaultUserAgent = "bomhort-go/" + Version

// Client talks to one BOMHort API gateway.
type Client struct {
	baseURL      string
	apiKey       string
	serviceToken string
	userAgent    string
	http         *http.Client
	maxRetries   int
	strict       bool
	limiter      *RateLimiter
	// sleep waits between 429 retries; replaced in tests.
	sleep func(context.Context, time.Duration) error
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey authenticates every request with the X-API-Key header.
func WithAPIKey(key string) Option { return func(c *Client) { c.apiKey = key } }

// WithServiceToken authenticates every request with
// "Authorization: Bearer <token>" (BOMHort's SERVICE_TOKEN).
func WithServiceToken(token string) Option { return func(c *Client) { c.serviceToken = token } }

// WithHTTPClient replaces the underlying HTTP client (default: 60 s timeout).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithUserAgent overrides the User-Agent header (default DefaultUserAgent).
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// WithRateLimit paces requests to at most limit per window on the client
// side (limit <= 0 disables pacing). BOMHort allows 100 requests per 10 s
// per client IP; 90 / 10 s leaves headroom for other callers.
func WithRateLimit(limit int, window time.Duration) Option {
	return func(c *Client) { c.limiter = NewRateLimiter(limit, window) }
}

// WithRateLimiter shares one RateLimiter between several clients talking
// to the same gateway.
func WithRateLimiter(l *RateLimiter) Option { return func(c *Client) { c.limiter = l } }

// WithMaxRetries bounds the number of retries on HTTP 429 (default 3).
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxRetries = n
		}
	}
}

// WithStrictDecoding makes response decoding fail on JSON fields the client
// does not know. Off by default so new server fields never break callers;
// the integration tests turn it on to detect API drift early.
func WithStrictDecoding() Option { return func(c *Client) { c.strict = true } }

// New creates a client for baseURL, e.g. "http://localhost:8080". A
// trailing slash and a trailing "/api/v1" are tolerated.
func New(baseURL string, opts ...Option) *Client {
	base := strings.TrimRight(baseURL, "/")
	base = strings.TrimSuffix(base, "/api/v1")
	c := &Client{
		baseURL:    base,
		userAgent:  DefaultUserAgent,
		http:       &http.Client{Timeout: 60 * time.Second},
		maxRetries: 3,
		sleep:      sleepCtx,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// BaseURL returns the configured base URL (without /api/v1).
func (c *Client) BaseURL() string { return c.baseURL }

// request describes one API call.
type request struct {
	method  string
	path    string // escaped path, starting with "/"
	query   url.Values
	body    []byte
	headers map[string]string
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.do(ctx, request{method: http.MethodGet, path: path, query: q}, out)
	return err
}

// do executes r, retrying on 429, and decodes a 2xx JSON body into out
// (if non-nil). It returns the raw body.
func (c *Client) do(ctx context.Context, r request, out any) ([]byte, error) {
	target := c.baseURL + r.path
	if len(r.query) > 0 {
		target += "?" + r.query.Encode()
	}
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		var body io.Reader
		if r.body != nil {
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, target, body)
		if err != nil {
			return nil, fmt.Errorf("bomhort: build request: %w", err)
		}
		c.authorize(req)
		for k, v := range r.headers {
			req.Header.Set(k, v)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("bomhort: %s %s: %w", r.method, r.path, err)
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("bomhort: %s %s: read response: %w", r.method, r.path, readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = newAPIError(r.method, r.path, resp.StatusCode, data)
			if attempt == c.maxRetries {
				break
			}
			if err := c.sleep(ctx, retryAfter(resp.Header.Get("Retry-After"), attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, newAPIError(r.method, r.path, resp.StatusCode, data)
		}
		if out != nil {
			if err := c.decode(data, out); err != nil {
				return nil, fmt.Errorf("bomhort: decode %s %s: %w", r.method, r.path, err)
			}
		}
		return data, nil
	}
	return nil, lastErr
}

// authorize sets the common headers and credentials on req.
func (c *Client) authorize(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	}
}

func (c *Client) decode(data []byte, out any) error {
	if !c.strict {
		return json.Unmarshal(data, out)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func retryAfter(header string, attempt int) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return time.Duration(1<<attempt) * time.Second
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// esc escapes one path segment (IDs, project/cluster/namespace names).
func esc(s string) string { return url.PathEscape(s) }

// pageQuery builds page/page_size parameters; zero values are omitted so
// the server defaults apply.
func pageQuery(o ListOptions) url.Values {
	q := url.Values{}
	if o.Page > 0 {
		q.Set("page", strconv.Itoa(o.Page))
	}
	if o.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(o.PageSize))
	}
	return q
}

func setIf(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}
