package bomhort

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

// Healthy calls GET /healthz (legacy health check, always public).
func (c *Client) Healthy(ctx context.Context) error {
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/healthz"}, nil)
	return err
}

// Live calls GET /livez: the gateway process is up.
func (c *Client) Live(ctx context.Context) error {
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/livez"}, nil)
	return err
}

// Ready calls GET /readyz: the gateway can reach ClickHouse. A not-ready
// gateway yields an *APIError with status 503 (see IsUnavailable).
func (c *Client) Ready(ctx context.Context) error {
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/readyz"}, nil)
	return err
}

// SBOMListOptions filters GET /api/v1/sboms.
type SBOMListOptions struct {
	ListOptions
	// Search is a substring match on document name or source path.
	Search string
	// Project is an exact project name (#398, unreleased; ignored by
	// older gateways).
	Project string
}

func (o *SBOMListOptions) query() url.Values {
	if o == nil {
		return nil
	}
	q := pageQuery(o.ListOptions)
	setIf(q, "search", o.Search)
	setIf(q, "project", o.Project)
	return q
}

// ListSBOMs returns one page of SBOMs. opts may be nil.
func (c *Client) ListSBOMs(ctx context.Context, opts *SBOMListOptions) (Paginated[SBOM], error) {
	var out Paginated[SBOM]
	err := c.getJSON(ctx, "/api/v1/sboms", opts.query(), &out)
	return out, err
}

// SBOMs iterates over all SBOMs matching opts, fetching pages lazily.
// opts.Page is ignored; opts.PageSize defaults to 100.
func (c *Client) SBOMs(ctx context.Context, opts *SBOMListOptions) Seq[SBOM] {
	var o SBOMListOptions
	if opts != nil {
		o = *opts
	}
	return Paginate(ctx, o.PageSize, func(ctx context.Context, lo ListOptions) (Paginated[SBOM], error) {
		o.ListOptions = lo
		return c.ListSBOMs(ctx, &o)
	})
}

// AllSBOMs collects every SBOM matching opts (nil = all SBOMs).
func (c *Client) AllSBOMs(ctx context.Context, opts *SBOMListOptions) ([]SBOM, error) {
	return Collect(c.SBOMs(ctx, opts))
}

// FindSBOM returns the first SBOM whose ID, document name or source file
// equals ref. A source file also matches by its base name, and uploaded
// documents (stored as "pushed/<uuid>-<filename>") by the filename they
// were uploaded with. It narrows the listing with ?search= when ref is not
// a UUID and falls back to a full scan otherwise.
func (c *Client) FindSBOM(ctx context.Context, ref string) (SBOM, error) {
	match := func(s SBOM) bool {
		return s.ID == ref || s.DocumentName == ref || s.SourceFile == ref ||
			path.Base(s.SourceFile) == ref || UploadedFilename(s.SourceFile) == ref
	}
	if ref == "" {
		return SBOM{}, fmt.Errorf("bomhort: empty SBOM reference")
	}
	if !looksLikeUUID(ref) {
		for s, err := range c.SBOMs(ctx, &SBOMListOptions{Search: ref}) {
			if err != nil {
				return SBOM{}, err
			}
			if match(s) {
				return s, nil
			}
		}
	}
	for s, err := range c.SBOMs(ctx, nil) {
		if err != nil {
			return SBOM{}, err
		}
		if match(s) {
			return s, nil
		}
	}
	return SBOM{}, &APIError{StatusCode: http.StatusNotFound, Message: fmt.Sprintf("no SBOM matches %q", ref)}
}

// UploadedFilename returns the filename a document was uploaded with when
// sourceFile has the "pushed/<uuid>-<filename>" form BOMHort stores uploads
// under, and "" otherwise.
func UploadedFilename(sourceFile string) string {
	base := path.Base(sourceFile)
	if len(base) > 37 && base[36] == '-' && looksLikeUUID(base[:36]) {
		return base[37:]
	}
	return ""
}

// SBOMDetail returns GET /api/v1/sboms/{id}/detail (metadata plus severity
// breakdown). Unknown ids yield a 404 *APIError.
func (c *Client) SBOMDetail(ctx context.Context, sbomID string) (SBOMDetail, error) {
	var out SBOMDetail
	err := c.getJSON(ctx, "/api/v1/sboms/"+esc(sbomID)+"/detail", nil, &out)
	return out, err
}

// Vulnerabilities returns all findings of an SBOM (not paginated), one row
// per (vuln_id, purl) on BOMHort >= 0.7.0.
func (c *Client) Vulnerabilities(ctx context.Context, sbomID string) ([]Vulnerability, error) {
	var out []Vulnerability
	err := c.getJSON(ctx, "/api/v1/sboms/"+esc(sbomID)+"/vulnerabilities", nil, &out)
	return out, err
}

// Dependencies returns the flat dependency node list of an SBOM.
func (c *Client) Dependencies(ctx context.Context, sbomID string) ([]DependencyNode, error) {
	var out []DependencyNode
	err := c.getJSON(ctx, "/api/v1/sboms/"+esc(sbomID)+"/dependencies", nil, &out)
	return out, err
}

// SBOMLicenses returns the per-license breakdown of an SBOM.
func (c *Client) SBOMLicenses(ctx context.Context, sbomID string) ([]SBOMLicense, error) {
	var out []SBOMLicense
	err := c.getJSON(ctx, "/api/v1/sboms/"+esc(sbomID)+"/licenses", nil, &out)
	return out, err
}

// SBOMVEXStatements returns the VEX statements scoped to an SBOM, newest
// first (GET /api/v1/sboms/{id}/vex).
func (c *Client) SBOMVEXStatements(ctx context.Context, sbomID string) ([]VEXStatement, error) {
	var out []VEXStatement
	err := c.getJSON(ctx, "/api/v1/sboms/"+esc(sbomID)+"/vex", nil, &out)
	return out, err
}

// DownloadSBOM returns the original SBOM document bytes.
func (c *Client) DownloadSBOM(ctx context.Context, sbomID string) ([]byte, error) {
	return c.do(ctx, request{method: http.MethodGet, path: "/api/v1/sboms/" + esc(sbomID) + "/download"}, nil)
}

// DownloadSBOMTo streams the original SBOM document into w and returns the
// number of bytes written. Unlike DownloadSBOM it does not buffer the
// document and does not retry on 429.
func (c *Client) DownloadSBOMTo(ctx context.Context, sbomID string, w io.Writer) (int64, error) {
	path := "/api/v1/sboms/" + esc(sbomID) + "/download"
	if err := c.limiter.Wait(ctx); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return 0, fmt.Errorf("bomhort: build request: %w", err)
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("bomhort: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, newAPIError(http.MethodGet, path, resp.StatusCode, data)
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return n, fmt.Errorf("bomhort: GET %s: stream: %w", path, err)
	}
	return n, nil
}

// SourcePatch is the body of PATCH /api/v1/sboms/{id}. A nil field is left
// unchanged; a pointer to "" clears it.
type SourcePatch struct {
	SourceRepo *string `json:"source_repo,omitempty"`
	SourceRef  *string `json:"source_ref,omitempty"`
}

// PatchSBOMSource sets or clears source_repo/source_ref of an existing SBOM
// (BOMHort #332, >= 0.7.0). Requires AUTH_ENABLED=true on the gateway
// (403 otherwise) and credentials. The returned values are normalised by
// BOMHort.
func (c *Client) PatchSBOMSource(ctx context.Context, sbomID string, patch SourcePatch) (SourceAttribution, error) {
	if patch.SourceRepo == nil && patch.SourceRef == nil {
		return SourceAttribution{}, fmt.Errorf("bomhort: PatchSBOMSource: set SourceRepo and/or SourceRef")
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return SourceAttribution{}, fmt.Errorf("bomhort: encode patch: %w", err)
	}
	var out SourceAttribution
	_, err = c.do(ctx, request{
		method:  http.MethodPatch,
		path:    "/api/v1/sboms/" + esc(sbomID),
		body:    body,
		headers: map[string]string{"Content-Type": "application/json"},
	}, &out)
	return out, err
}

// String returns a pointer to s, for SourcePatch fields.
func String(s string) *string { return &s }

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}
