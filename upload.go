package bomhort

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// UploadOptions are the optional parameters of POST /api/v1/sboms/upload.
// Empty fields are omitted, so the gateway's configured defaults apply.
type UploadOptions struct {
	// SBOMID scopes every statement of an uploaded VEX document to one
	// SBOM (BOMHort #350, >= 0.7.0). Only valid for VEX uploads; must be a
	// UUID.
	SBOMID string
	// Cluster, Namespace and Project override the gateway's ownership
	// defaults (CLUSTER_NAME, NAMESPACE, PROJECT).
	Cluster   string
	Namespace string
	Project   string
	// Parent names the product the upload belongs to (unreleased).
	Parent string
	// Tags are merged with the instance's default tags.
	Tags []string
	// SourceRepo (http(s) URL without credentials) and SourceRef (git ref)
	// attribute the SBOM to its source (#332, >= 0.7.0), sent as
	// X-Source-Repo / X-Source-Ref.
	SourceRepo string
	SourceRef  string
}

// Upload pushes a document through POST /api/v1/sboms/upload. filename is
// sent as X-Filename and decides how BOMHort classifies the content: it
// must end in .spdx.json, .cdx.json, .openvex.json, .vex.json or .json.
//
// BOMHort only accepts uploads when AUTH_ENABLED=true (403 otherwise) and
// needs writable storage (503 otherwise). Ingestion is asynchronous: a
// "pending" result carries the job id; "duplicate" means identical content
// was ingested before.
func (c *Client) Upload(ctx context.Context, filename string, doc []byte, opts *UploadOptions) (UploadResult, error) {
	name := path.Base(strings.TrimSpace(filename))
	if !uploadableName(name) {
		return UploadResult{}, fmt.Errorf("bomhort: filename %q must end in .spdx.json, .cdx.json, .openvex.json, .vex.json or .json", filename)
	}
	if len(doc) == 0 {
		return UploadResult{}, fmt.Errorf("bomhort: refusing to upload empty document %q", name)
	}
	q := url.Values{}
	headers := map[string]string{
		"Content-Type": "application/json",
		"X-Filename":   name,
	}
	if opts != nil {
		if opts.SBOMID != "" && !isVEXName(name) {
			return UploadResult{}, fmt.Errorf("bomhort: SBOMID is only valid for VEX uploads (*.openvex.json / *.vex.json), got %q", name)
		}
		setIf(q, "sbom_id", opts.SBOMID)
		setIf(q, "cluster", opts.Cluster)
		setIf(q, "namespace", opts.Namespace)
		setIf(q, "project", opts.Project)
		setIf(q, "parent", opts.Parent)
		if len(opts.Tags) > 0 {
			q.Set("tags", strings.Join(opts.Tags, ","))
		}
		if opts.SourceRepo != "" {
			headers["X-Source-Repo"] = opts.SourceRepo
		}
		if opts.SourceRef != "" {
			headers["X-Source-Ref"] = opts.SourceRef
		}
	}
	var out UploadResult
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/sboms/upload", query: q, body: doc, headers: headers}, &out)
	return out, err
}

// UploadSBOM uploads an SPDX or CycloneDX JSON document. It is Upload with
// a check that filename is not a VEX name.
func (c *Client) UploadSBOM(ctx context.Context, filename string, doc []byte, opts *UploadOptions) (UploadResult, error) {
	if isVEXName(path.Base(filename)) {
		return UploadResult{}, fmt.Errorf("bomhort: %q is a VEX filename; use UploadVEX", filename)
	}
	return c.Upload(ctx, filename, doc, opts)
}

// UploadVEX uploads an OpenVEX document. filename must end in
// .openvex.json or .vex.json so BOMHort classifies the job as VEX. A
// non-empty sbomID scopes every statement to that SBOM (?sbom_id=, #350);
// with "" BOMHort resolves each product @id against the SBOMs' id,
// source_repo and document name, and statements whose product resolves to
// nothing suppress nothing.
//
// Within its SBOM a statement applies to a finding when vulnerability.name
// == vuln_id and the subcomponent purl == purl (plain string equality);
// a product without subcomponents covers every finding with that vuln_id.
// Copy both values verbatim from Vulnerability. See docs/VEX.md.
func (c *Client) UploadVEX(ctx context.Context, filename string, doc []byte, sbomID string) (UploadResult, error) {
	if !isVEXName(path.Base(filename)) {
		return UploadResult{}, fmt.Errorf("bomhort: filename %q must end in .openvex.json or .vex.json", filename)
	}
	return c.Upload(ctx, filename, doc, &UploadOptions{SBOMID: sbomID})
}

// isVEXName and uploadableName mirror BOMHort's repo.ClassifyFileType
// (case-insensitive suffix match).
func isVEXName(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".openvex.json") || strings.HasSuffix(name, ".vex.json")
}

func uploadableName(name string) bool {
	return name != "." && name != "/" && strings.HasSuffix(strings.ToLower(name), ".json")
}
