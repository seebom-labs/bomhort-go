package bomhorttest_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	bomhort "github.com/seebom-labs/bomhort-go"
	"github.com/seebom-labs/bomhort-go/bomhorttest"
)

const purl = "pkg:golang/golang.org/x/net@v0.17.0"

func setup(t *testing.T) (*bomhorttest.Server, *bomhort.Client, bomhort.SBOM, bomhort.SBOM) {
	t.Helper()
	srv := bomhorttest.New("key")
	t.Cleanup(srv.Close)
	vulns := func() []bomhort.Vulnerability {
		return []bomhort.Vulnerability{
			{VulnID: "GHSA-1", Severity: "HIGH", PURL: purl},
			{VulnID: "GHSA-2", Severity: "CRITICAL", PURL: "pkg:npm/x@1.0.0"},
		}
	}
	a := srv.AddSBOM(bomhort.SBOM{ID: bomhorttest.UUID(1), DocumentName: "app", SourceFile: "app.spdx.json", Project: "app"}, vulns(),
		[]bomhort.DependencyNode{{Index: 0, Name: "app", Children: []uint32{1}}, {Index: 1, Name: "x/net", PURL: purl}}, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	b := srv.AddSBOM(bomhort.SBOM{DocumentName: "other", SourceFile: "other.cdx.json", Project: "other"}, vulns(), nil, nil)
	return srv, bomhort.New(srv.URL, bomhort.WithAPIKey("key")), a, b
}

// vexDoc builds a one-statement OpenVEX document about product; with
// subcomponents it is the spec shape, without it a product-wide statement.
func vexDoc(vuln, product, status string, subcomponents ...string) []byte {
	p := map[string]any{"@id": product}
	if len(subcomponents) > 0 {
		var subs []map[string]any
		for _, sc := range subcomponents {
			subs = append(subs, map[string]any{"@id": sc, "identifiers": map[string]any{"purl": sc}})
		}
		p["subcomponents"] = subs
	}
	doc := map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       "https://example.com/vex/1",
		"author":    "tester",
		"role":      "automation",
		"tooling":   "bomhort-go/test",
		"timestamp": "2026-01-01T00:00:00Z",
		"version":   1,
		"statements": []map[string]any{{
			"vulnerability": map[string]any{"name": vuln},
			"products":      []map[string]any{p},
			"status":        status,
			"justification": "vulnerable_code_not_in_execute_path",
			"status_notes":  "govulncheck: not reachable",
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestReadEndpoints(t *testing.T) {
	srv, c, a, b := setup(t)
	ctx := context.Background()

	if err := c.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
	srv.SetReady(false)
	if err := c.Ready(ctx); !bomhort.IsUnavailable(err) {
		t.Fatalf("readyz: %v", err)
	}
	srv.SetReady(true)
	if err := c.Ready(ctx); err != nil {
		t.Fatal(err)
	}

	if b.ID == "" || b.VulnCount != 2 {
		t.Fatalf("AddSBOM must assign id and vuln count: %+v", b)
	}
	all, err := c.AllSBOMs(ctx, nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("%v %v", all, err)
	}
	p, err := c.ListSBOMs(ctx, &bomhort.SBOMListOptions{Search: "OTHER"})
	if err != nil || p.Total != 1 || p.Data[0].ID != b.ID {
		t.Fatalf("search: %+v %v", p, err)
	}
	p, err = c.ListSBOMs(ctx, &bomhort.SBOMListOptions{Project: "app"})
	if err != nil || p.Total != 1 || p.Data[0].ID != a.ID {
		t.Fatalf("project filter: %+v %v", p, err)
	}
	if s, err := c.FindSBOM(ctx, "other.cdx.json"); err != nil || s.ID != b.ID {
		t.Fatalf("FindSBOM: %+v %v", s, err)
	}

	d, err := c.SBOMDetail(ctx, a.ID)
	if err != nil || d.HighVulns != 1 || d.CriticalVulns != 1 || d.DocumentName != "app" {
		t.Fatalf("detail: %+v %v", d, err)
	}
	if _, err := c.SBOMDetail(ctx, bomhorttest.UUID(999)); !bomhort.IsNotFound(err) {
		t.Fatalf("unknown detail: %v", err)
	}
	if _, err := c.Vulnerabilities(ctx, "not-a-uuid"); !bomhort.IsBadRequest(err) {
		t.Fatalf("invalid id must be 400 like BOMHort: %v", err)
	}
	if v, err := c.Vulnerabilities(ctx, bomhorttest.UUID(999)); err != nil || len(v) != 0 {
		t.Fatalf("unknown id lists are empty, not 404: %v %v", v, err)
	}
	deps, err := c.Dependencies(ctx, a.ID)
	if err != nil || len(deps) != 2 {
		t.Fatalf("deps: %v %v", deps, err)
	}
	raw, err := c.DownloadSBOM(ctx, a.ID)
	if err != nil || !strings.Contains(string(raw), "SPDX-2.3") {
		t.Fatalf("download: %s %v", raw, err)
	}
	if _, err := c.DownloadSBOM(ctx, b.ID); !bomhort.IsNotFound(err) {
		t.Fatalf("download without raw: %v", err)
	}
	srv.SetLicenses(a.ID, []bomhort.SBOMLicense{{LicenseID: "MIT", Category: "permissive", PackageCount: 1}})
	if l, err := c.SBOMLicenses(ctx, a.ID); err != nil || len(l) != 1 {
		t.Fatalf("licenses: %v %v", l, err)
	}
}

func TestAuth(t *testing.T) {
	srv, _, a, _ := setup(t)
	ctx := context.Background()
	if err := bomhort.New(srv.URL).Healthy(ctx); err != nil {
		t.Fatalf("health probes are public: %v", err)
	}
	if _, err := bomhort.New(srv.URL).Vulnerabilities(ctx, a.ID); !bomhort.IsUnauthorized(err) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := bomhort.New(srv.URL, bomhort.WithAPIKey("wrong")).Vulnerabilities(ctx, a.ID); !bomhort.IsUnauthorized(err) {
		t.Fatalf("wrong key: %v", err)
	}

	tok := bomhorttest.New("")
	defer tok.Close()
	tok.ServiceToken = "svc"
	if _, err := bomhort.New(tok.URL, bomhort.WithServiceToken("svc")).ListSBOMs(ctx, nil); err != nil {
		t.Fatalf("service token: %v", err)
	}

	open := bomhorttest.New("")
	defer open.Close()
	c := bomhort.New(open.URL)
	if _, err := c.ListSBOMs(ctx, nil); err != nil {
		t.Fatalf("auth disabled: %v", err)
	}
	if _, err := c.UploadSBOM(ctx, "a.spdx.json", []byte(`{}`), nil); !bomhort.IsForbidden(err) {
		t.Fatalf("upload without auth must be 403 like BOMHort: %v", err)
	}
	if _, err := c.PatchSBOMSource(ctx, bomhorttest.UUID(1), bomhort.SourcePatch{SourceRef: bomhort.String("v1")}); !bomhort.IsForbidden(err) {
		t.Fatalf("patch without auth must be 403: %v", err)
	}
}

func TestUploadSBOMIngestsAndDedupes(t *testing.T) {
	srv, c, _, _ := setup(t)
	ctx := context.Background()
	doc := []byte(`{"spdxVersion":"SPDX-2.3","name":"pushed-app","packages":[{},{}]}`)
	res, err := c.UploadSBOM(ctx, "pushed-app.spdx.json", doc, &bomhort.UploadOptions{
		Project: "pushed", Cluster: "prod", Tags: []string{"a", "b"}, SourceRepo: "https://github.com/o/pushed.git", SourceRef: "v1",
	})
	if err != nil || res.Status != "pending" || res.JobType != "sbom" || res.Project != "pushed" || res.JobID == "" {
		t.Fatalf("upload: %+v %v", res, err)
	}
	s, err := c.FindSBOM(ctx, "pushed-app")
	if err != nil || s.Project != "pushed" || s.Cluster != "prod" || s.SourceRepo != "https://github.com/o/pushed" || s.PackageCount != 2 {
		t.Fatalf("ingested SBOM: %+v %v", s, err)
	}
	if f, err := c.FindSBOM(ctx, "pushed-app.spdx.json"); err != nil || f.ID != s.ID || !strings.HasPrefix(f.SourceFile, "pushed/") {
		t.Fatalf("FindSBOM by uploaded filename: %+v %v", f, err)
	}
	uploads, _ := srv.Snapshot()
	if last := uploads[len(uploads)-1]; last.Query["tags"] != "a,b" || last.SourceRef != "v1" {
		t.Fatalf("recorded upload: %+v", last)
	}
	dup, err := c.UploadSBOM(ctx, "again.spdx.json", doc, nil)
	if err != nil || !dup.Duplicate() {
		t.Fatalf("duplicate: %+v %v", dup, err)
	}
	if _, err := c.UploadSBOM(ctx, "bad.spdx.json", []byte(`{nope`), nil); !bomhort.IsBadRequest(err) {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, err := c.UploadSBOM(ctx, "x.spdx.json", []byte(`{"a":1}`), &bomhort.UploadOptions{SourceRepo: "https://user:pw@github.com/o/r"}); !bomhort.IsBadRequest(err) {
		t.Fatalf("credentials in repo URL: %v", err)
	}
}

func TestScopedVEXOnlyAffectsOneSBOM(t *testing.T) {
	srv, c, a, b := setup(t)
	ctx := context.Background()
	res, err := c.UploadVEX(ctx, "app.openvex.json", vexDoc("GHSA-1", "app", "not_affected", purl), a.ID)
	if err != nil || res.JobType != "vex" {
		t.Fatalf("%+v %v", res, err)
	}
	va, _ := c.Vulnerabilities(ctx, a.ID)
	vb, _ := c.Vulnerabilities(ctx, b.ID)
	if va[0].VEXStatus != "not_affected" || va[0].VEXScope != "sbom" || va[0].VEXAuthor != "tester" || va[0].VEXStatementID == "" {
		t.Fatalf("scoped statement not applied: %+v", va[0])
	}
	if vb[0].VEXStatus != "" {
		t.Fatalf("scoped statement leaked to another SBOM: %+v", vb[0])
	}
	if va[1].VEXStatus != "" {
		t.Fatalf("statement must match (vuln_id, purl) exactly: %+v", va[1])
	}
	sts, err := c.SBOMVEXStatements(ctx, a.ID)
	if err != nil || len(sts) != 1 || sts[0].ProductPURL != purl || sts[0].Tooling != "bomhort-go/test" || sts[0].StatusNotes == "" {
		t.Fatalf("sbom vex: %+v %v", sts, err)
	}
	if sts, _ := c.SBOMVEXStatements(ctx, b.ID); len(sts) != 0 {
		t.Fatalf("scoped statement listed for other SBOM: %+v", sts)
	}
	_, stored := srv.Snapshot()
	if len(stored) != 1 || stored[0].SBOMID != a.ID {
		t.Fatalf("stored: %+v", stored)
	}
	if _, err := c.UploadVEX(ctx, "x.openvex.json", vexDoc("A", "B", "fixed"), "not-a-uuid"); !bomhort.IsBadRequest(err) {
		t.Fatalf("invalid sbom_id: %v", err)
	}
}

func TestVEXScopeResolution(t *testing.T) {
	srv, c, a, b := setup(t)
	ctx := context.Background()
	upload := func(doc []byte, sbomID string) {
		t.Helper()
		if _, err := c.UploadVEX(ctx, "d.openvex.json", doc, sbomID); err != nil {
			t.Fatal(err)
		}
	}
	vuln := func(id string, i int) bomhort.Vulnerability {
		t.Helper()
		v, err := c.Vulnerabilities(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return v[i]
	}

	// Unscoped, product = document name of b: resolved to b only.
	upload(vexDoc("GHSA-2", "other", "affected", "pkg:npm/x@1.0.0"), "")
	if v := vuln(b.ID, 1); v.VEXStatus != "affected" || v.VEXScope != "sbom" {
		t.Fatalf("product ref not resolved to SBOM: %+v", v)
	}
	if v := vuln(a.ID, 1); v.VEXStatus != "" {
		t.Fatalf("resolved statement leaked: %+v", v)
	}

	// Unscoped component shape (product = purl): resolves to no SBOM, inert.
	upload(vexDoc("GHSA-1", purl, "fixed"), "")
	if v := vuln(a.ID, 0); v.VEXStatus != "" {
		t.Fatalf("unscoped statement must not suppress: %+v", v)
	}
	all, _ := c.AllVEXStatements(ctx)
	if last := all[len(all)-1]; last.SBOMID != "" || last.ProductPURL != purl {
		t.Fatalf("unresolved statement stored as %+v", last)
	}

	// Product without subcomponents + ?sbom_id=: product-wide ("*").
	upload(vexDoc("https://github.com/advisories/GHSA-2", "whatever", "not_affected"), a.ID)
	if v := vuln(a.ID, 1); v.VEXStatus != "not_affected" {
		t.Fatalf("product-wide statement (URL vuln name) not applied: %+v", v)
	}
	if v := vuln(a.ID, 0); v.VEXStatus != "" {
		t.Fatalf("product-wide statement must still match the vuln id: %+v", v)
	}
	if sts, _ := c.SBOMVEXStatements(ctx, a.ID); sts[0].ProductPURL != "*" || sts[0].VulnID != "GHSA-2" {
		t.Fatalf("product-wide statement stored as %+v", sts[0])
	}

	// Source repo resolution (normalised) and rescue after a later ingest.
	upload(vexDoc("GHSA-9", "git+https://github.com/o/late.git@v2", "fixed", "pkg:npm/late@1"), "")
	late := srv.AddSBOM(bomhort.SBOM{DocumentName: "late", SourceRepo: "https://github.com/o/late"},
		[]bomhort.Vulnerability{{VulnID: "GHSA-9", PURL: "pkg:npm/late@1", Severity: "LOW"}}, nil, nil)
	if v := vuln(late.ID, 0); v.VEXStatus != "fixed" {
		t.Fatalf("statement not rescued after SBOM ingest: %+v", v)
	}
}

func TestNewestStatementWins(t *testing.T) {
	srv, c, a, _ := setup(t)
	ctx := context.Background()
	srv.AddStatement(bomhort.VEXStatement{VulnID: "GHSA-1", ProductPURL: purl, Status: "affected", VEXTimestamp: "2026-05-01T00:00:00Z", SBOMID: a.ID})
	srv.AddStatement(bomhort.VEXStatement{VulnID: "GHSA-1", ProductPURL: purl, Status: "fixed", VEXTimestamp: "2026-03-01T00:00:00Z", SBOMID: a.ID})
	v, _ := c.Vulnerabilities(ctx, a.ID)
	if v[0].VEXStatus != "affected" || v[0].VEXTimestamp != "2026-05-01T00:00:00Z" {
		t.Fatalf("older statement overrode newer one: %+v", v[0])
	}
}

func TestPatchSource(t *testing.T) {
	_, c, a, _ := setup(t)
	ctx := context.Background()
	res, err := c.PatchSBOMSource(ctx, a.ID, bomhort.SourcePatch{SourceRepo: bomhort.String("https://github.com/o/app.git"), SourceRef: bomhort.String("abc123")})
	if err != nil || res.SourceRepo != "https://github.com/o/app" || res.SourceRef != "abc123" || res.SBOMID != a.ID {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = c.PatchSBOMSource(ctx, a.ID, bomhort.SourcePatch{SourceRef: bomhort.String("")})
	if err != nil || res.SourceRepo != "https://github.com/o/app" || res.SourceRef != "" {
		t.Fatalf("partial patch must keep repo and clear ref: %+v %v", res, err)
	}
	s, _ := c.FindSBOM(ctx, a.ID)
	if s.SourceRepo != "https://github.com/o/app" {
		t.Fatalf("not persisted: %+v", s)
	}
	if _, err := c.PatchSBOMSource(ctx, bomhorttest.UUID(42), bomhort.SourcePatch{SourceRef: bomhort.String("x")}); !bomhort.IsNotFound(err) {
		t.Fatalf("unknown sbom: %v", err)
	}
	if _, err := c.PatchSBOMSource(ctx, a.ID, bomhort.SourcePatch{SourceRepo: bomhort.String("ftp://x")}); !bomhort.IsBadRequest(err) {
		t.Fatalf("bad repo: %v", err)
	}
}

func TestCannedAndRequests(t *testing.T) {
	srv, c, _, _ := setup(t)
	ctx := context.Background()
	srv.Handle("GET /api/v1/fleet", 200, []bomhort.FleetCluster{{Name: "prod", SBOMCount: 2}})
	srv.Handle("GET /api/v1/clusters/gone/stats", 404, map[string]string{"error": "Cluster not found"})
	f, err := c.Fleet(ctx)
	if err != nil || len(f) != 1 || f[0].Name != "prod" {
		t.Fatalf("%v %v", f, err)
	}
	if _, err := c.ClusterStats(ctx, "gone"); !bomhort.IsNotFound(err) {
		t.Fatalf("%v", err)
	}
	if _, err := c.Tags(ctx); !bomhort.IsNotFound(err) {
		t.Fatalf("unregistered endpoints are 404: %v", err)
	}
	if _, err := bomhort.New(srv.URL).Fleet(ctx); !bomhort.IsUnauthorized(err) {
		t.Fatalf("canned endpoints are authenticated too: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) == 0 || reqs[0] != "GET /api/v1/fleet" {
		t.Fatalf("requests: %v", reqs)
	}
}

func TestConcurrentUse(t *testing.T) {
	_, c, a, _ := setup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Vulnerabilities(ctx, a.ID)
			doc := vexDoc("GHSA-1", "app", []string{"affected", "fixed"}[i%2], purl)
			_, _ = c.UploadVEX(ctx, "c.openvex.json", append(doc, []byte(strings.Repeat(" ", i))...), a.ID)
		}()
	}
	wg.Wait()
}
