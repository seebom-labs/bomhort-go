//go:build integration

// Package integration exercises the client against a live BOMHort.
//
//	BOMHORT_URL=http://localhost:18080 BOMHORT_API_KEY=... go test -tags integration ./test/integration/
//
// hack/e2e-bomhort.sh provisions such an instance with docker compose.
//
// Every response is decoded with WithStrictDecoding, so a field BOMHort adds
// without a matching struct field fails the run: that is how API drift is
// detected (see docs/TESTING.md). Endpoints that only exist on BOMHort main
// (not yet released) are skipped when the server answers 404.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	bomhort "github.com/seebom-labs/bomhort-go"
)

const (
	project   = "bomhort-go-it"
	cluster   = "it-cluster"
	namespace = "it-namespace"
	tag       = "bomhort-go"
	repo      = "https://github.com/seebom-labs/bomhort"
)

// fixture is the SBOM uploaded once per run and shared by all tests.
type fixture struct {
	c        *bomhort.Client
	sbom     bomhort.SBOM
	doc      []byte
	filename string
	vulns    []bomhort.Vulnerability
}

var (
	once    sync.Once
	shared  *fixture
	initErr error
)

func timeout() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("BOMHORT_IT_TIMEOUT")); err == nil {
		return d
	}
	return 5 * time.Minute
}

func newClient(t *testing.T, opts ...bomhort.Option) *bomhort.Client {
	t.Helper()
	url := os.Getenv("BOMHORT_URL")
	if url == "" {
		t.Skip("BOMHORT_URL not set")
	}
	opts = append([]bomhort.Option{
		bomhort.WithStrictDecoding(),
		bomhort.WithRateLimit(80, 10*time.Second),
		bomhort.WithUserAgent("bomhort-go-integration/" + bomhort.Version),
	}, opts...)
	return bomhort.New(url, opts...)
}

func authed(t *testing.T) *bomhort.Client {
	t.Helper()
	key := os.Getenv("BOMHORT_API_KEY")
	if key == "" {
		t.Skip("BOMHORT_API_KEY not set (uploads need auth)")
	}
	return newClient(t, bomhort.WithAPIKey(key))
}

// setup uploads testdata/bomhort-0.6.1.spdx.json with a per-run nonce (so
// reruns against a kept stack are not duplicates) and waits until BOMHort
// has parsed it and the OSV scan reported vulnerabilities.
func setup(t *testing.T) *fixture {
	t.Helper()
	c := authed(t)
	once.Do(func() { shared, initErr = ingest(c) })
	if initErr != nil {
		t.Fatal(initErr)
	}
	return shared
}

func ingest(c *bomhort.Client) (*fixture, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout())
	defer cancel()

	for err := c.Ready(ctx); err != nil; err = c.Ready(ctx) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("BOMHort never became ready: %w", err)
		}
		time.Sleep(2 * time.Second)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	nonce := make([]byte, 4)
	_, _ = rand.Read(nonce)
	run := hex.EncodeToString(nonce)
	m["name"] = "bomhort-go-it-" + run
	m["documentNamespace"] = fmt.Sprintf("https://bomhort-go.invalid/it/%s", run)
	doc, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	filename := "bomhort-go-it-" + run + ".spdx.json"

	res, err := c.UploadSBOM(ctx, filename, doc, &bomhort.UploadOptions{
		Cluster: cluster, Namespace: namespace, Project: project,
		Tags:       []string{tag, "integration"},
		SourceRepo: repo + ".git", SourceRef: "v0.6.1",
	})
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	if res.Status != "pending" || res.JobType != "sbom" || res.JobID == "" || res.SHA256Hash == "" {
		return nil, fmt.Errorf("unexpected upload result %+v", res)
	}

	for {
		p, err := c.ListSBOMs(ctx, &bomhort.SBOMListOptions{Search: run})
		if err == nil {
			for _, s := range p.Data {
				if s.DocumentName == m["name"] && s.VulnCount > 0 {
					vulns, err := c.Vulnerabilities(ctx, s.ID)
					if err != nil {
						return nil, err
					}
					return &fixture{c: c, sbom: s, doc: doc, filename: filename, vulns: vulns}, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("SBOM %s not ingested with vulnerabilities in %s (last error: %v)", filename, timeout(), err)
		case <-time.After(3 * time.Second):
		}
	}
}

// unreleased skips when an endpoint that only exists on BOMHort main
// answers 404 on a released server.
func unreleased(t *testing.T, err error) {
	t.Helper()
	if bomhort.IsNotFound(err) {
		t.Skipf("endpoint not available on this BOMHort (unreleased): %v", err)
	}
}

// must turns (value, error) into a value, failing the test on error:
// must(c.SBOMDetail(ctx, id))(t).
var (
	probeOnce sync.Once
	hasUnrel  bool
)

// requireUnreleased skips unless the server has the API that is only on
// BOMHort main (probed via GET /api/v1/projects/{name}/sboms of the fixture
// project, a route released servers do not have).
func requireUnreleased(t *testing.T, c *bomhort.Client) {
	t.Helper()
	probeOnce.Do(func() {
		_, err := c.ListProjectSBOMs(context.Background(), project, nil)
		hasUnrel = !bomhort.IsNotFound(err)
	})
	if !hasUnrel {
		t.Skip("server predates the unreleased BOMHort API")
	}
}

func must[T any](v T, err error) func(testing.TB) T {
	return func(t testing.TB) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestHealth(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	for name, f := range map[string]func(context.Context) error{"healthz": c.Healthy, "livez": c.Live, "readyz": c.Ready} {
		if err := f(ctx); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	if os.Getenv("BOMHORT_API_KEY") == "" {
		t.Skip("BOMHORT_API_KEY not set; auth is probably disabled")
	}
	ctx := context.Background()
	if _, err := newClient(t).ListSBOMs(ctx, nil); !bomhort.IsUnauthorized(err) {
		t.Errorf("anonymous request: want 401, got %v", err)
	}
	if _, err := newClient(t, bomhort.WithAPIKey("definitely-wrong")).ListSBOMs(ctx, nil); !bomhort.IsUnauthorized(err) {
		t.Errorf("wrong key: want 401, got %v", err)
	}
}

func TestSBOM(t *testing.T) {
	f := setup(t)
	c, s, ctx := f.c, f.sbom, context.Background()

	if s.Project != project || s.Cluster != cluster || s.Namespace != namespace {
		t.Errorf("ownership not applied: %+v", s)
	}
	if s.SourceRepo != repo || s.SourceRef != "v0.6.1" {
		t.Errorf("source attribution not normalised/applied: repo=%q ref=%q", s.SourceRepo, s.SourceRef)
	}
	if s.PackageCount == 0 || s.SPDXVersion == "" || s.IngestedAt == "" {
		t.Errorf("incomplete SBOM: %+v", s)
	}
	if got := must(c.FindSBOM(ctx, s.ID))(t); got.ID != s.ID {
		t.Errorf("FindSBOM(id) = %s", got.ID)
	}
	if got := must(c.FindSBOM(ctx, f.filename))(t); got.ID != s.ID {
		t.Errorf("FindSBOM(filename) = %s", got.ID)
	}

	d := must(c.SBOMDetail(ctx, s.ID))(t)
	if d.ID != s.ID || d.VulnCount != s.VulnCount ||
		d.CriticalVulns+d.HighVulns+d.MediumVulns+d.LowVulns == 0 {
		t.Errorf("detail mismatch: %+v", d)
	}

	for _, v := range f.vulns {
		if v.VulnID == "" || v.PURL == "" || v.Severity == "" {
			t.Errorf("incomplete vulnerability: %+v", v)
		}
	}
	deps := must(c.Dependencies(ctx, s.ID))(t)
	if len(deps) == 0 {
		t.Error("no dependency nodes")
	}
	_ = must(c.SBOMLicenses(ctx, s.ID))(t)

	got := must(c.DownloadSBOM(ctx, s.ID))(t)
	if !bytes.Equal(got, f.doc) {
		t.Errorf("download differs from upload (%d vs %d bytes)", len(got), len(f.doc))
	}
	var buf bytes.Buffer
	if n, err := c.DownloadSBOMTo(ctx, s.ID, &buf); err != nil || n != int64(len(f.doc)) {
		t.Errorf("DownloadSBOMTo: n=%d err=%v", n, err)
	}

	page := must(c.ListSBOMs(ctx, &bomhort.SBOMListOptions{ListOptions: bomhort.ListOptions{PageSize: 1}}))(t)
	if page.Total == 0 || len(page.Data) != 1 || page.PageSize != 1 {
		t.Errorf("pagination: %+v", page)
	}
	if p, err := c.ListSBOMs(ctx, &bomhort.SBOMListOptions{Project: project}); err != nil {
		t.Error(err)
	} else if !slices.ContainsFunc(p.Data, func(x bomhort.SBOM) bool { return x.ID == s.ID }) {
		// ?project= is unreleased; older servers ignore it and return everything.
		t.Logf("?project= filter did not return the SBOM (unreleased on this server?)")
	}

	if _, err := c.SBOMDetail(ctx, "00000000-0000-4000-8000-000000000000"); !bomhort.IsNotFound(err) {
		t.Errorf("unknown SBOM detail: want 404, got %v", err)
	}
	if _, err := c.Vulnerabilities(ctx, "not-a-uuid"); !bomhort.IsBadRequest(err) {
		t.Errorf("invalid SBOM id: want 400, got %v", err)
	}
}

func TestDuplicateUpload(t *testing.T) {
	f := setup(t)
	res, err := f.c.UploadSBOM(context.Background(), "again-"+f.filename, f.doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate() || res.SHA256Hash == "" {
		t.Errorf("want duplicate, got %+v", res)
	}
}

func TestPatchSource(t *testing.T) {
	f := setup(t)
	c, ctx := f.c, context.Background()
	res := must(c.PatchSBOMSource(ctx, f.sbom.ID, bomhort.SourcePatch{SourceRef: bomhort.String("v0.6.1-patched")}))(t)
	if res.SBOMID != f.sbom.ID || res.SourceRepo != repo || res.SourceRef != "v0.6.1-patched" {
		t.Errorf("patch result: %+v", res)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		s := must(c.FindSBOM(ctx, f.sbom.ID))(t)
		if s.SourceRef == "v0.6.1-patched" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("patched ref not visible: %+v", s)
		}
		time.Sleep(time.Second)
	}
	if _, err := c.PatchSBOMSource(ctx, f.sbom.ID, bomhort.SourcePatch{SourceRepo: bomhort.String("ftp://nope")}); !bomhort.IsBadRequest(err) {
		t.Errorf("invalid repo: want 400, got %v", err)
	}
}

// distinct returns up to n findings with pairwise different vulnerability
// IDs, so statements about one never affect another.
func distinct(vulns []bomhort.Vulnerability, n int) []bomhort.Vulnerability {
	seen := map[string]bool{}
	var out []bomhort.Vulnerability
	for _, v := range vulns {
		if !seen[v.VulnID] && len(out) < n {
			seen[v.VulnID] = true
			out = append(out, v)
		}
	}
	return out
}

// openVEX builds a one-statement document. With subcomponents it is the
// spec shape (product = the SBOM, subcomponent = the vulnerable package);
// without, the statement covers the product as a whole.
func openVEX(t *testing.T, id, vulnID, product string, subcomponents ...string) []byte {
	ts := time.Now().UTC().Format(time.RFC3339)
	p := map[string]any{"@id": product}
	if len(subcomponents) > 0 {
		var subs []map[string]any
		for _, sc := range subcomponents {
			subs = append(subs, map[string]any{"@id": sc, "identifiers": map[string]any{"purl": sc}})
		}
		p["subcomponents"] = subs
	}
	return must(json.Marshal(map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       "https://bomhort-go.invalid/vex/" + id,
		"author":    "bomhort-go integration",
		"role":      "automation",
		"timestamp": ts,
		"version":   1,
		"tooling":   "bomhort-go/" + bomhort.Version,
		"statements": []map[string]any{{
			"vulnerability":    map[string]any{"name": vulnID},
			"products":         []map[string]any{p},
			"status":           "not_affected",
			"justification":    "vulnerable_code_not_in_execute_path",
			"impact_statement": "integration test",
			"timestamp":        ts,
		}},
	}))(t)
}

// waitVEX polls until every finding selected by want carries not_affected.
func waitVEX(t *testing.T, f *fixture, want func(bomhort.Vulnerability) bool) []bomhort.Vulnerability {
	t.Helper()
	deadline := time.Now().Add(timeout())
	for {
		var hit []bomhort.Vulnerability
		missing := 0
		for _, v := range must(f.c.Vulnerabilities(context.Background(), f.sbom.ID))(t) {
			if !want(v) {
				continue
			}
			if v.VEXStatus == "not_affected" {
				hit = append(hit, v)
			} else {
				missing++
			}
		}
		if len(hit) > 0 && missing == 0 {
			for _, v := range hit {
				if v.VEXScope != "sbom" || v.VEXJustification != "vulnerable_code_not_in_execute_path" || v.VEXStatementID == "" {
					t.Errorf("VEX fields: %+v", v)
				}
			}
			return hit
		}
		if time.Now().After(deadline) {
			t.Fatalf("VEX not applied (%d applied, %d missing)", len(hit), missing)
		}
		time.Sleep(3 * time.Second)
	}
}

func TestVEX(t *testing.T) {
	f := setup(t)
	c, ctx := f.c, context.Background()
	vs := distinct(f.vulns, 3)
	if len(vs) < 3 {
		t.Skipf("need 3 distinct vulnerability IDs, have %d", len(vs))
	}
	base := strings.TrimSuffix(f.filename, ".spdx.json")

	// Explicit scope: ?sbom_id= plus subcomponent → exact (vuln_id, purl).
	t.Run("scoped", func(t *testing.T) {
		v := vs[0]
		res, err := c.UploadVEX(ctx, base+"-scoped.openvex.json", openVEX(t, f.sbom.ID+"/scoped", v.VulnID, f.sbom.DocumentName, v.PURL), f.sbom.ID)
		if err != nil {
			t.Fatal(err)
		}
		if res.JobType != "vex" || res.Status != "pending" {
			t.Fatalf("upload result: %+v", res)
		}
		waitVEX(t, f, func(x bomhort.Vulnerability) bool { return x.VulnID == v.VulnID && x.PURL == v.PURL })
		sts := must(c.SBOMVEXStatements(ctx, f.sbom.ID))(t)
		if !slices.ContainsFunc(sts, func(s bomhort.VEXStatement) bool {
			return s.VulnID == v.VulnID && s.ProductPURL == v.PURL && s.SBOMID == f.sbom.ID && s.Author == "bomhort-go integration"
		}) {
			t.Errorf("statement not listed for SBOM: %+v", sts)
		}
	})

	// No ?sbom_id=: BOMHort resolves the product @id (here the SPDX
	// document name) to the SBOM.
	t.Run("resolved-by-product", func(t *testing.T) {
		v := vs[1]
		if _, err := c.UploadVEX(ctx, base+"-resolved.openvex.json", openVEX(t, f.sbom.ID+"/resolved", v.VulnID, f.sbom.DocumentName, v.PURL), ""); err != nil {
			t.Fatal(err)
		}
		waitVEX(t, f, func(x bomhort.Vulnerability) bool { return x.VulnID == v.VulnID && x.PURL == v.PURL })
	})

	// Product without subcomponents: covers every finding with that ID,
	// stored with product_purl "*".
	t.Run("product-wide", func(t *testing.T) {
		v := vs[2]
		if _, err := c.UploadVEX(ctx, base+"-wide.openvex.json", openVEX(t, f.sbom.ID+"/wide", v.VulnID, f.sbom.DocumentName), f.sbom.ID); err != nil {
			t.Fatal(err)
		}
		waitVEX(t, f, func(x bomhort.Vulnerability) bool { return x.VulnID == v.VulnID })
		sts := must(c.SBOMVEXStatements(ctx, f.sbom.ID))(t)
		if !slices.ContainsFunc(sts, func(s bomhort.VEXStatement) bool { return s.VulnID == v.VulnID && s.ProductPURL == "*" }) {
			t.Errorf("product-wide statement not stored as '*': %+v", sts)
		}
	})

	all := must(c.AllVEXStatements(ctx))(t)
	n := 0
	for _, s := range all {
		if s.SBOMID == f.sbom.ID {
			n++
		}
	}
	if n < 3 {
		t.Errorf("/vex/statements lists %d statements for the SBOM, want >= 3", n)
	}
}

func TestCatalog(t *testing.T) {
	f := setup(t)
	c, v, ctx := f.c, f.vulns[0], context.Background()

	t.Run("dashboard", func(t *testing.T) {
		s := must(c.DashboardStats(ctx))(t)
		if s.TotalSBOMs == 0 || s.TotalVulnerabilities == 0 {
			t.Errorf("empty dashboard: %+v", s)
		}
	})
	t.Run("affected-projects", func(t *testing.T) {
		ap := must(c.AffectedProjects(ctx, v.VulnID))(t)
		if !slices.ContainsFunc(ap, func(a bomhort.AffectedProject) bool { return a.SBOMID == f.sbom.ID }) {
			t.Errorf("%s: fixture SBOM not affected: %+v", v.VulnID, ap)
		}
	})
	t.Run("dependency-stats", func(t *testing.T) { _ = must(c.DependencyStats(ctx, 10))(t) })
	t.Run("version-skew", func(t *testing.T) { _ = must(c.VersionSkew(ctx, nil))(t) })
	t.Run("search", func(t *testing.T) { _ = must(c.Search(ctx, "golang", 5))(t) })
	t.Run("search-packages", func(t *testing.T) { _ = must(c.SearchPackages(ctx, "golang.org/x", nil))(t) })
	t.Run("package-detail", func(t *testing.T) {
		deps := must(c.Dependencies(ctx, f.sbom.ID))(t)
		for _, d := range deps {
			if d.Name != "" && d.PURL != "" {
				_ = must(c.PackageDetail(ctx, d.Name, nil))(t)
				return
			}
		}
		t.Skip("no named dependency")
	})
	t.Run("archived", func(t *testing.T) { _ = must(c.ArchivedPackages(ctx))(t) })
	t.Run("license-compliance", func(t *testing.T) { _ = must(c.LicenseCompliance(ctx))(t) })
	t.Run("license-violations", func(t *testing.T) { _ = must(c.LicenseViolations(ctx))(t) })
	t.Run("license-exceptions", func(t *testing.T) { _ = must(c.LicenseExceptions(ctx))(t) })
	t.Run("license-policy", func(t *testing.T) { _ = must(c.LicensePolicy(ctx))(t) })
	t.Run("vulnerabilities", func(t *testing.T) {
		p := must(c.ListVulnerabilities(ctx, &bomhort.ListOptions{PageSize: 500}))(t)
		if p.Total == 0 {
			t.Error("no vulnerabilities")
		}
	})
}

func TestProjectsAndFleet(t *testing.T) {
	f := setup(t)
	c, ctx := f.c, context.Background()

	t.Run("projects", func(t *testing.T) {
		ps := must(bomhort.Collect(c.Projects(ctx, &bomhort.ProjectListOptions{Search: project})))(t)
		if !slices.ContainsFunc(ps, func(p bomhort.Project) bool { return p.ProjectName == project }) {
			t.Errorf("project %q not listed: %+v", project, ps)
		}
	})
	t.Run("project-groups", func(t *testing.T) {
		// Released servers ignore ?group_by=parent and answer with plain
		// project rows, which strict decoding rejects.
		requireUnreleased(t, c)
		_ = must(c.ListProjectGroups(ctx, nil))(t)
	})
	t.Run("project", func(t *testing.T) {
		p, err := c.Project(ctx, project)
		unreleased(t, err)
		if err != nil {
			t.Fatal(err)
		}
		if p.ProjectName != project {
			t.Errorf("project detail: %+v", p)
		}
	})
	t.Run("project-sboms", func(t *testing.T) {
		p, err := c.ListProjectSBOMs(ctx, project, nil)
		unreleased(t, err)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(p.Data, func(s bomhort.SBOM) bool { return s.ID == f.sbom.ID }) {
			t.Errorf("fixture SBOM not in project: %+v", p)
		}
	})
	t.Run("project-vulnerabilities", func(t *testing.T) {
		vs, err := c.ProjectVulnerabilities(ctx, project)
		unreleased(t, err)
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) == 0 {
			t.Error("no project vulnerabilities")
		}
	})
	t.Run("project-packages", func(t *testing.T) {
		_, err := c.ListProjectPackages(ctx, project, nil)
		unreleased(t, err)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tags", func(t *testing.T) {
		tags := must(c.Tags(ctx))(t)
		if !slices.ContainsFunc(tags, func(x bomhort.Tag) bool { return x.Tag == tag }) {
			t.Errorf("tag %q missing: %+v", tag, tags)
		}
	})
	t.Run("clusters", func(t *testing.T) {
		cs := must(c.Clusters(ctx))(t)
		if !slices.ContainsFunc(cs, func(x bomhort.Cluster) bool { return x.Name == cluster }) {
			t.Errorf("cluster %q missing: %+v", cluster, cs)
		}
		_ = must(c.ClusterStats(ctx, cluster))(t)
		_ = must(c.ListClusterSBOMs(ctx, cluster, nil))(t)
	})
	t.Run("namespaces", func(t *testing.T) {
		ns := must(c.Namespaces(ctx, cluster))(t)
		if !slices.ContainsFunc(ns, func(x bomhort.Namespace) bool { return x.Name == namespace }) {
			t.Errorf("namespace %q missing: %+v", namespace, ns)
		}
		_ = must(c.NamespaceStats(ctx, namespace, cluster))(t)
		_ = must(c.ListNamespaceSBOMs(ctx, namespace, cluster, nil))(t)
	})
	t.Run("fleet", func(t *testing.T) { _ = must(c.Fleet(ctx))(t) })
}
