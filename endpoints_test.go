package bomhort

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const testID = "11111111-2222-3333-4444-555555555555"

// TestEndpointContract pins the wire format of every endpoint: method,
// escaped path, query string, request headers/body and response decoding.
// It is the unit-level counterpart of the integration tests against a real
// BOMHort.
func TestEndpointContract(t *testing.T) {
	type call func(c *Client, ctx context.Context) (any, error)
	cases := []struct {
		name    string
		call    call
		method  string
		path    string // escaped
		query   string // url.Values.Encode() form
		headers map[string]string
		body    string // expected request body
		resp    string
		want    any
	}{
		{"Healthy", func(c *Client, ctx context.Context) (any, error) { return nil, c.Healthy(ctx) },
			"GET", "/healthz", "", nil, "", `{"status":"ok"}`, nil},
		{"Live", func(c *Client, ctx context.Context) (any, error) { return nil, c.Live(ctx) },
			"GET", "/livez", "", nil, "", `{"status":"ok"}`, nil},
		{"Ready", func(c *Client, ctx context.Context) (any, error) { return nil, c.Ready(ctx) },
			"GET", "/readyz", "", nil, "", `{"status":"ok"}`, nil},
		{"ListSBOMs nil", func(c *Client, ctx context.Context) (any, error) { return c.ListSBOMs(ctx, nil) },
			"GET", "/api/v1/sboms", "", nil, "", `{"data":[{"sbom_id":"a","project":"p","source_repo":"https://github.com/o/r"}],"total":1,"page":1,"page_size":50}`,
			Paginated[SBOM]{Data: []SBOM{{ID: "a", Project: "p", SourceRepo: "https://github.com/o/r"}}, Total: 1, Page: 1, PageSize: 50}},
		{"ListSBOMs opts", func(c *Client, ctx context.Context) (any, error) {
			return c.ListSBOMs(ctx, &SBOMListOptions{ListOptions: ListOptions{Page: 2, PageSize: 10}, Search: "argo cd", Project: "argo/cd"})
		}, "GET", "/api/v1/sboms", "page=2&page_size=10&project=argo%2Fcd&search=argo+cd", nil, "", `{"data":[],"total":0}`,
			Paginated[SBOM]{Data: []SBOM{}}},
		{"SBOMDetail", func(c *Client, ctx context.Context) (any, error) { return c.SBOMDetail(ctx, testID) },
			"GET", "/api/v1/sboms/" + testID + "/detail", "", nil, "", `{"sbom_id":"x","critical_vulns":2}`,
			SBOMDetail{ID: "x", CriticalVulns: 2}},
		{"Vulnerabilities", func(c *Client, ctx context.Context) (any, error) { return c.Vulnerabilities(ctx, testID) },
			"GET", "/api/v1/sboms/" + testID + "/vulnerabilities", "", nil, "",
			`[{"vuln_id":"GHSA-1","purl":"pkg:golang/x@v1","vex_status":"not_affected","vex_scope":"sbom","vex_timestamp":"2026-01-01T00:00:00Z"}]`,
			[]Vulnerability{{VulnID: "GHSA-1", PURL: "pkg:golang/x@v1", VEXStatus: "not_affected", VEXScope: "sbom", VEXTimestamp: "2026-01-01T00:00:00Z"}}},
		{"Dependencies", func(c *Client, ctx context.Context) (any, error) { return c.Dependencies(ctx, testID) },
			"GET", "/api/v1/sboms/" + testID + "/dependencies", "", nil, "", `[{"index":0,"name":"root","children":[1]},{"index":1,"name":"dep"}]`,
			[]DependencyNode{{Index: 0, Name: "root", Children: []uint32{1}}, {Index: 1, Name: "dep"}}},
		{"SBOMLicenses", func(c *Client, ctx context.Context) (any, error) { return c.SBOMLicenses(ctx, testID) },
			"GET", "/api/v1/sboms/" + testID + "/licenses", "", nil, "", `[{"license_id":"MIT","category":"permissive","package_count":3,"packages":["a"]}]`,
			[]SBOMLicense{{LicenseID: "MIT", Category: "permissive", PackageCount: 3, Packages: []string{"a"}}}},
		{"SBOMVEXStatements", func(c *Client, ctx context.Context) (any, error) { return c.SBOMVEXStatements(ctx, testID) },
			"GET", "/api/v1/sboms/" + testID + "/vex", "", nil, "", `[{"vex_id":"v","sbom_id":"s","status":"fixed","affected_sboms":[{"sbom_id":"s","document_name":"d"}]}]`,
			[]VEXStatement{{VEXID: "v", SBOMID: "s", Status: "fixed", AffectedSBOMs: []SBOMLink{{SBOMID: "s", DocumentName: "d"}}}}},
		{"DownloadSBOM", func(c *Client, ctx context.Context) (any, error) {
			b, err := c.DownloadSBOM(ctx, testID)
			return string(b), err
		}, "GET", "/api/v1/sboms/" + testID + "/download", "", nil, "", `{"spdxVersion":"SPDX-2.3"}`, `{"spdxVersion":"SPDX-2.3"}`},
		{"PatchSBOMSource", func(c *Client, ctx context.Context) (any, error) {
			return c.PatchSBOMSource(ctx, testID, SourcePatch{SourceRepo: String("https://github.com/o/r"), SourceRef: String("")})
		}, "PATCH", "/api/v1/sboms/" + testID, "", map[string]string{"Content-Type": "application/json"},
			`{"source_repo":"https://github.com/o/r","source_ref":""}`, `{"sbom_id":"x","source_repo":"https://github.com/o/r","source_ref":""}`,
			SourceAttribution{SBOMID: "x", SourceRepo: "https://github.com/o/r"}},
		{"Upload SBOM with options", func(c *Client, ctx context.Context) (any, error) {
			return c.UploadSBOM(ctx, "dir/app.spdx.json", []byte(`{"spdxVersion":"SPDX-2.3"}`), &UploadOptions{
				Cluster: "prod", Namespace: "pay", Project: "app", Parent: "suite", Tags: []string{"cncf", "sandbox"},
				SourceRepo: "https://github.com/o/app", SourceRef: "v1.2.3",
			})
		}, "POST", "/api/v1/sboms/upload", "cluster=prod&namespace=pay&parent=suite&project=app&tags=cncf%2Csandbox",
			map[string]string{"X-Filename": "app.spdx.json", "Content-Type": "application/json", "X-Source-Repo": "https://github.com/o/app", "X-Source-Ref": "v1.2.3"},
			`{"spdxVersion":"SPDX-2.3"}`, `{"status":"pending","job_id":"j","sha256_hash":"h","job_type":"sbom","cluster":"prod","namespace":"pay","project":"app","parent":"suite"}`,
			UploadResult{Status: "pending", JobID: "j", SHA256Hash: "h", JobType: "sbom", Cluster: "prod", Namespace: "pay", Project: "app", Parent: "suite"}},
		{"UploadVEX scoped", func(c *Client, ctx context.Context) (any, error) {
			return c.UploadVEX(ctx, "app.openvex.json", []byte(`{"statements":[]}`), testID)
		}, "POST", "/api/v1/sboms/upload", "sbom_id=" + testID, map[string]string{"X-Filename": "app.openvex.json"},
			`{"statements":[]}`, `{"status":"pending","job_id":"j","sha256_hash":"h","job_type":"vex"}`,
			UploadResult{Status: "pending", JobID: "j", SHA256Hash: "h", JobType: "vex"}},
		{"UploadVEX global", func(c *Client, ctx context.Context) (any, error) {
			return c.UploadVEX(ctx, "APP.VEX.JSON", []byte(`{}`), "")
		}, "POST", "/api/v1/sboms/upload", "", map[string]string{"X-Filename": "APP.VEX.JSON"}, `{}`, `{"status":"duplicate","sha256_hash":"h"}`,
			UploadResult{Status: "duplicate", SHA256Hash: "h"}},
		{"ListVEXStatements", func(c *Client, ctx context.Context) (any, error) {
			return c.ListVEXStatements(ctx, &ListOptions{Page: 3, PageSize: 500})
		}, "GET", "/api/v1/vex/statements", "page=3&page_size=500", nil, "", `{"data":[{"vuln_id":"CVE-1","author":"a","role":"r","tooling":"t","status_notes":"n"}],"total":201,"page":3,"page_size":500}`,
			Paginated[VEXStatement]{Data: []VEXStatement{{VulnID: "CVE-1", Author: "a", Role: "r", Tooling: "t", StatusNotes: "n"}}, Total: 201, Page: 3, PageSize: 500}},
		{"ListVulnerabilities", func(c *Client, ctx context.Context) (any, error) { return c.ListVulnerabilities(ctx, nil) },
			"GET", "/api/v1/vulnerabilities", "", nil, "", `{"data":[{"vuln_id":"CVE-1"}],"total":1}`,
			Paginated[Vulnerability]{Data: []Vulnerability{{VulnID: "CVE-1"}}, Total: 1}},
		{"AffectedProjects", func(c *Client, ctx context.Context) (any, error) {
			return c.AffectedProjects(ctx, "GHSA-abcd-efgh-ijkl")
		},
			"GET", "/api/v1/vulnerabilities/GHSA-abcd-efgh-ijkl/affected-projects", "", nil, "", `[{"sbom_id":"s","is_direct":true}]`,
			[]AffectedProject{{SBOMID: "s", IsDirect: true}}},
		{"DashboardStats", func(c *Client, ctx context.Context) (any, error) { return c.DashboardStats(ctx) },
			"GET", "/api/v1/stats/dashboard", "", nil, "", `{"total_sboms":3,"license_breakdown":{"permissive":2}}`,
			DashboardStats{TotalSBOMs: 3, LicenseBreakdown: map[string]uint64{"permissive": 2}}},
		{"DependencyStats", func(c *Client, ctx context.Context) (any, error) { return c.DependencyStats(ctx, 20) },
			"GET", "/api/v1/stats/dependencies", "limit=20", nil, "", `{"total_unique_deps":9,"top_dependencies":[{"package_name":"x","versions":["1"]}]}`,
			DependencyStats{TotalUniqueDeps: 9, TopDependencies: []DependencyStat{{PackageName: "x", Versions: []string{"1"}}}}},
		{"VersionSkew", func(c *Client, ctx context.Context) (any, error) {
			return c.VersionSkew(ctx, &SearchListOptions{ListOptions: ListOptions{PageSize: 5}, Search: "net"})
		}, "GET", "/api/v1/stats/version-skew", "page_size=5&search=net", nil, "",
			`{"total_skewed_packages":1,"items":[{"package_name":"net","versions":[{"version":"1","projects":["a"]}]}],"page":1,"page_size":5}`,
			VersionSkew{TotalSkewedPackages: 1, Items: []VersionSkewItem{{PackageName: "net", Versions: []VersionSkewDetail{{Version: "1", Projects: []string{"a"}}}}}, Page: 1, PageSize: 5}},
		{"Search", func(c *Client, ctx context.Context) (any, error) { return c.Search(ctx, "log4j", 10) },
			"GET", "/api/v1/search", "limit=10&q=log4j", nil, "", `{"query":"log4j","packages":[{"package_name":"log4j"}],"total_packages":1}`,
			SearchResult{Query: "log4j", Packages: []SearchPackage{{PackageName: "log4j"}}, TotalPackages: 1}},
		{"SearchPackages", func(c *Client, ctx context.Context) (any, error) { return c.SearchPackages(ctx, "x/net", nil) },
			"GET", "/api/v1/packages/search", "q=x%2Fnet", nil, "", `{"total_results":1,"items":[{"package_name":"x/net","projects":[{"project_name":"p"}]}],"query":"x/net"}`,
			PackageSearch{TotalResults: 1, Items: []PackageSearchResult{{PackageName: "x/net", Projects: []PackageProject{{ProjectName: "p"}}}}, Query: "x/net"}},
		{"PackageDetail", func(c *Client, ctx context.Context) (any, error) {
			return c.PackageDetail(ctx, "golang.org/x/net", &ListOptions{Page: 2})
		}, "GET", "/api/v1/packages/detail", "name=golang.org%2Fx%2Fnet&page=2", nil, "", `{"package_name":"golang.org/x/net","total_projects":4}`,
			PackageDetail{PackageName: "golang.org/x/net", TotalProjects: 4}},
		{"ArchivedPackages", func(c *Client, ctx context.Context) (any, error) { return c.ArchivedPackages(ctx) },
			"GET", "/api/v1/packages/archived", "", nil, "", `[{"package_name":"old","stars":5,"last_pushed":"2020-01-02T03:04:05Z"}]`,
			[]ArchivedPackage{{PackageName: "old", Stars: 5, LastPushed: mustTime("2020-01-02T03:04:05Z")}}},
		{"LicenseCompliance", func(c *Client, ctx context.Context) (any, error) { return c.LicenseCompliance(ctx) },
			"GET", "/api/v1/licenses/compliance", "", nil, "", `[{"license_id":"GPL-3.0","category":"copyleft","sbom_count":2}]`,
			[]LicenseCompliance{{LicenseID: "GPL-3.0", Category: "copyleft", SBOMCount: 2}}},
		{"LicenseViolations", func(c *Client, ctx context.Context) (any, error) { return c.LicenseViolations(ctx) },
			"GET", "/api/v1/projects/license-compliance", "", nil, "", `[{"sbom_id":"s","copyleft_count":1,"violating_licenses":["GPL-3.0"]}]`,
			[]LicenseViolation{{SBOMID: "s", CopyleftCount: 1, ViolatingLicenses: []string{"GPL-3.0"}}}},
		{"LicenseExceptions", func(c *Client, ctx context.Context) (any, error) { return c.LicenseExceptions(ctx) },
			"GET", "/api/v1/license-exceptions", "", nil, "", `{"version":"1.0.0","blanketExceptions":[{"id":"b","license":"MPL-2.0"}],"exceptions":[{"id":"e","package":"p","license":"GPL"}]}`,
			LicenseExceptions{Version: "1.0.0", BlanketExceptions: []BlanketLicenseException{{ID: "b", License: "MPL-2.0"}}, Exceptions: []LicenseException{{ID: "e", Package: "p", License: "GPL"}}}},
		{"LicensePolicy", func(c *Client, ctx context.Context) (any, error) { return c.LicensePolicy(ctx) },
			"GET", "/api/v1/license-policy", "", nil, "", `{"permissive":["MIT"],"copyleft":["GPL-3.0"],"expressionMode":"strict"}`,
			LicensePolicy{Permissive: []string{"MIT"}, Copyleft: []string{"GPL-3.0"}, ExpressionMode: "strict"}},
		{"ListProjects", func(c *Client, ctx context.Context) (any, error) {
			return c.ListProjects(ctx, &ProjectListOptions{Search: "argo", Tag: "cncf"})
		}, "GET", "/api/v1/projects", "search=argo&tag=cncf", nil, "", `{"data":[{"project_name":"argo","tags":["cncf"],"parent":"argoproj","parent_source":"repo"}],"total":1}`,
			Paginated[Project]{Data: []Project{{ProjectName: "argo", Tags: []string{"cncf"}, Parent: "argoproj", ParentSource: "repo"}}, Total: 1}},
		{"ListProjectGroups", func(c *Client, ctx context.Context) (any, error) { return c.ListProjectGroups(ctx, nil) },
			"GET", "/api/v1/projects", "group_by=parent", nil, "", `{"data":[{"name":"argoproj","project_count":2,"members":[{"project_name":"argo-cd"}]}],"total":1}`,
			Paginated[ProjectGroup]{Data: []ProjectGroup{{Name: "argoproj", ProjectCount: 2, Members: []Project{{ProjectName: "argo-cd"}}}}, Total: 1}},
		{"Project with slash", func(c *Client, ctx context.Context) (any, error) { return c.Project(ctx, "org/proj") },
			"GET", "/api/v1/projects/org%2Fproj", "", nil, "", `{"project_name":"org/proj","children":["c"]}`,
			ProjectDetail{ProjectName: "org/proj", Children: []string{"c"}}},
		{"ListProjectSBOMs", func(c *Client, ctx context.Context) (any, error) {
			return c.ListProjectSBOMs(ctx, "p q", &ListOptions{PageSize: 2})
		}, "GET", "/api/v1/projects/p%20q/sboms", "page_size=2", nil, "", `{"data":[{"sbom_id":"a"}],"total":1}`,
			Paginated[SBOM]{Data: []SBOM{{ID: "a"}}, Total: 1}},
		{"ProjectVulnerabilities", func(c *Client, ctx context.Context) (any, error) { return c.ProjectVulnerabilities(ctx, "p") },
			"GET", "/api/v1/projects/p/vulnerabilities", "", nil, "", `[{"vuln_id":"CVE-1","affected_sboms":3}]`,
			[]Vulnerability{{VulnID: "CVE-1", AffectedSBOMs: 3}}},
		{"ListProjectPackages", func(c *Client, ctx context.Context) (any, error) {
			return c.ListProjectPackages(ctx, "p", &SearchListOptions{Search: "yaml"})
		}, "GET", "/api/v1/projects/p/packages", "search=yaml", nil, "", `{"data":[{"name":"yaml","sbom_count":10}],"total":1}`,
			Paginated[ProjectPackage]{Data: []ProjectPackage{{Name: "yaml", SBOMCount: 10}}, Total: 1}},
		{"Tags", func(c *Client, ctx context.Context) (any, error) { return c.Tags(ctx) },
			"GET", "/api/v1/tags", "", nil, "", `[{"tag":"cncf","sbom_count":3,"project_count":2,"is_project":true}]`,
			[]Tag{{Tag: "cncf", SBOMCount: 3, ProjectCount: 2, IsProject: true}}},
		{"Clusters", func(c *Client, ctx context.Context) (any, error) { return c.Clusters(ctx) },
			"GET", "/api/v1/clusters", "", nil, "", `[{"name":"prod","sbom_count":1}]`, []Cluster{{Name: "prod", SBOMCount: 1}}},
		{"ClusterStats", func(c *Client, ctx context.Context) (any, error) { return c.ClusterStats(ctx, "prod-eu") },
			"GET", "/api/v1/clusters/prod-eu/stats", "", nil, "", `{"cluster":"prod-eu","total_sboms":4}`, ClusterStats{Cluster: "prod-eu", TotalSBOMs: 4}},
		{"ListClusterSBOMs", func(c *Client, ctx context.Context) (any, error) {
			return c.ListClusterSBOMs(ctx, "prod", &ListOptions{Page: 1, PageSize: 1})
		}, "GET", "/api/v1/clusters/prod/sboms", "page=1&page_size=1", nil, "", `{"data":[],"total":0}`, Paginated[SBOM]{Data: []SBOM{}}},
		{"Namespaces filtered", func(c *Client, ctx context.Context) (any, error) { return c.Namespaces(ctx, "prod") },
			"GET", "/api/v1/namespaces", "cluster=prod", nil, "", `[{"name":"pay","cluster":"prod","cluster_count":1}]`,
			[]Namespace{{Name: "pay", Cluster: "prod", ClusterCount: 1}}},
		{"Namespaces fleet-wide", func(c *Client, ctx context.Context) (any, error) { return c.Namespaces(ctx, "") },
			"GET", "/api/v1/namespaces", "", nil, "", `[]`, []Namespace{}},
		{"NamespaceStats", func(c *Client, ctx context.Context) (any, error) { return c.NamespaceStats(ctx, "pay", "prod") },
			"GET", "/api/v1/namespaces/pay/stats", "cluster=prod", nil, "", `{"namespace":"pay","clusters":["prod"]}`,
			NamespaceStats{Namespace: "pay", Clusters: []string{"prod"}}},
		{"ListNamespaceSBOMs", func(c *Client, ctx context.Context) (any, error) {
			return c.ListNamespaceSBOMs(ctx, "pay", "", &ListOptions{Page: 2})
		}, "GET", "/api/v1/namespaces/pay/sboms", "page=2", nil, "", `{"data":[{"sbom_id":"a","namespace":"pay"}],"total":3}`,
			Paginated[SBOM]{Data: []SBOM{{ID: "a", Namespace: "pay"}}, Total: 3}},
		{"Fleet", func(c *Client, ctx context.Context) (any, error) { return c.Fleet(ctx) },
			"GET", "/api/v1/fleet", "", nil, "", `[{"name":"prod","namespaces":[{"name":"pay","projects":[{"name":"app"}]}]}]`,
			[]FleetCluster{{Name: "prod", Namespaces: []FleetNamespace{{Name: "pay", Projects: []FleetProject{{Name: "app"}}}}}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath, gotQuery, gotBody string
			var gotHeader http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath, gotQuery, gotHeader = r.Method, r.URL.EscapedPath(), r.URL.Query().Encode(), r.Header.Clone()
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				_, _ = io.WriteString(w, tc.resp)
			}))
			defer srv.Close()

			got, err := tc.call(New(srv.URL), context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if gotMethod != tc.method || gotPath != tc.path || gotQuery != tc.query {
				t.Errorf("request = %s %s ?%s, want %s %s ?%s", gotMethod, gotPath, gotQuery, tc.method, tc.path, tc.query)
			}
			for k, v := range tc.headers {
				if gotHeader.Get(k) != v {
					t.Errorf("header %s = %q, want %q", k, gotHeader.Get(k), v)
				}
			}
			if gotBody != tc.body {
				t.Errorf("body = %s, want %s", gotBody, tc.body)
			}
			if tc.want != nil && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("decoded\n got %#v\nwant %#v", got, tc.want)
			}
		})
	}
}
