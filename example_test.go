package bomhort_test

import (
	"context"
	"fmt"
	"log"
	"time"

	bomhort "github.com/seebom-labs/bomhort-go"
	"github.com/seebom-labs/bomhort-go/bomhorttest"
)

// fakeGateway starts a bomhorttest server with one SBOM so the examples
// run without a real BOMHort.
func fakeGateway() *bomhorttest.Server {
	srv := bomhorttest.New("example-key")
	srv.AddSBOM(
		bomhort.SBOM{ID: bomhorttest.UUID(1), DocumentName: "payments-api", SourceFile: "payments-api.spdx.json", Project: "payments"},
		[]bomhort.Vulnerability{
			{VulnID: "GHSA-qppj-fm5r-hxr3", Severity: "HIGH", PURL: "pkg:golang/golang.org/x/net@v0.17.0", FixedVersion: "0.23.0"},
		},
		nil, nil,
	)
	return srv
}

func Example() {
	srv := fakeGateway()
	defer srv.Close()

	c := bomhort.New(srv.URL,
		bomhort.WithAPIKey("example-key"),
		bomhort.WithRateLimit(90, 10*time.Second),
	)
	ctx := context.Background()

	for sbom, err := range c.SBOMs(ctx, nil) {
		if err != nil {
			log.Fatal(err)
		}
		vulns, err := c.Vulnerabilities(ctx, sbom.ID)
		if err != nil {
			log.Fatal(err)
		}
		for _, v := range vulns {
			fmt.Printf("%s: %s %s in %s\n", sbom.DocumentName, v.Severity, v.VulnID, v.PURL)
		}
	}
	// Output:
	// payments-api: HIGH GHSA-qppj-fm5r-hxr3 in pkg:golang/golang.org/x/net@v0.17.0
}

func ExampleClient_UploadVEX() {
	srv := fakeGateway()
	defer srv.Close()
	c := bomhort.New(srv.URL, bomhort.WithAPIKey("example-key"))
	ctx := context.Background()

	sbom, err := c.FindSBOM(ctx, "payments-api")
	if err != nil {
		log.Fatal(err)
	}
	// The product is the SBOM (scoped explicitly via sbom_id); the
	// subcomponent is the vulnerable package. vulnerability.name and the
	// subcomponent purl must be copied verbatim from the finding: BOMHort
	// matches them by exact string equality.
	doc := []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "https://example.com/vex/payments-api-1",
	  "author": "security@example.com",
	  "timestamp": "2026-01-01T00:00:00Z",
	  "version": 1,
	  "statements": [{
	    "vulnerability": {"name": "GHSA-qppj-fm5r-hxr3"},
	    "products": [{
	      "@id": "payments-api",
	      "subcomponents": [{"@id": "pkg:golang/golang.org/x/net@v0.17.0"}]
	    }],
	    "status": "not_affected",
	    "justification": "vulnerable_code_not_in_execute_path"
	  }]
	}`)
	res, err := c.UploadVEX(ctx, "payments-api.openvex.json", doc, sbom.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("upload:", res.Status, res.JobType)

	vulns, _ := c.Vulnerabilities(ctx, sbom.ID)
	fmt.Println("vex_status:", vulns[0].VEXStatus, "scope:", vulns[0].VEXScope)
	// Output:
	// upload: pending vex
	// vex_status: not_affected scope: sbom
}

func ExampleClient_UploadSBOM() {
	srv := fakeGateway()
	defer srv.Close()
	c := bomhort.New(srv.URL, bomhort.WithAPIKey("example-key"))

	doc := []byte(`{"spdxVersion":"SPDX-2.3","name":"checkout","packages":[]}`)
	res, err := c.UploadSBOM(context.Background(), "checkout.spdx.json", doc, &bomhort.UploadOptions{
		Project:    "checkout",
		Tags:       []string{"payments"},
		SourceRepo: "https://github.com/example/checkout",
		SourceRef:  "v1.4.0",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Status, res.JobType, res.Project)
	// Output: pending sbom checkout
}

func ExampleIsNotFound() {
	srv := fakeGateway()
	defer srv.Close()
	c := bomhort.New(srv.URL, bomhort.WithAPIKey("example-key"))

	_, err := c.SBOMDetail(context.Background(), bomhorttest.UUID(404))
	fmt.Println(bomhort.IsNotFound(err))
	// Output: true
}

func ExamplePaginate() {
	srv := fakeGateway()
	defer srv.Close()
	c := bomhort.New(srv.URL, bomhort.WithAPIKey("example-key"))
	ctx := context.Background()

	// Any List* call can be turned into a lazy sequence.
	pages := bomhort.Paginate(ctx, 200, func(ctx context.Context, o bomhort.ListOptions) (bomhort.Paginated[bomhort.SBOM], error) {
		return c.ListSBOMs(ctx, &bomhort.SBOMListOptions{ListOptions: o, Project: "payments"})
	})
	sboms, err := bomhort.Collect(pages)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(sboms), sboms[0].DocumentName)
	// Output: 1 payments-api
}
