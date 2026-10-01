package bomhort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestUploadValidation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	doc := []byte(`{}`)

	bad := []struct {
		name string
		run  func() error
	}{
		{"no .json", func() error { _, err := c.Upload(ctx, "sbom.xml", doc, nil); return err }},
		{"empty name", func() error { _, err := c.Upload(ctx, "  ", doc, nil); return err }},
		{"empty body", func() error { _, err := c.Upload(ctx, "a.spdx.json", nil, nil); return err }},
		{"sbom_id on SBOM", func() error { _, err := c.Upload(ctx, "a.spdx.json", doc, &UploadOptions{SBOMID: testID}); return err }},
		{"VEX via UploadSBOM", func() error { _, err := c.UploadSBOM(ctx, "a.openvex.json", doc, nil); return err }},
		{"SBOM via UploadVEX", func() error { _, err := c.UploadVEX(ctx, "a.cdx.json", doc, ""); return err }},
	}
	for _, b := range bad {
		if err := b.run(); err == nil {
			t.Errorf("%s: expected client-side error", b.name)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid uploads must not reach the server, got %d calls", calls.Load())
	}
	for _, ok := range []string{"a.json", "a.spdx.json", "A.CDX.JSON", "x/y/a.vex.json"} {
		if _, err := c.Upload(ctx, ok, doc, nil); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestPatchRequiresAField(t *testing.T) {
	if _, err := New("http://127.0.0.1:1").PatchSBOMSource(context.Background(), testID, SourcePatch{}); err == nil {
		t.Fatal("empty patch must be rejected client-side")
	}
}

// pagedServer serves n SBOMs in pages, honouring page/page_size.
func pagedServer(t *testing.T, n int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		resp := Paginated[SBOM]{Data: []SBOM{}, Total: uint64(n), Page: uint64(page), PageSize: uint64(size)}
		for i := (page - 1) * size; i < min(page*size, n); i++ {
			resp.Data = append(resp.Data, SBOM{ID: fmt.Sprint(i), DocumentName: fmt.Sprint("doc-", i), SourceFile: fmt.Sprint("f-", i)})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestPaginationWalksAllPages(t *testing.T) {
	srv, calls := pagedServer(t, 7)
	c := New(srv.URL)
	all, err := c.AllSBOMs(context.Background(), &SBOMListOptions{ListOptions: ListOptions{PageSize: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 7 || all[6].ID != "6" || calls.Load() != 3 {
		t.Fatalf("got %d items in %d calls", len(all), calls.Load())
	}
}

func TestPaginationEarlyBreakAndEmpty(t *testing.T) {
	srv, calls := pagedServer(t, 1000)
	n := 0
	for s, err := range New(srv.URL).SBOMs(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if n++; s.ID == "150" {
			break
		}
	}
	if n != 151 || calls.Load() != 2 {
		t.Fatalf("early break: %d items, %d calls (default page size %d)", n, calls.Load(), DefaultWalkPageSize)
	}

	empty, emptyCalls := pagedServer(t, 0)
	all, err := New(empty.URL).AllSBOMs(context.Background(), nil)
	if err != nil || len(all) != 0 || emptyCalls.Load() != 1 {
		t.Fatalf("empty: %v %v %d", all, err, emptyCalls.Load())
	}
}

func TestPaginationStopsOnShortPageWithWrongTotal(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data := []VEXStatement{}
		if r.URL.Query().Get("page") == "1" {
			data = append(data, VEXStatement{VulnID: "a"})
		}
		// Total claims more than exists: the walker must stop on the empty page.
		_ = json.NewEncoder(w).Encode(Paginated[VEXStatement]{Data: data, Total: 99})
	}))
	defer srv.Close()
	all, err := New(srv.URL).AllVEXStatements(context.Background())
	if err != nil || len(all) != 1 || calls.Load() != 2 {
		t.Fatalf("%v %v calls=%d", all, err, calls.Load())
	}
}

func TestPaginationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := New(srv.URL).AllSBOMs(context.Background(), nil); StatusCode(err) != 500 {
		t.Fatalf("err = %v", err)
	}
	seq := Paginate(context.Background(), 0, func(context.Context, ListOptions) (Paginated[int], error) {
		return Paginated[int]{}, errors.New("boom")
	})
	if _, err := Collect(seq); err == nil || err.Error() != "boom" {
		t.Fatalf("Collect err = %v", err)
	}
}

func TestProjectsIterator(t *testing.T) {
	var seenTag atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTag.Store(r.URL.Query().Get("tag"))
		_ = json.NewEncoder(w).Encode(Paginated[Project]{Data: []Project{{ProjectName: "a"}, {ProjectName: "b"}}, Total: 2})
	}))
	defer srv.Close()
	all, err := Collect(New(srv.URL).Projects(context.Background(), &ProjectListOptions{Tag: "cncf"}))
	if err != nil || len(all) != 2 || seenTag.Load() != "cncf" {
		t.Fatalf("%v %v %v", all, err, seenTag.Load())
	}
}

func TestFindSBOM(t *testing.T) {
	srv, _ := pagedServer(t, 250)
	c := New(srv.URL)
	ctx := context.Background()
	for _, ref := range []string{"42", "doc-200", "f-249"} {
		s, err := c.FindSBOM(ctx, ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if !(s.ID == ref || s.DocumentName == ref || s.SourceFile == ref) {
			t.Fatalf("%s: got %+v", ref, s)
		}
	}
	if _, err := c.FindSBOM(ctx, "nope"); !IsNotFound(err) {
		t.Fatalf("missing ref: %v", err)
	}
	if _, err := c.FindSBOM(ctx, ""); err == nil {
		t.Fatal("empty ref")
	}
}

func TestFindSBOMUsesSearchFirst(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("search"))
		_ = json.NewEncoder(w).Encode(Paginated[SBOM]{Data: []SBOM{{ID: "x", DocumentName: "app"}}, Total: 1})
	}))
	defer srv.Close()
	if _, err := New(srv.URL).FindSBOM(context.Background(), "app"); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || queries[0] != "app" {
		t.Fatalf("expected one ?search=app call, got %q", queries)
	}
}

func TestDownloadSBOMTo(t *testing.T) {
	doc := strings.Repeat(`{"spdxVersion":"SPDX-2.3"}`, 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"Authentication required"}`)
			return
		}
		if r.URL.Path != "/api/v1/sboms/"+testID+"/download" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"SBOM not found"}`)
			return
		}
		_, _ = io.WriteString(w, doc)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	n, err := New(srv.URL, WithAPIKey("k")).DownloadSBOMTo(context.Background(), testID, &buf)
	if err != nil || n != int64(len(doc)) || buf.String() != doc {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := New(srv.URL).DownloadSBOMTo(context.Background(), testID, io.Discard); !IsUnauthorized(err) {
		t.Fatalf("err = %v", err)
	}
	if _, err := New(srv.URL, WithAPIKey("k")).DownloadSBOMTo(context.Background(), "other", io.Discard); !IsNotFound(err) {
		t.Fatalf("err = %v", err)
	}
}
