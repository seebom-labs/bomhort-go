// Package bomhorttest provides an in-memory fake of the BOMHort API gateway
// for tests of code that talks to BOMHort through bomhort.Client.
//
// The fake mimics the parts of BOMHort that clients observe: authentication
// (X-API-Key / Bearer service token, public health probes), pagination,
// ?search= / ?project= filters, the push-model upload with duplicate
// detection, VEX ingestion with BOMHort's scoping and matching rules (see
// the Server type), and the source-attribution PATCH. Endpoints
// without built-in behaviour can be served with canned JSON via Handle.
//
//	srv := bomhorttest.New("test-key")
//	defer srv.Close()
//	srv.AddSBOM(bomhort.SBOM{ID: bomhorttest.UUID(1), DocumentName: "app"}, vulns, deps, raw)
//	c := bomhort.New(srv.URL, bomhort.WithAPIKey("test-key"))
package bomhorttest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	bomhort "github.com/seebom-labs/bomhort-go"
)

// Upload is one accepted POST /api/v1/sboms/upload.
type Upload struct {
	Filename string
	Body     []byte
	// SBOMID is the ?sbom_id= scope of a VEX upload ("" = resolve the
	// product ref).
	SBOMID string
	// Query holds the remaining query parameters (cluster, project, tags, …).
	Query map[string]string
	// SourceRepo / SourceRef are the X-Source-Repo / X-Source-Ref headers.
	SourceRepo string
	SourceRef  string
	Result     bomhort.UploadResult
}

// Server is a fake BOMHort api-gateway. Set the exported fields before the
// first request; afterwards use the (concurrency-safe) methods.
//
// VEX follows BOMHort >= 0.7 (#335, #350):
//
//   - Every statement is scoped to one SBOM. An upload with ?sbom_id= scopes
//     all its statements to that SBOM; otherwise each product @id (or its
//     identifiers.purl) is resolved against the SBOMs' id, source_repo
//     (normalised) and document_name. Statements whose product resolves to
//     nothing are stored unscoped and suppress nothing until an SBOM that
//     matches is added later (BOMHort's "rescue" pass).
//   - A product with subcomponents yields one statement per subcomponent
//     purl. A product without subcomponents is product-wide once scoped: its
//     product_purl becomes "*" and it covers every finding with that
//     vulnerability ID in the SBOM.
//   - A finding (vuln_id, purl) takes the newest statement (by timestamp) of
//     its SBOM whose vuln_id is equal and whose product_purl is equal or
//     "*". Matching is plain string equality; URL vulnerability names are
//     reduced to their last path segment as BOMHort does.
type Server struct {
	*httptest.Server

	// APIKey enables authentication when non-empty. Like BOMHort with
	// AUTH_ENABLED=false, an empty key makes write endpoints answer 403.
	APIKey string
	// ServiceToken is accepted as "Authorization: Bearer <token>" or
	// X-Service-Token when non-empty.
	ServiceToken string
	// ApplyUploads turns uploaded OpenVEX documents into statements and
	// updates matching findings (default true), like BOMHort's worker.
	ApplyUploads bool
	// IngestUploads registers uploaded SBOM documents as new SBOMs without
	// findings (default true).
	IngestUploads bool

	mu         sync.Mutex
	ready      bool
	sboms      []bomhort.SBOM
	vulns      map[string][]bomhort.Vulnerability
	deps       map[string][]bomhort.DependencyNode
	raw        map[string][]byte
	licenses   map[string][]bomhort.SBOMLicense
	statements []stored
	uploads    []Upload
	hashes     map[string]bool
	canned     map[string]canned
	requests   []string
}

// stored is a VEX statement plus the ingest-time data BOMHort keeps to
// re-resolve unscoped statements.
type stored struct {
	bomhort.VEXStatement
	ref  string // product @id / purl as written in the document
	wide bool   // product without subcomponents
}

type canned struct {
	status int
	body   any
}

// New starts the fake. apiKey "" disables authentication (and writes).
func New(apiKey string) *Server {
	s := &Server{
		APIKey:        apiKey,
		ApplyUploads:  true,
		IngestUploads: true,
		ready:         true,
		vulns:         map[string][]bomhort.Vulnerability{},
		deps:          map[string][]bomhort.DependencyNode{},
		raw:           map[string][]byte{},
		licenses:      map[string][]bomhort.SBOMLicense{},
		hashes:        map[string]bool{},
		canned:        map[string]canned{},
	}
	mux := http.NewServeMux()
	health := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, bomhort.Health{Status: "ok"})
	}
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /livez", health)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /api/v1/sboms", s.auth(s.listSBOMs))
	mux.HandleFunc("GET /api/v1/sboms/{id}/detail", s.auth(s.detail))
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", s.auth(s.sbomVulns))
	mux.HandleFunc("GET /api/v1/sboms/{id}/dependencies", s.auth(s.sbomDeps))
	mux.HandleFunc("GET /api/v1/sboms/{id}/licenses", s.auth(s.sbomLicenses))
	mux.HandleFunc("GET /api/v1/sboms/{id}/vex", s.auth(s.sbomVEX))
	mux.HandleFunc("GET /api/v1/sboms/{id}/download", s.auth(s.download))
	mux.HandleFunc("PATCH /api/v1/sboms/{id}", s.auth(s.patchSource))
	mux.HandleFunc("GET /api/v1/vex/statements", s.auth(s.listStatements))
	mux.HandleFunc("POST /api/v1/sboms/upload", s.auth(s.upload))
	mux.HandleFunc("/", s.auth(s.cannedHandler))
	s.Server = httptest.NewServer(s.record(mux))
	return s
}

// UUID returns a deterministic, valid UUID for test fixtures, e.g.
// UUID(1) == "00000000-0000-4000-8000-000000000001".
func UUID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// AddSBOM registers an SBOM with its findings, dependency tree and raw
// document. VulnCount is derived from vulns; an empty ID gets a random UUID.
func (s *Server) AddSBOM(sb bomhort.SBOM, vulns []bomhort.Vulnerability, deps []bomhort.DependencyNode, raw []byte) bomhort.SBOM {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sb.ID == "" {
		sb.ID = randomUUID()
	}
	if sb.IngestedAt == "" {
		sb.IngestedAt = now()
	}
	sb.VulnCount = uint64(len(vulns))
	sb.PackageCount = max(sb.PackageCount, uint64(len(deps)))
	s.sboms = append(s.sboms, sb)
	s.vulns[sb.ID] = vulns
	s.deps[sb.ID] = deps
	s.raw[sb.ID] = raw
	s.rescue()
	return sb
}

// SetLicenses sets the license breakdown served for an SBOM.
func (s *Server) SetLicenses(sbomID string, l []bomhort.SBOMLicense) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.licenses[sbomID] = l
}

// AddStatement stores an already-ingested VEX statement as is. It only
// affects findings of st.SBOMID; use ProductPURL "*" for a product-wide
// statement. An empty VEXID gets a random UUID.
func (s *Server) AddStatement(st bomhort.VEXStatement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.VEXID == "" {
		st.VEXID = randomUUID()
	}
	s.statements = append(s.statements, stored{VEXStatement: st, ref: st.ProductPURL, wide: st.ProductPURL == "*"})
}

// SetReady toggles /readyz between 200 and 503.
func (s *Server) SetReady(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ok
}

// Handle serves v as JSON with status for "METHOD /path" (exact path, no
// query), e.g. Handle("GET /api/v1/fleet", 200, []bomhort.FleetCluster{…}).
// It covers endpoints without built-in behaviour and overrides nothing
// that is built in.
func (s *Server) Handle(pattern string, status int, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canned[pattern] = canned{status: status, body: v}
}

// SBOMs returns a copy of the registered SBOMs.
func (s *Server) SBOMs() []bomhort.SBOM {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bomhort.SBOM(nil), s.sboms...)
}

// Snapshot returns copies of the accepted uploads and stored statements.
func (s *Server) Snapshot() ([]Upload, []bomhort.VEXStatement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Upload(nil), s.uploads...), s.allStatements()
}

// Requests returns "METHOD /path?query" for every request received.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authEnabled() bool { return s.APIKey != "" || s.ServiceToken != "" }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() {
			next(w, r)
			return
		}
		var presented string
		switch {
		case strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "):
			presented = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		case r.Header.Get("X-Service-Token") != "":
			presented = r.Header.Get("X-Service-Token")
		default:
			presented = r.Header.Get("X-API-Key")
		}
		switch {
		case presented == "":
			writeError(w, http.StatusUnauthorized, "Authentication required")
		case presented == s.APIKey && s.APIKey != "", presented == s.ServiceToken && s.ServiceToken != "":
			next(w, r)
		default:
			writeError(w, http.StatusUnauthorized, "Invalid credentials")
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	ok := s.ready
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, bomhort.Health{Status: "unavailable", Reason: "clickhouse"})
		return
	}
	writeJSON(w, http.StatusOK, bomhort.Health{Status: "ok"})
}

// page mirrors BOMHort's parseUint64/clampPageSize (default 50, max 500).
func page[T any](r *http.Request, all []T) bomhort.Paginated[T] {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if p < 1 {
		p = 1
	}
	if size < 1 {
		size = 50
	}
	size = min(size, 500)
	start := min((p-1)*size, len(all))
	end := min(start+size, len(all))
	data := append([]T{}, all[start:end]...)
	return bomhort.Paginated[T]{Data: data, Total: uint64(len(all)), Page: uint64(p), PageSize: uint64(size)}
}

func (s *Server) listSBOMs(w http.ResponseWriter, r *http.Request) {
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	project := strings.TrimSpace(r.URL.Query().Get("project"))
	s.mu.Lock()
	defer s.mu.Unlock()
	var match []bomhort.SBOM
	for _, sb := range s.sboms {
		if search != "" && !strings.Contains(strings.ToLower(sb.DocumentName), search) && !strings.Contains(strings.ToLower(sb.SourceFile), search) {
			continue
		}
		if project != "" && sb.Project != project {
			continue
		}
		match = append(match, sb)
	}
	writeJSON(w, http.StatusOK, page(r, match))
}

// lookup validates the {id} path value like BOMHort (400 for non-UUIDs)
// and reports whether the SBOM exists. It must be called with s.mu held.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
		return "", -1, false
	}
	for i, sb := range s.sboms {
		if sb.ID == id {
			return id, i, true
		}
	}
	return id, -1, true
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, i, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if i < 0 {
		writeError(w, http.StatusNotFound, "SBOM not found")
		return
	}
	sb := s.sboms[i]
	d := bomhort.SBOMDetail{
		ID: sb.ID, SourceFile: sb.SourceFile, SPDXVersion: sb.SPDXVersion, DocumentName: sb.DocumentName,
		DocumentVersion: sb.DocumentVersion, PackageCount: sb.PackageCount, VulnCount: sb.VulnCount,
		IngestedAt: sb.IngestedAt, SourceRepo: sb.SourceRepo, SourceRef: sb.SourceRef,
	}
	for _, v := range s.vulns[id] {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			d.CriticalVulns++
		case "HIGH":
			d.HighVulns++
		case "MEDIUM", "MODERATE":
			d.MediumVulns++
		case "LOW":
			d.LowVulns++
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// BOMHort answers per-SBOM lists of unknown ids with 200 and an empty list.
func (s *Server) sbomVulns(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, _, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, s.resolvedVulns(id))
	}
}

func (s *Server) sbomDeps(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, _, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, nonNil(s.deps[id]))
	}
}

func (s *Server) sbomLicenses(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, _, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, nonNil(s.licenses[id]))
	}
}

func (s *Server) sbomVEX(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, _, ok := s.lookup(w, r)
	if !ok {
		return
	}
	out := []bomhort.VEXStatement{}
	for _, st := range s.statements {
		if st.SBOMID == id {
			out = append(out, st.VEXStatement)
		}
	}
	slices.SortStableFunc(out, func(a, b bomhort.VEXStatement) int {
		if newer(a.VEXTimestamp, b.VEXTimestamp) {
			return -1
		}
		if newer(b.VEXTimestamp, a.VEXTimestamp) {
			return 1
		}
		return 0
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, _, ok := s.lookup(w, r)
	if !ok {
		return
	}
	raw := s.raw[id]
	if raw == nil {
		writeError(w, http.StatusNotFound, "SBOM not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.json"`)
	_, _ = w.Write(raw)
}

func (s *Server) listStatements(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, page(r, s.allStatements()))
}

func (s *Server) patchSource(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		writeError(w, http.StatusForbidden, "PATCH requires AUTH_ENABLED=true")
		return
	}
	var req struct {
		SourceRepo *string `json:"source_repo"`
		SourceRef  *string `json:"source_ref"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if req.SourceRepo == nil && req.SourceRef == nil {
		writeError(w, http.StatusBadRequest, "Provide source_repo and/or source_ref")
		return
	}
	if req.SourceRepo != nil && *req.SourceRepo != "" && !validRepoURL(*req.SourceRepo) {
		writeError(w, http.StatusBadRequest, "source_repo must be an http(s) repository URL without credentials")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, i, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if i < 0 {
		writeError(w, http.StatusNotFound, "SBOM not found")
		return
	}
	if req.SourceRepo != nil {
		s.sboms[i].SourceRepo = normalizeRepo(*req.SourceRepo)
	}
	if req.SourceRef != nil {
		s.sboms[i].SourceRef = *req.SourceRef
	}
	writeJSON(w, http.StatusOK, bomhort.SourceAttribution{SBOMID: id, SourceRepo: s.sboms[i].SourceRepo, SourceRef: s.sboms[i].SourceRef})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		writeError(w, http.StatusForbidden, "Upload requires AUTH_ENABLED=true")
		return
	}
	name := path.Base(strings.TrimSpace(r.Header.Get("X-Filename")))
	if name == "" || name == "." || name == "/" {
		writeError(w, http.StatusBadRequest, "X-Filename header is required")
		return
	}
	lower := strings.ToLower(name)
	isVEX := strings.HasSuffix(lower, ".openvex.json") || strings.HasSuffix(lower, ".vex.json")
	if !strings.HasSuffix(lower, ".json") {
		writeError(w, http.StatusBadRequest, "Unsupported file type: filename must end in .spdx.json, .cdx.json, .openvex.json, .vex.json, or .json")
		return
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "Empty request body")
		return
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hashes[hash] {
		writeJSON(w, http.StatusOK, bomhort.UploadResult{Status: "duplicate", SHA256Hash: hash, Message: "Content already ingested, skipping"})
		return
	}
	if !json.Valid(body) {
		if isVEX {
			writeError(w, http.StatusBadRequest, "Invalid VEX content: not valid JSON")
		} else {
			writeError(w, http.StatusBadRequest, "Invalid SBOM content: not valid JSON")
		}
		return
	}
	q := r.URL.Query()
	sbomID := strings.TrimSpace(q.Get("sbom_id"))
	if sbomID != "" {
		if !isVEX {
			writeError(w, http.StatusBadRequest, "?sbom_id= is only valid for VEX uploads")
			return
		}
		if !isUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "?sbom_id= must be a valid SBOM UUID")
			return
		}
	}
	repo, ref := strings.TrimSpace(r.Header.Get("X-Source-Repo")), strings.TrimSpace(r.Header.Get("X-Source-Ref"))
	if repo != "" && !validRepoURL(repo) {
		writeError(w, http.StatusBadRequest, "X-Source-Repo must be an http(s) repository URL without credentials")
		return
	}
	if ref != "" && (strings.ContainsAny(ref, " \t\n") || len(ref) > 256) {
		writeError(w, http.StatusBadRequest, "X-Source-Ref must be a git ref without whitespace (max 256 chars)")
		return
	}
	s.hashes[hash] = true

	jobType := "sbom"
	if isVEX {
		jobType = "vex"
	}
	res := bomhort.UploadResult{
		Status: "pending", JobID: randomUUID(), SHA256Hash: hash, JobType: jobType,
		Cluster: q.Get("cluster"), Namespace: q.Get("namespace"), Project: q.Get("project"), Parent: q.Get("parent"),
	}
	extra := map[string]string{}
	for k := range q {
		if k != "sbom_id" {
			extra[k] = q.Get(k)
		}
	}
	s.uploads = append(s.uploads, Upload{Filename: name, Body: body, SBOMID: sbomID, Query: extra, SourceRepo: repo, SourceRef: ref, Result: res})
	sourceFile := "pushed/" + res.JobID + "-" + name
	switch {
	case isVEX && s.ApplyUploads:
		s.applyVEX(body, sourceFile, sbomID)
	case !isVEX && s.IngestUploads:
		s.ingestSBOM(body, sourceFile, res, repo, ref)
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) ingestSBOM(body []byte, sourceFile string, res bomhort.UploadResult, repo, ref string) {
	var doc struct {
		Name        string `json:"name"`
		SPDXVersion string `json:"spdxVersion"`
		SpecVersion string `json:"specVersion"`
		Packages    []any  `json:"packages"`
		Components  []any  `json:"components"`
		Metadata    struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(body, &doc)
	sb := bomhort.SBOM{
		ID: randomUUID(), SourceFile: sourceFile, SPDXVersion: doc.SPDXVersion, DocumentName: doc.Name,
		PackageCount: uint64(len(doc.Packages) + len(doc.Components)), IngestedAt: now(),
		SourceRepo: normalizeRepo(repo), SourceRef: ref,
		Cluster: res.Cluster, Namespace: res.Namespace, Project: res.Project,
	}
	if sb.DocumentName == "" {
		sb.DocumentName = doc.Metadata.Component.Name
		sb.DocumentVersion = doc.Metadata.Component.Version
	}
	if sb.SPDXVersion == "" && doc.SpecVersion != "" {
		sb.SPDXVersion = "CycloneDX-" + doc.SpecVersion
	}
	s.sboms = append(s.sboms, sb)
	s.vulns[sb.ID] = nil
	s.raw[sb.ID] = body
	s.rescue()
}

// applyVEX mimics BOMHort's VEX ingestion (parser + parsing-worker scoping).
// Must be called with s.mu held.
func (s *Server) applyVEX(body []byte, sourceFile, sbomID string) {
	type ident struct {
		ID          string `json:"@id"`
		Identifiers struct {
			PURL string `json:"purl"`
		} `json:"identifiers"`
	}
	var doc struct {
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Role       string `json:"role"`
		Tooling    string `json:"tooling"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Timestamp     string `json:"timestamp"`
			Vulnerability struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products []struct {
				ident
				Subcomponents []ident `json:"subcomponents"`
			} `json:"products"`
			Status          string `json:"status"`
			StatusNotes     string `json:"status_notes"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	purlOf := func(i ident) string {
		if i.Identifiers.PURL != "" {
			return i.Identifiers.PURL
		}
		return i.ID
	}
	ingested := now()
	for _, st := range doc.Statements {
		vulnID := st.Vulnerability.Name
		if vulnID == "" && len(st.Vulnerability.Aliases) > 0 {
			vulnID = st.Vulnerability.Aliases[0]
		}
		if vulnID == "" {
			continue
		}
		vulnID = normalizeVulnID(vulnID)
		ts := ingested
		for _, t := range []string{st.Timestamp, doc.Timestamp} {
			if _, err := time.Parse(time.RFC3339, t); err == nil {
				ts = t
				break
			}
		}
		for _, p := range st.Products {
			ref := purlOf(p.ident)
			match, wide := []string{ref}, true
			if len(p.Subcomponents) > 0 {
				match, wide = nil, false
				for _, sc := range p.Subcomponents {
					if u := purlOf(sc); u != "" {
						match = append(match, u)
					}
				}
			}
			for _, purl := range match {
				if purl == "" {
					continue
				}
				x := stored{ref: ref, wide: wide, VEXStatement: bomhort.VEXStatement{
					VEXID: randomUUID(), DocumentID: doc.ID, SourceFile: sourceFile,
					ProductPURL: purl, VulnID: vulnID, Status: st.Status,
					Justification: st.Justification, ImpactStatement: st.ImpactStatement, ActionStatement: st.ActionStatement,
					VEXTimestamp: ts, IngestedAt: ingested,
					Author: doc.Author, Role: doc.Role, Tooling: doc.Tooling, StatusNotes: st.StatusNotes,
				}}
				target := sbomID
				if target == "" {
					target = s.resolveProduct(ref)
				}
				s.statements = append(s.statements, x.scope(target))
			}
		}
	}
}

// scope binds a statement to an SBOM; product-wide statements then cover
// every component ("*").
func (x stored) scope(sbomID string) stored {
	if sbomID == "" {
		return x
	}
	x.SBOMID = sbomID
	if x.wide {
		x.ProductPURL = "*"
	}
	return x
}

// resolveProduct maps a VEX product ref to an SBOM like BOMHort's
// ResolveSBOMByProductRef: sbom_id, source_repo, then document_name; the
// repository URL form is retried normalised. Must be called with s.mu held.
func (s *Server) resolveProduct(ref string) string {
	if ref == "" {
		return ""
	}
	for _, r := range []string{ref, normalizeRepo(ref)} {
		if r == "" {
			continue
		}
		for _, sb := range s.sboms {
			if sb.ID == r || (sb.SourceRepo != "" && sb.SourceRepo == r) || (sb.DocumentName != "" && sb.DocumentName == r) {
				return sb.ID
			}
		}
	}
	return ""
}

// rescue scopes unscoped statements whose product now resolves, as BOMHort
// does after every SBOM ingest. Must be called with s.mu held.
func (s *Server) rescue() {
	for i, x := range s.statements {
		if x.SBOMID == "" {
			s.statements[i] = x.scope(s.resolveProduct(x.ref))
		}
	}
}

// resolvedVulns returns the findings of an SBOM with the winning VEX
// statement applied. Must be called with s.mu held.
func (s *Server) resolvedVulns(sbomID string) []bomhort.Vulnerability {
	out := slices.Clone(nonNil(s.vulns[sbomID]))
	for i := range out {
		v := &out[i]
		var win *stored
		for j := range s.statements {
			x := &s.statements[j]
			if x.SBOMID != sbomID || x.VulnID != v.VulnID || (x.ProductPURL != v.PURL && x.ProductPURL != "*") {
				continue
			}
			if win == nil || !newer(win.VEXTimestamp, x.VEXTimestamp) {
				win = x
			}
		}
		if win == nil {
			continue
		}
		v.VEXStatus = win.Status
		v.VEXJustification = win.Justification
		v.VEXTimestamp = win.VEXTimestamp
		v.VEXStatementID = win.VEXID
		v.VEXAuthor = win.Author
		v.VEXTooling = win.Tooling
		v.VEXScope = "sbom"
	}
	return out
}

// allStatements must be called with s.mu held.
func (s *Server) allStatements() []bomhort.VEXStatement {
	out := make([]bomhort.VEXStatement, len(s.statements))
	for i, x := range s.statements {
		out[i] = x.VEXStatement
	}
	return out
}

// normalizeVulnID reduces advisory URLs to their last path segment.
func normalizeVulnID(id string) string {
	if strings.HasPrefix(id, "http://") || strings.HasPrefix(id, "https://") {
		if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
			return id[i+1:]
		}
	}
	return id
}

// normalizeRepo is a simplified sourcerepo.Normalize: it strips "git+",
// an "@ref" suffix, ".git" and trailing slashes from http(s) URLs.
func normalizeRepo(raw string) string {
	u := strings.TrimPrefix(strings.TrimSpace(raw), "git+")
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok || (scheme != "https" && scheme != "http") {
		return ""
	}
	host, p, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(p, "@"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/"), ".git")
	if strings.Contains(host, "@") || p == "" {
		return ""
	}
	return scheme + "://" + strings.ToLower(host) + "/" + p
}

func (s *Server) cannedHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c, ok := s.canned[r.Method+" "+r.URL.Path]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, c.status, c.body)
}

// newer reports whether RFC 3339 timestamp a is strictly after b; unparsable
// values compare as strings.
func newer(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if errA != nil || errB != nil {
		return a > b
	}
	return ta.After(tb)
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func validRepoURL(u string) bool {
	return (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) && !strings.Contains(strings.SplitN(strings.SplitN(u, "://", 2)[1], "/", 2)[0], "@")
}
