package bomhort

import "time"

// The types in this file mirror backend/pkg/dto/api.go (and a few
// handler-local response shapes) in seebom-labs/BOMHort. Field names and
// JSON tags follow the server exactly; timestamps are kept as the strings
// BOMHort sends. Fields marked "unreleased" exist on BOMHort main but not
// in the latest release yet and are simply empty on older gateways.

// ListOptions selects one page of a paginated endpoint. Zero values use the
// server defaults (page 1, page_size 50; BOMHort caps page_size at 500).
type ListOptions struct {
	Page     int
	PageSize int
}

// Paginated wraps the list responses of paginated endpoints.
type Paginated[T any] struct {
	Data     []T    `json:"data"`
	Total    uint64 `json:"total"`
	Page     uint64 `json:"page"`
	PageSize uint64 `json:"page_size"`
}

// Health is the body of /healthz, /livez and /readyz.
type Health struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// DashboardStats is GET /api/v1/stats/dashboard.
type DashboardStats struct {
	TotalSBOMs               uint64            `json:"total_sboms"`
	TotalPackages            uint64            `json:"total_packages"`
	TotalVulnerabilities     uint64            `json:"total_vulnerabilities"`
	EffectiveVulnerabilities uint64            `json:"effective_vulnerabilities"`
	SuppressedByVEX          uint64            `json:"suppressed_by_vex"`
	CriticalVulns            uint64            `json:"critical_vulns"`
	HighVulns                uint64            `json:"high_vulns"`
	MediumVulns              uint64            `json:"medium_vulns"`
	LowVulns                 uint64            `json:"low_vulns"`
	LicenseBreakdown         map[string]uint64 `json:"license_breakdown"`
	ExemptedPackages         uint64            `json:"exempted_packages"`
	TotalVEXStatements       uint64            `json:"total_vex_statements"`
	LastCVERefresh           string            `json:"last_cve_refresh,omitempty"`
	NewVulnsSinceRefresh     uint64            `json:"new_vulns_since_refresh"`
	ArchivedReposCount       uint64            `json:"archived_repos_count"`
}

// SBOM is one entry of GET /api/v1/sboms (and the project, cluster and
// namespace SBOM listings). DTO: SBOMListItem.
type SBOM struct {
	ID           string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	SPDXVersion  string `json:"spdx_version"`
	DocumentName string `json:"document_name"`
	// DocumentVersion is the described product's version ("" = unknown).
	DocumentVersion string `json:"document_version,omitempty"`
	PackageCount    uint64 `json:"package_count"`
	VulnCount       uint64 `json:"vuln_count"`
	IngestedAt      string `json:"ingested_at"`
	// SourceRepo and SourceRef are the product's source repository and
	// commit/tag (BOMHort #332, >= 0.7.0); empty when unknown.
	SourceRepo string `json:"source_repo,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
	// Ownership dimensions (#177); empty on single-instance deployments.
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
}

// SBOMDetail is GET /api/v1/sboms/{id}/detail.
type SBOMDetail struct {
	ID              string `json:"sbom_id"`
	SourceFile      string `json:"source_file"`
	SPDXVersion     string `json:"spdx_version"`
	DocumentName    string `json:"document_name"`
	DocumentVersion string `json:"document_version,omitempty"`
	PackageCount    uint64 `json:"package_count"`
	VulnCount       uint64 `json:"vuln_count"`
	IngestedAt      string `json:"ingested_at"`
	SourceRepo      string `json:"source_repo,omitempty"`
	SourceRef       string `json:"source_ref,omitempty"`
	CriticalVulns   uint64 `json:"critical_vulns"`
	HighVulns       uint64 `json:"high_vulns"`
	MediumVulns     uint64 `json:"medium_vulns"`
	LowVulns        uint64 `json:"low_vulns"`
}

// Vulnerability is one finding: GET /api/v1/vulnerabilities,
// /sboms/{id}/vulnerabilities and /projects/{name}/vulnerabilities.
// DTO: VulnerabilityListItem.
//
// A VEX statement applies to a finding when it is scoped to the finding's
// SBOM, statement.vuln_id == VulnID and statement.product_purl == PURL or
// "*" (product-wide), all by plain string equality; never normalise VulnID
// or PURL before writing VEX for them. See docs/VEX.md.
type Vulnerability struct {
	VulnID       string `json:"vuln_id"`
	Severity     string `json:"severity"`
	PURL         string `json:"purl"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixed_version"`
	SourceFile   string `json:"source_file"`
	DiscoveredAt string `json:"discovered_at"`
	VEXStatus    string `json:"vex_status,omitempty"`
	// Effective VEX statement detail (#335, >= 0.7.0): one row per
	// (vuln_id, purl); the statement with the newest vex_timestamp wins.
	VEXJustification string `json:"vex_justification,omitempty"`
	VEXTimestamp     string `json:"vex_timestamp,omitempty"`
	VEXStatementID   string `json:"vex_statement_id,omitempty"`
	VEXAuthor        string `json:"vex_author,omitempty"`
	VEXTooling       string `json:"vex_tooling,omitempty"`
	// VEXScope is "sbom" when a statement scoped to this SBOM applies
	// (#350, >= 0.7.0). BOMHort's DTO also documents "global", but since
	// 0.7.0 unscoped statements never apply, so it is not sent in practice.
	VEXScope string `json:"vex_scope,omitempty"`
	// AffectedSBOMs is set only on project-level listings: how many of the
	// project's SBOMs carry this (vuln_id, purl) pair (#398, unreleased).
	AffectedSBOMs uint64 `json:"affected_sboms,omitempty"`
}

// DependencyNode is one node of GET /api/v1/sboms/{id}/dependencies. The
// tree is a flat list; Children holds the Index values of child nodes.
type DependencyNode struct {
	Index    uint32   `json:"index"`
	SPDXID   string   `json:"spdx_id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	License  string   `json:"license"`
	Children []uint32 `json:"children"`
}

// SBOMLicense is one entry of GET /api/v1/sboms/{id}/licenses.
// DTO: SBOMLicenseBreakdownItem.
type SBOMLicense struct {
	LicenseID        string   `json:"license_id"`
	Category         string   `json:"category"`
	PackageCount     uint32   `json:"package_count"`
	Packages         []string `json:"packages"`
	ExemptedPackages []string `json:"exempted_packages,omitempty"`
	ExemptionReason  string   `json:"exemption_reason,omitempty"`
}

// VEXStatement is one ingested statement: GET /api/v1/vex/statements and
// /sboms/{id}/vex. DTO: VEXStatementItem.
type VEXStatement struct {
	VEXID      string `json:"vex_id"`
	DocumentID string `json:"document_id"`
	SourceFile string `json:"source_file"`
	// SBOMID is the SBOM the statement is scoped to (#350). Empty means
	// the product resolved to no SBOM (yet): such statements suppress
	// nothing until a matching SBOM is ingested.
	SBOMID string `json:"sbom_id,omitempty"`
	// ProductPURL is the subcomponent purl the statement is about, or "*"
	// for a product-wide statement (product without subcomponents).
	ProductPURL     string `json:"product_purl"`
	VulnID          string `json:"vuln_id"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	VEXTimestamp    string `json:"vex_timestamp"`
	IngestedAt      string `json:"ingested_at"`
	// Provenance (#334, >= 0.7.0); empty when the document has none.
	Author        string     `json:"author,omitempty"`
	Role          string     `json:"role,omitempty"`
	Tooling       string     `json:"tooling,omitempty"`
	StatusNotes   string     `json:"status_notes,omitempty"`
	AffectedSBOMs []SBOMLink `json:"affected_sboms,omitempty"`
}

// SBOMLink references an SBOM by id and document name.
// DTO: VEXAffectedSBOM, LicenseAffectedSBOM.
type SBOMLink struct {
	SBOMID       string `json:"sbom_id"`
	DocumentName string `json:"document_name"`
}

// LicenseCompliance is one entry of GET /api/v1/licenses/compliance.
// DTO: LicenseComplianceItem.
type LicenseCompliance struct {
	LicenseID            string     `json:"license_id"`
	Category             string     `json:"category"`
	PackageCount         uint64     `json:"package_count"`
	SBOMCount            int        `json:"sbom_count"`
	NonCompliantPackages []string   `json:"non_compliant_packages,omitempty"`
	ExemptedPackages     []string   `json:"exempted_packages,omitempty"`
	ExemptionReason      string     `json:"exemption_reason,omitempty"`
	AffectedSBOMs        []SBOMLink `json:"affected_sboms,omitempty"`
}

// LicenseViolation is one entry of GET /api/v1/projects/license-compliance.
// DTO: ProjectLicenseViolation.
type LicenseViolation struct {
	SBOMID               string   `json:"sbom_id"`
	SourceFile           string   `json:"source_file"`
	DocumentName         string   `json:"document_name"`
	CopyleftCount        uint64   `json:"copyleft_count"`
	UnknownCount         uint64   `json:"unknown_count"`
	ViolatingLicenses    []string `json:"violating_licenses"`
	NonCompliantPackages []string `json:"non_compliant_packages"`
}

// LicenseExceptions is GET /api/v1/license-exceptions (the operator's
// license-exceptions.json). Server type: license.ExceptionsFile.
type LicenseExceptions struct {
	Version           string                    `json:"version"`
	LastUpdated       string                    `json:"lastUpdated"`
	Description       string                    `json:"description,omitempty"`
	BlanketExceptions []BlanketLicenseException `json:"blanketExceptions"`
	Exceptions        []LicenseException        `json:"exceptions"`
}

// BlanketLicenseException exempts an entire license.
type BlanketLicenseException struct {
	ID           string `json:"id"`
	License      string `json:"license"`
	Status       string `json:"status"`
	ApprovedDate string `json:"approvedDate"`
	Scope        string `json:"scope,omitempty"`
	Results      string `json:"results,omitempty"`
	IssueURL     string `json:"issueUrl,omitempty"`
	PackageURL   string `json:"packageUrl,omitempty"`
	Comment      string `json:"comment,omitempty"`
}

// LicenseException exempts one package+license combination.
type LicenseException struct {
	ID           string `json:"id"`
	Package      string `json:"package"`
	License      string `json:"license"`
	Project      string `json:"project,omitempty"`
	Status       string `json:"status"`
	ApprovedDate string `json:"approvedDate"`
	Scope        string `json:"scope,omitempty"`
	Results      string `json:"results,omitempty"`
	IssueURL     string `json:"issueUrl,omitempty"`
	PackageURL   string `json:"packageUrl,omitempty"`
	Comment      string `json:"comment,omitempty"`
}

// LicensePolicy is GET /api/v1/license-policy (permissive/copyleft
// classification). Server type: license.PolicyFile.
type LicensePolicy struct {
	Description    string   `json:"description,omitempty"`
	Permissive     []string `json:"permissive"`
	Copyleft       []string `json:"copyleft"`
	ExpressionMode string   `json:"expressionMode,omitempty"`
}

// AffectedProject is one entry of
// GET /api/v1/vulnerabilities/{id}/affected-projects.
type AffectedProject struct {
	SBOMID       string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	DocumentName string `json:"document_name"`
	PURL         string `json:"purl"`
	PackageName  string `json:"package_name"`
	Version      string `json:"version"`
	Severity     string `json:"severity"`
	VEXStatus    string `json:"vex_status,omitempty"`
	IsDirect     bool   `json:"is_direct"`
}

// DependencyStats is GET /api/v1/stats/dependencies.
// DTO: DependencyStatsResponse.
type DependencyStats struct {
	TotalUniqueDeps uint64           `json:"total_unique_deps"`
	TopDependencies []DependencyStat `json:"top_dependencies"`
}

// DependencyStat is one cross-project dependency usage entry.
// DTO: DependencyStatsItem.
type DependencyStat struct {
	PackageName  string   `json:"package_name"`
	PURL         string   `json:"purl"`
	ProjectCount uint64   `json:"project_count"`
	Versions     []string `json:"versions"`
	VulnCount    uint64   `json:"vuln_count"`
}

// VersionSkew is GET /api/v1/stats/version-skew. DTO: VersionSkewResponse.
type VersionSkew struct {
	TotalSkewedPackages uint64            `json:"total_skewed_packages"`
	Items               []VersionSkewItem `json:"items"`
	Page                uint64            `json:"page"`
	PageSize            uint64            `json:"page_size"`
}

// VersionSkewItem is a package with inconsistent versions across projects.
type VersionSkewItem struct {
	PackageName     string              `json:"package_name"`
	PURL            string              `json:"purl"`
	VersionCount    uint64              `json:"version_count"`
	ProjectCount    uint64              `json:"project_count"`
	IsDirectInCount uint64              `json:"is_direct_in_count"`
	Versions        []VersionSkewDetail `json:"versions"`
}

// VersionSkewDetail is the per-version breakdown of a skewed package.
type VersionSkewDetail struct {
	Version      string   `json:"version"`
	ProjectCount uint64   `json:"project_count"`
	Projects     []string `json:"projects"`
}

// PackageSearch is GET /api/v1/packages/search.
// DTO: DependencySearchResponse.
type PackageSearch struct {
	TotalResults uint64                `json:"total_results"`
	Items        []PackageSearchResult `json:"items"`
	Page         uint64                `json:"page"`
	PageSize     uint64                `json:"page_size"`
	Query        string                `json:"query"`
}

// PackageSearchResult is one package found by search.
// DTO: DependencySearchResult.
type PackageSearchResult struct {
	PackageName  string           `json:"package_name"`
	PURL         string           `json:"purl"`
	ProjectCount uint64           `json:"project_count"`
	Versions     []string         `json:"versions"`
	Projects     []PackageProject `json:"projects"`
}

// PackageProject is a project using a package.
// DTO: DependencySearchProject.
type PackageProject struct {
	ProjectName string `json:"project_name"`
	Version     string `json:"version"`
	SBOMID      string `json:"sbom_id"`
}

// PackageDetail is GET /api/v1/packages/detail.
// DTO: PackageDetailResponse.
type PackageDetail struct {
	PackageName   string           `json:"package_name"`
	TotalProjects uint64           `json:"total_projects"`
	Projects      []PackageProject `json:"projects"`
	Page          uint64           `json:"page"`
	PageSize      uint64           `json:"page_size"`
}

// ArchivedPackage is one entry of GET /api/v1/packages/archived: a
// dependency whose upstream GitHub repository is archived.
// Server type: clickhouse.ArchivedPackageInfo.
type ArchivedPackage struct {
	SBOMID         string    `json:"sbom_id"`
	SourceFile     string    `json:"source_file"`
	ProjectName    string    `json:"project_name"`
	ProjectVersion string    `json:"project_version"`
	PackageName    string    `json:"package_name"`
	PackagePURL    string    `json:"package_purl"`
	Repo           string    `json:"repo"`
	LastPushed     time.Time `json:"last_pushed"`
	Stars          uint32    `json:"stars"`
}

// SearchResult is GET /api/v1/search, a faceted search across packages,
// projects, vulnerabilities and licenses. DTO: GlobalSearchResponse.
type SearchResult struct {
	Query                string                `json:"query"`
	Packages             []SearchPackage       `json:"packages"`
	TotalPackages        uint64                `json:"total_packages"`
	Projects             []SearchProject       `json:"projects"`
	TotalProjects        uint64                `json:"total_projects"`
	Vulnerabilities      []SearchVulnerability `json:"vulnerabilities"`
	TotalVulnerabilities uint64                `json:"total_vulnerabilities"`
	Licenses             []SearchLicense       `json:"licenses"`
	TotalLicenses        uint64                `json:"total_licenses"`
}

// SearchPackage is a package hit. DTO: GlobalSearchPackage.
type SearchPackage struct {
	PackageName  string `json:"package_name"`
	PURL         string `json:"purl"`
	ProjectCount uint64 `json:"project_count"`
}

// SearchProject is a project hit. DTO: GlobalSearchProject.
type SearchProject struct {
	ProjectName  string `json:"project_name"`
	SBOMCount    uint64 `json:"sbom_count"`
	LatestSBOMID string `json:"latest_sbom_id"`
}

// SearchVulnerability is a vulnerability hit. DTO: GlobalSearchVulnerability.
type SearchVulnerability struct {
	VulnID        string `json:"vuln_id"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	AffectedSBOMs uint64 `json:"affected_sboms"`
}

// SearchLicense is a license hit. DTO: GlobalSearchLicense.
type SearchLicense struct {
	LicenseID string `json:"license_id"`
	Category  string `json:"category"`
	SBOMCount uint64 `json:"sbom_count"`
}

// Cluster is one entry of GET /api/v1/clusters. DTO: ClusterListItem.
type Cluster struct {
	Name         string `json:"name"`
	SBOMCount    uint64 `json:"sbom_count"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// ClusterStats is GET /api/v1/clusters/{name}/stats.
type ClusterStats struct {
	Cluster              string            `json:"cluster"`
	TotalSBOMs           uint64            `json:"total_sboms"`
	TotalPackages        uint64            `json:"total_packages"`
	TotalVulnerabilities uint64            `json:"total_vulnerabilities"`
	CriticalVulns        uint64            `json:"critical_vulns"`
	HighVulns            uint64            `json:"high_vulns"`
	MediumVulns          uint64            `json:"medium_vulns"`
	LowVulns             uint64            `json:"low_vulns"`
	LicenseBreakdown     map[string]uint64 `json:"license_breakdown"`
	LastIngested         string            `json:"last_ingested,omitempty"`
}

// Namespace is one entry of GET /api/v1/namespaces. A namespace name is
// only unique inside a cluster; ClusterCount tells how many clusters use
// it. Cluster is set only when the listing was filtered.
// DTO: NamespaceListItem.
type Namespace struct {
	Name         string `json:"name"`
	Cluster      string `json:"cluster,omitempty"`
	ClusterCount uint64 `json:"cluster_count"`
	SBOMCount    uint64 `json:"sbom_count"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// NamespaceStats is GET /api/v1/namespaces/{name}/stats.
type NamespaceStats struct {
	Namespace            string            `json:"namespace"`
	Cluster              string            `json:"cluster,omitempty"`
	Clusters             []string          `json:"clusters"`
	TotalSBOMs           uint64            `json:"total_sboms"`
	TotalPackages        uint64            `json:"total_packages"`
	TotalVulnerabilities uint64            `json:"total_vulnerabilities"`
	CriticalVulns        uint64            `json:"critical_vulns"`
	HighVulns            uint64            `json:"high_vulns"`
	MediumVulns          uint64            `json:"medium_vulns"`
	LowVulns             uint64            `json:"low_vulns"`
	LicenseBreakdown     map[string]uint64 `json:"license_breakdown"`
	LastIngested         string            `json:"last_ingested,omitempty"`
}

// FleetCluster is the root of the ownership tree of GET /api/v1/fleet.
// Unassigned dimensions appear with an empty name.
type FleetCluster struct {
	Name       string           `json:"name"`
	SBOMCount  uint64           `json:"sbom_count"`
	VulnCount  uint64           `json:"vuln_count"`
	Namespaces []FleetNamespace `json:"namespaces"`
}

// FleetNamespace groups projects inside one cluster.
type FleetNamespace struct {
	Name      string         `json:"name"`
	SBOMCount uint64         `json:"sbom_count"`
	VulnCount uint64         `json:"vuln_count"`
	Projects  []FleetProject `json:"projects"`
}

// FleetProject is a leaf of the ownership tree.
type FleetProject struct {
	Name         string `json:"name"`
	SBOMCount    uint64 `json:"sbom_count"`
	VulnCount    uint64 `json:"vuln_count"`
	LastIngested string `json:"last_ingested,omitempty"`
}

// Project is one entry of GET /api/v1/projects. PackageCount and
// VulnCount are de-duplicated across the project's SBOMs (#398).
// DTO: ProjectListItem.
type Project struct {
	ProjectName    string   `json:"project_name"`
	SBOMCount      uint64   `json:"sbom_count"`
	PackageCount   uint64   `json:"package_count"`
	VulnCount      uint64   `json:"vuln_count"`
	LatestIngested string   `json:"latest_ingested"`
	LatestSBOMID   string   `json:"latest_sbom_id"`
	Tags           []string `json:"tags"`
	// Parent is the resolved product this project belongs to and
	// ParentSource how it was resolved (unreleased).
	Parent       string `json:"parent,omitempty"`
	ParentSource string `json:"parent_source,omitempty"`
}

// ProjectGroup is one entry of GET /api/v1/projects?group_by=parent
// (unreleased). DTO: ProjectGroupItem.
type ProjectGroup struct {
	Name           string    `json:"name"`
	IsProject      bool      `json:"is_project"`
	ProjectCount   uint64    `json:"project_count"`
	SBOMCount      uint64    `json:"sbom_count"`
	PackageCount   uint64    `json:"package_count"`
	VulnCount      uint64    `json:"vuln_count"`
	LatestIngested string    `json:"latest_ingested"`
	Tags           []string  `json:"tags"`
	Sources        []string  `json:"sources"`
	Owner          string    `json:"owner,omitempty"`
	Members        []Project `json:"members"`
}

// ProjectDetail is GET /api/v1/projects/{name} (#398, unreleased): one
// project aggregated across all of its SBOMs.
type ProjectDetail struct {
	ProjectName         string            `json:"project_name"`
	Tags                []string          `json:"tags"`
	Parents             []string          `json:"parents"`
	RelatedProjectCount uint64            `json:"related_project_count"`
	SBOMCount           uint64            `json:"sbom_count"`
	PackageCount        uint64            `json:"package_count"`
	VulnCount           uint64            `json:"vuln_count"`
	CriticalVulns       uint64            `json:"critical_vulns"`
	HighVulns           uint64            `json:"high_vulns"`
	MediumVulns         uint64            `json:"medium_vulns"`
	LowVulns            uint64            `json:"low_vulns"`
	LatestIngested      string            `json:"latest_ingested,omitempty"`
	LatestVersion       string            `json:"latest_version,omitempty"`
	LatestSBOMID        string            `json:"latest_sbom_id,omitempty"`
	SourceRepo          string            `json:"source_repo,omitempty"`
	Clusters            []string          `json:"clusters"`
	Namespaces          []string          `json:"namespaces"`
	LicenseBreakdown    map[string]uint64 `json:"license_breakdown"`
	Parent              string            `json:"parent,omitempty"`
	ParentSource        string            `json:"parent_source,omitempty"`
	ParentOwner         string            `json:"parent_owner,omitempty"`
	Children            []string          `json:"children"`
}

// ProjectPackage is one distinct component across a project's SBOMs
// (GET /api/v1/projects/{name}/packages, unreleased).
// DTO: ProjectPackageItem.
type ProjectPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	SBOMCount uint64 `json:"sbom_count"`
	VulnCount uint64 `json:"vuln_count"`
}

// Tag is one entry of GET /api/v1/tags. DTO: TagListItem.
type Tag struct {
	Tag          string `json:"tag"`
	SBOMCount    uint64 `json:"sbom_count"`
	ProjectCount uint64 `json:"project_count"`
	// IsProject is true when the tag is also a project name, i.e. a parent
	// (#398, unreleased).
	IsProject bool `json:"is_project"`
}

// UploadResult is the response of POST /api/v1/sboms/upload.
type UploadResult struct {
	// Status is "pending" (202, job enqueued) or "duplicate" (200, content
	// with the same SHA-256 was already ingested).
	Status     string `json:"status"`
	JobID      string `json:"job_id,omitempty"`
	SHA256Hash string `json:"sha256_hash"`
	// JobType is "sbom" or "vex".
	JobType   string `json:"job_type,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
	Parent    string `json:"parent,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Duplicate reports whether BOMHort skipped the upload as already ingested.
func (r UploadResult) Duplicate() bool { return r.Status == "duplicate" }

// SourceAttribution is the response of PATCH /api/v1/sboms/{id}.
type SourceAttribution struct {
	SBOMID     string `json:"sbom_id"`
	SourceRepo string `json:"source_repo"`
	SourceRef  string `json:"source_ref"`
}
