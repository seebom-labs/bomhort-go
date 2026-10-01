package bomhort

import (
	"context"
	"net/url"
	"strconv"
)

// ListVEXStatements returns one page of all ingested VEX statements.
func (c *Client) ListVEXStatements(ctx context.Context, opts *ListOptions) (Paginated[VEXStatement], error) {
	var out Paginated[VEXStatement]
	err := c.getJSON(ctx, "/api/v1/vex/statements", pageQuery(opt(opts)), &out)
	return out, err
}

// VEXStatements iterates over all ingested VEX statements (opts.PageSize
// defaults to 100, opts.Page is ignored).
func (c *Client) VEXStatements(ctx context.Context, opts *ListOptions) Seq[VEXStatement] {
	return Paginate(ctx, opt(opts).PageSize, func(ctx context.Context, o ListOptions) (Paginated[VEXStatement], error) {
		return c.ListVEXStatements(ctx, &o)
	})
}

// AllVEXStatements collects every ingested VEX statement.
func (c *Client) AllVEXStatements(ctx context.Context) ([]VEXStatement, error) {
	return Collect(c.VEXStatements(ctx, nil))
}

// ListVulnerabilities returns one page of all findings across the
// instance, each with its VEX status attached.
func (c *Client) ListVulnerabilities(ctx context.Context, opts *ListOptions) (Paginated[Vulnerability], error) {
	var out Paginated[Vulnerability]
	err := c.getJSON(ctx, "/api/v1/vulnerabilities", pageQuery(opt(opts)), &out)
	return out, err
}

// AffectedProjects returns the SBOMs affected by a vulnerability id
// (CVE-…, GHSA-…, GO-…), including transitive dependencies.
func (c *Client) AffectedProjects(ctx context.Context, vulnID string) ([]AffectedProject, error) {
	var out []AffectedProject
	err := c.getJSON(ctx, "/api/v1/vulnerabilities/"+esc(vulnID)+"/affected-projects", nil, &out)
	return out, err
}

// DashboardStats returns the instance-wide KPIs.
func (c *Client) DashboardStats(ctx context.Context) (DashboardStats, error) {
	var out DashboardStats
	err := c.getJSON(ctx, "/api/v1/stats/dashboard", nil, &out)
	return out, err
}

// DependencyStats returns the most used dependencies across all projects.
// limit <= 0 uses the server default (50, max 500).
func (c *Client) DependencyStats(ctx context.Context, limit int) (DependencyStats, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out DependencyStats
	err := c.getJSON(ctx, "/api/v1/stats/dependencies", q, &out)
	return out, err
}

// SearchListOptions is ListOptions plus a substring search term.
type SearchListOptions struct {
	ListOptions
	Search string
}

func (o *SearchListOptions) query() url.Values {
	if o == nil {
		return url.Values{}
	}
	q := pageQuery(o.ListOptions)
	setIf(q, "search", o.Search)
	return q
}

// VersionSkew returns packages used in inconsistent versions across
// projects. opts may be nil.
func (c *Client) VersionSkew(ctx context.Context, opts *SearchListOptions) (VersionSkew, error) {
	var out VersionSkew
	err := c.getJSON(ctx, "/api/v1/stats/version-skew", opts.query(), &out)
	return out, err
}

// Search runs the faceted global search. q must be at least two characters
// after trimming; limit <= 0 uses the server default (5 per facet, max 50).
func (c *Client) Search(ctx context.Context, q string, limit int) (SearchResult, error) {
	v := url.Values{"q": {q}}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out SearchResult
	err := c.getJSON(ctx, "/api/v1/search", v, &out)
	return out, err
}

// SearchPackages finds packages by name across all SBOMs.
func (c *Client) SearchPackages(ctx context.Context, q string, opts *ListOptions) (PackageSearch, error) {
	v := pageQuery(opt(opts))
	v.Set("q", q)
	var out PackageSearch
	err := c.getJSON(ctx, "/api/v1/packages/search", v, &out)
	return out, err
}

// PackageDetail lists the projects using a package (exact name).
func (c *Client) PackageDetail(ctx context.Context, name string, opts *ListOptions) (PackageDetail, error) {
	v := pageQuery(opt(opts))
	v.Set("name", name)
	var out PackageDetail
	err := c.getJSON(ctx, "/api/v1/packages/detail", v, &out)
	return out, err
}

// ArchivedPackages lists dependencies whose upstream GitHub repository is
// archived.
func (c *Client) ArchivedPackages(ctx context.Context) ([]ArchivedPackage, error) {
	var out []ArchivedPackage
	err := c.getJSON(ctx, "/api/v1/packages/archived", nil, &out)
	return out, err
}

// LicenseCompliance returns the license compliance overview.
func (c *Client) LicenseCompliance(ctx context.Context) ([]LicenseCompliance, error) {
	var out []LicenseCompliance
	err := c.getJSON(ctx, "/api/v1/licenses/compliance", nil, &out)
	return out, err
}

// LicenseViolations returns the SBOMs with non-compliant licenses after
// applying the configured exceptions (GET /api/v1/projects/license-compliance).
func (c *Client) LicenseViolations(ctx context.Context) ([]LicenseViolation, error) {
	var out []LicenseViolation
	err := c.getJSON(ctx, "/api/v1/projects/license-compliance", nil, &out)
	return out, err
}

// LicenseExceptions returns the operator's license exceptions file.
func (c *Client) LicenseExceptions(ctx context.Context) (LicenseExceptions, error) {
	var out LicenseExceptions
	err := c.getJSON(ctx, "/api/v1/license-exceptions", nil, &out)
	return out, err
}

// LicensePolicy returns the permissive/copyleft classification in effect.
func (c *Client) LicensePolicy(ctx context.Context) (LicensePolicy, error) {
	var out LicensePolicy
	err := c.getJSON(ctx, "/api/v1/license-policy", nil, &out)
	return out, err
}
