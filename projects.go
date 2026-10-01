package bomhort

import (
	"context"
	"net/url"
)

// ProjectListOptions filters GET /api/v1/projects.
type ProjectListOptions struct {
	ListOptions
	// Search is a substring match on the project name.
	Search string
	// Tag narrows the listing to one grouping label. Sub-projects of a
	// parent project P are listed with Tag: P.
	Tag string
}

func (o *ProjectListOptions) query() url.Values {
	if o == nil {
		return url.Values{}
	}
	q := pageQuery(o.ListOptions)
	setIf(q, "search", o.Search)
	setIf(q, "tag", o.Tag)
	return q
}

// ListProjects returns one page of projects (SBOMs grouped by project).
func (c *Client) ListProjects(ctx context.Context, opts *ProjectListOptions) (Paginated[Project], error) {
	var out Paginated[Project]
	err := c.getJSON(ctx, "/api/v1/projects", opts.query(), &out)
	return out, err
}

// Projects iterates over all projects matching opts.
func (c *Client) Projects(ctx context.Context, opts *ProjectListOptions) Seq[Project] {
	var o ProjectListOptions
	if opts != nil {
		o = *opts
	}
	return Paginate(ctx, o.PageSize, func(ctx context.Context, lo ListOptions) (Paginated[Project], error) {
		o.ListOptions = lo
		return c.ListProjects(ctx, &o)
	})
}

// ListProjectGroups returns one page of parents with their member projects
// (GET /api/v1/projects?group_by=parent, unreleased).
func (c *Client) ListProjectGroups(ctx context.Context, opts *ProjectListOptions) (Paginated[ProjectGroup], error) {
	q := opts.query()
	q.Set("group_by", "parent")
	var out Paginated[ProjectGroup]
	err := c.getJSON(ctx, "/api/v1/projects", q, &out)
	return out, err
}

// Project returns one project aggregated over all of its SBOMs
// (GET /api/v1/projects/{name}, #398, unreleased). Names containing "/" are
// escaped correctly. A project literally named "license-compliance" is not
// reachable through this route (BOMHort limitation).
func (c *Client) Project(ctx context.Context, name string) (ProjectDetail, error) {
	var out ProjectDetail
	err := c.getJSON(ctx, "/api/v1/projects/"+esc(name), nil, &out)
	return out, err
}

// ListProjectSBOMs returns one page of a project's SBOMs (its versions)
// (GET /api/v1/projects/{name}/sboms, #398, unreleased).
func (c *Client) ListProjectSBOMs(ctx context.Context, name string, opts *ListOptions) (Paginated[SBOM], error) {
	var out Paginated[SBOM]
	err := c.getJSON(ctx, "/api/v1/projects/"+esc(name)+"/sboms", pageQuery(opt(opts)), &out)
	return out, err
}

// ProjectVulnerabilities returns the distinct findings across a project's
// SBOMs; Vulnerability.AffectedSBOMs says in how many SBOMs each occurs
// (GET /api/v1/projects/{name}/vulnerabilities, #398, unreleased).
func (c *Client) ProjectVulnerabilities(ctx context.Context, name string) ([]Vulnerability, error) {
	var out []Vulnerability
	err := c.getJSON(ctx, "/api/v1/projects/"+esc(name)+"/vulnerabilities", nil, &out)
	return out, err
}

// ListProjectPackages returns one page of the distinct components across a
// project's SBOMs (GET /api/v1/projects/{name}/packages, #398,
// unreleased). opts may be nil.
func (c *Client) ListProjectPackages(ctx context.Context, name string, opts *SearchListOptions) (Paginated[ProjectPackage], error) {
	var out Paginated[ProjectPackage]
	err := c.getJSON(ctx, "/api/v1/projects/"+esc(name)+"/packages", opts.query(), &out)
	return out, err
}

// Tags returns the grouping labels in use with their reach.
func (c *Client) Tags(ctx context.Context) ([]Tag, error) {
	var out []Tag
	err := c.getJSON(ctx, "/api/v1/tags", nil, &out)
	return out, err
}

// Clusters lists all clusters with summary statistics.
func (c *Client) Clusters(ctx context.Context) ([]Cluster, error) {
	var out []Cluster
	err := c.getJSON(ctx, "/api/v1/clusters", nil, &out)
	return out, err
}

// ClusterStats returns the statistics of one cluster (404 if unknown).
func (c *Client) ClusterStats(ctx context.Context, name string) (ClusterStats, error) {
	var out ClusterStats
	err := c.getJSON(ctx, "/api/v1/clusters/"+esc(name)+"/stats", nil, &out)
	return out, err
}

// ListClusterSBOMs returns one page of the SBOMs of a cluster.
func (c *Client) ListClusterSBOMs(ctx context.Context, name string, opts *ListOptions) (Paginated[SBOM], error) {
	var out Paginated[SBOM]
	err := c.getJSON(ctx, "/api/v1/clusters/"+esc(name)+"/sboms", pageQuery(opt(opts)), &out)
	return out, err
}

// Namespaces lists namespaces with summary statistics. cluster "" lists
// them fleet-wide (a namespace name is only unique within a cluster).
func (c *Client) Namespaces(ctx context.Context, cluster string) ([]Namespace, error) {
	q := url.Values{}
	setIf(q, "cluster", cluster)
	var out []Namespace
	err := c.getJSON(ctx, "/api/v1/namespaces", q, &out)
	return out, err
}

// NamespaceStats returns the statistics of a namespace, optionally within
// one cluster (404 if unknown).
func (c *Client) NamespaceStats(ctx context.Context, name, cluster string) (NamespaceStats, error) {
	q := url.Values{}
	setIf(q, "cluster", cluster)
	var out NamespaceStats
	err := c.getJSON(ctx, "/api/v1/namespaces/"+esc(name)+"/stats", q, &out)
	return out, err
}

// ListNamespaceSBOMs returns one page of the SBOMs of a namespace,
// optionally within one cluster.
func (c *Client) ListNamespaceSBOMs(ctx context.Context, name, cluster string, opts *ListOptions) (Paginated[SBOM], error) {
	q := pageQuery(opt(opts))
	setIf(q, "cluster", cluster)
	var out Paginated[SBOM]
	err := c.getJSON(ctx, "/api/v1/namespaces/"+esc(name)+"/sboms", q, &out)
	return out, err
}

// Fleet returns the whole cluster → namespace → project ownership tree.
func (c *Client) Fleet(ctx context.Context) ([]FleetCluster, error) {
	var out []FleetCluster
	err := c.getJSON(ctx, "/api/v1/fleet", nil, &out)
	return out, err
}
