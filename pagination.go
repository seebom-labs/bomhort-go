package bomhort

import (
	"context"
	"iter"
)

// Seq is a lazy sequence of list items. Iteration stops at the first
// error, which is yielded together with the zero value of T:
//
//	for s, err := range c.SBOMs(ctx, nil) {
//		if err != nil { return err }
//		...
//	}
type Seq[T any] = iter.Seq2[T, error]

// DefaultWalkPageSize is the page size used by the iterators and All*
// helpers when none is given. 100 keeps a full walk well below BOMHort's
// rate limit for typical instances while avoiding huge responses.
const DefaultWalkPageSize = 100

// Collect drains seq into a slice, returning the first error.
func Collect[T any](seq Seq[T]) ([]T, error) {
	var all []T
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		all = append(all, v)
	}
	return all, nil
}

// Paginate turns any page-wise List* call into a lazy sequence. It walks
// pages of pageSize (DefaultWalkPageSize if <= 0) until an empty page or
// the reported total is reached:
//
//	vulns := bomhort.Paginate(ctx, 200, func(ctx context.Context, o bomhort.ListOptions) (bomhort.Paginated[bomhort.Vulnerability], error) {
//		return c.ListVulnerabilities(ctx, &o)
//	})
func Paginate[T any](ctx context.Context, pageSize int, fetch func(context.Context, ListOptions) (Paginated[T], error)) Seq[T] {
	if pageSize <= 0 {
		pageSize = DefaultWalkPageSize
	}
	return func(yield func(T, error) bool) {
		var seen uint64
		for page := 1; ; page++ {
			p, err := fetch(ctx, ListOptions{Page: page, PageSize: pageSize})
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, v := range p.Data {
				if !yield(v, nil) {
					return
				}
			}
			seen += uint64(len(p.Data))
			if len(p.Data) == 0 || seen >= p.Total {
				return
			}
		}
	}
}

// opt dereferences optional list options.
func opt(o *ListOptions) ListOptions {
	if o == nil {
		return ListOptions{}
	}
	return *o
}
