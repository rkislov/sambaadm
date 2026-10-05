package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

const defaultPageSize = 500

// SearchOptions controls an LDAP search.
type SearchOptions struct {
	BaseDN     string
	Filter     string
	Attributes []string
	Scope      *int // nil = wholeSubtree
	PageSize   uint32
}

// ScopeBase returns a pointer to ldap.ScopeBaseObject.
func ScopeBase() *int {
	s := ldap.ScopeBaseObject
	return &s
}

// ScopeSubtree returns a pointer to ldap.ScopeWholeSubtree.
func ScopeSubtree() *int {
	s := ldap.ScopeWholeSubtree
	return &s
}

// Search performs a paged search and returns all entries.
func (c *Client) Search(ctx context.Context, opts SearchOptions) ([]*ldap.Entry, error) {
	conn, err := c.Conn(ctx)
	if err != nil {
		return nil, err
	}

	base := opts.BaseDN
	if base == "" {
		base = c.cfg.BaseDN
	}
	scope := ldap.ScopeWholeSubtree
	if opts.Scope != nil {
		scope = *opts.Scope
	}
	pageSize := opts.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	filter := opts.Filter
	if filter == "" {
		filter = "(objectClass=*)"
	}

	paging := ldap.NewControlPaging(pageSize)
	var all []*ldap.Entry

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		req := ldap.NewSearchRequest(
			base,
			scope,
			ldap.NeverDerefAliases,
			0, 0, false,
			filter,
			opts.Attributes,
			[]ldap.Control{paging},
		)

		res, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("ldap search: %w", err)
		}
		all = append(all, res.Entries...)

		pagingResult := ldap.FindControl(res.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}
		ctrl, ok := pagingResult.(*ldap.ControlPaging)
		if !ok || len(ctrl.Cookie) == 0 {
			break
		}
		paging.SetCookie(ctrl.Cookie)
	}

	return all, nil
}

// SearchOne returns a single entry or an error if not found.
func (c *Client) SearchOne(ctx context.Context, opts SearchOptions) (*ldap.Entry, error) {
	opts.PageSize = 1
	entries, err := c.Search(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("not found"))
	}
	return entries[0], nil
}
