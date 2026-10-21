package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// DirectoryNode uses parsed DNs so escaped commas and multivalued RDNs remain intact.
type DirectoryNode struct {
	DN       string           `json:"dn"`
	ObjectDN string           `json:"objectDN,omitempty"`
	ParentDN string           `json:"parentDN,omitempty"`
	Label    string           `json:"label"`
	Kind     string           `json:"kind"`
	Children []*DirectoryNode `json:"children"`
}
type directoryEntry struct{ DN, Label, Kind string }

func directoryTree(base string, entries []directoryEntry) (*DirectoryNode, error) {
	baseDN, err := ldap.ParseDN(base)
	if err != nil || len(baseDN.RDNs) == 0 {
		return nil, fmt.Errorf("configure a valid LDAP Base DN")
	}
	root := &DirectoryNode{DN: readableDN(baseDN), Label: readableDN(baseDN), Kind: "domain", Children: []*DirectoryNode{}}
	nodes := map[string]*DirectoryNode{strings.ToLower(baseDN.String()): root}
	var ensure func(*ldap.DN) *DirectoryNode
	ensure = func(dn *ldap.DN) *DirectoryNode {
		if baseDN.EqualFold(dn) {
			return root
		}
		key := strings.ToLower(dn.String())
		if n := nodes[key]; n != nil {
			return n
		}
		parent := ensure(&ldap.DN{RDNs: dn.RDNs[1:]})
		n := &DirectoryNode{DN: readableDN(dn), Label: readableDN(&ldap.DN{RDNs: dn.RDNs[:1]}), Kind: "container", Children: []*DirectoryNode{}}
		n.ParentDN = parent.DN
		nodes[key] = n
		parent.Children = append(parent.Children, n)
		return n
	}
	for _, entry := range entries {
		dn, e := ldap.ParseDN(entry.DN)
		if e != nil {
			return nil, fmt.Errorf("invalid directory DN: %w", e)
		}
		if !baseDN.EqualFold(dn) && !baseDN.AncestorOfFold(dn) {
			continue
		}
		n := ensure(dn)
		n.ObjectDN = entry.DN
		n.Kind = entry.Kind
		if entry.Label != "" {
			n.Label = entry.Label
		}
	}
	var order func(*DirectoryNode)
	order = func(n *DirectoryNode) {
		sort.Slice(n.Children, func(i, j int) bool {
			a, b := n.Children[i], n.Children[j]
			ac := a.Kind == "container" || a.Kind == "ou"
			bc := b.Kind == "container" || b.Kind == "ou"
			if ac != bc {
				return ac
			}
			return strings.ToLower(a.Label) < strings.ToLower(b.Label)
		})
		for _, c := range n.Children {
			order(c)
		}
	}
	order(root)
	return root, nil
}
func (s *Server) handleAPIDirectoryTree(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "users"
	}
	if kind != "users" && kind != "groups" && kind != "computers" && kind != "ou" {
		writeJSON(w, 400, map[string]string{"error": "unknown directory kind"})
		return
	}
	entries := []directoryEntry{}
	ous, err := s.svcs.OU.List(r.Context())
	if err != nil {
		apiResult(w, nil, err)
		return
	}
	for _, o := range ous {
		entries = append(entries, directoryEntry{o.DN, o.Name, "ou"})
	}
	switch kind {
	case "users":
		list, e := s.svcs.Users.List(r.Context(), "", "")
		err = e
		for _, u := range list {
			entries = append(entries, directoryEntry{u.DN, u.SAMAccountName, "user"})
		}
	case "groups":
		list, e := s.svcs.Groups.List(r.Context(), "")
		err = e
		for _, g := range list {
			entries = append(entries, directoryEntry{g.DN, g.SAMAccountName, "group"})
		}
	case "computers":
		list, e := s.svcs.Computers.List(r.Context(), "")
		err = e
		for _, c := range list {
			entries = append(entries, directoryEntry{c.DN, c.SAMAccountName, "computer"})
		}
	}
	if err != nil {
		apiResult(w, nil, err)
		return
	}
	tree, err := directoryTree(s.cfg.LDAP.BaseDN, entries)
	apiResult(w, tree, err)
}

// readableDN preserves Unicode while escaping RFC 4514 delimiters in values.
func readableDN(dn *ldap.DN) string {
	parts := make([]string, 0, len(dn.RDNs))
	for _, rdn := range dn.RDNs {
		attrs := make([]string, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			attrs = append(attrs, a.Type+"="+ldap.EscapeDN(a.Value))
		}
		parts = append(parts, strings.Join(attrs, "+"))
	}
	return strings.Join(parts, ",")
}
