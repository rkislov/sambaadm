// Package testldap implements the small LDAP protocol subset needed by regression
// tests. It is never imported by application packages and never contacts a DC.
package testldap

import (
	"net"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type Entry struct {
	DN         string
	Attributes map[string][]string
}
type Search struct {
	User   string
	Filter *ber.Packet
}
type Bind struct {
	Connection int
	User       string
	Success    bool
}
type Server struct {
	listener  net.Listener
	mu        sync.Mutex
	clients   map[net.Conn]bool
	binds     []Bind
	searches  []Search
	next      int
	closed    bool
	wg        sync.WaitGroup
	Passwords map[string]string
	Lookup    func(Search) ([]Entry, int64)
}

func New(t *testing.T, passwords map[string]string, lookup func(Search) ([]Entry, int64)) *Server {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &Server{listener: listener, clients: map[net.Conn]bool{}, Passwords: passwords, Lookup: lookup}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.next++
			id := s.next
			s.clients[conn] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go s.serve(conn, id)
		}
	}()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		listener.Close()
		s.CloseConnections()
		s.wg.Wait()
	})
	return s
}
func (s *Server) URI() string { return "ldap://" + s.listener.Addr().String() }
func (s *Server) Binds() []Bind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Bind(nil), s.binds...)
}
func (s *Server) Searches() []Search {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Search(nil), s.searches...)
}
func (s *Server) CloseConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		c.Close()
	}
}
func (s *Server) Active() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.clients) }
func packet(id int64, op *ber.Packet) []byte {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	p.AppendChild(op)
	return p.Bytes()
}
func str(v string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "")
}
func result(tag ber.Tag, code int64) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	p.AppendChild(str(""))
	p.AppendChild(str(""))
	return p
}
func (s *Server) serve(conn net.Conn, id int) {
	defer s.wg.Done()
	defer func() { conn.Close(); s.mu.Lock(); delete(s.clients, conn); s.mu.Unlock() }()
	bound := ""
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(p.Children) < 2 {
			return
		}
		messageID, ok := p.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := p.Children[1]
		switch op.Tag {
		case 0:
			if len(op.Children) < 3 {
				return
			}
			user := op.Children[1].Data.String()
			pass := op.Children[2].Data.String()
			expected, exists := s.Passwords[user]
			valid := exists && pass != "" && pass == expected
			bound = ""
			code := int64(49)
			if valid {
				bound = user
				code = 0
			}
			s.mu.Lock()
			s.binds = append(s.binds, Bind{Connection: id, User: user, Success: valid})
			s.mu.Unlock()
			if _, err = conn.Write(packet(messageID, result(1, code))); err != nil {
				return
			}
		case 3:
			if len(op.Children) < 7 {
				return
			}
			query := Search{User: bound, Filter: op.Children[6]}
			s.mu.Lock()
			s.searches = append(s.searches, query)
			s.mu.Unlock()
			entries, code := s.Lookup(query)
			for _, entry := range entries {
				response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
				response.AppendChild(str(entry.DN))
				attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				for key, values := range entry.Attributes {
					attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					attr.AppendChild(str(key))
					set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
					for _, value := range values {
						set.AppendChild(str(value))
					}
					attr.AppendChild(set)
					attributes.AppendChild(attr)
				}
				response.AppendChild(attributes)
				if _, err = conn.Write(packet(messageID, response)); err != nil {
					return
				}
			}
			if _, err = conn.Write(packet(messageID, result(5, code))); err != nil {
				return
			}
		case 2:
			return
		default:
			return
		}
	}
}
