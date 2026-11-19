package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type WorkstationSurveyOptions struct {
	Resolvers []string
	Queries   []string
}
type SurveyDNSResult struct {
	Resolver   string    `json:"resolver"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Transport  string    `json:"transport"`
	Observed   time.Time `json:"observed"`
	Status     string    `json:"status"`
	RCode      string    `json:"rcode,omitempty"`
	Answers    []string  `json:"answers"`
	DurationMS int64     `json:"durationMs"`
	Truncated  bool      `json:"truncated,omitempty"`
}

var surveyDNSTypes = map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME, "SRV": dns.TypeSRV, "SOA": dns.TypeSOA, "NS": dns.TypeNS}

func validateSurveyDNSOptions(in WorkstationSurveyOptions) error {
	if len(in.Resolvers) > 4 || len(in.Queries) > 8 || (len(in.Resolvers) == 0) != (len(in.Queries) == 0) {
		return fmt.Errorf("DNS survey requires 1–4 resolver IPs and 1–8 name/TYPE queries, or neither")
	}
	for _, s := range in.Resolvers {
		if _, e := netip.ParseAddr(s); e != nil {
			return fmt.Errorf("DNS resolver must be an explicit IP address")
		}
	}
	for _, q := range in.Queries {
		if _, _, e := surveyDNSQuery(q); e != nil {
			return e
		}
	}
	return nil
}
func surveyDNSQuery(q string) (string, uint16, error) {
	name, kind, ok := strings.Cut(q, "/")
	kind = strings.ToUpper(kind)
	name = strings.TrimSuffix(name, ".")
	if !ok || surveyDNSTypes[kind] == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return "", 0, fmt.Errorf("DNS query must be FQDN/A|AAAA|CNAME|SRV|SOA|NS")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", 0, fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return "", 0, fmt.Errorf("invalid DNS name")
			}
		}
	}
	return strings.ToLower(name) + ".", surveyDNSTypes[kind], nil
}

type surveyDNSExchange func(context.Context, *dns.Msg, string, string) (*dns.Msg, time.Duration, error)

func exchangeSurveyDNS(ctx context.Context, m *dns.Msg, addr, transport string) (*dns.Msg, time.Duration, error) {
	client := dns.Client{Net: transport, Timeout: 2 * time.Second}
	return client.ExchangeContext(ctx, m, addr)
}
func collectSurveyDNS(ctx context.Context, in WorkstationSurveyOptions, exchange surveyDNSExchange) []SurveyDNSResult {
	var out []SurveyDNSResult
	for _, resolver := range in.Resolvers {
		for _, query := range in.Queries {
			name, kind, _ := surveyDNSQuery(query)
			for _, transport := range []string{"udp", "tcp"} {
				out = append(out, SurveyDNSResult{Resolver: resolver, Name: name, Type: dns.TypeToString[kind], Transport: transport, Status: "unknown", Answers: []string{}})
			}
		}
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	for w := 0; w < 4; w++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				o := &out[i]
				o.Observed = time.Now().UTC()
				m := new(dns.Msg)
				m.SetQuestion(o.Name, surveyDNSTypes[o.Type])
				probe, cancel := context.WithTimeout(ctx, 2*time.Second)
				response, duration, err := exchange(probe, m, net.JoinHostPort(o.Resolver, "53"), o.Transport)
				cancel()
				o.DurationMS = duration.Milliseconds()
				if err != nil || response == nil {
					continue
				}
				o.RCode = dns.RcodeToString[response.Rcode]
				o.Truncated = response.Truncated
				o.Status = "observed"
				for _, rr := range response.Answer {
					if len(o.Answers) == 32 {
						o.Truncated = true
						break
					}
					line := rr.String()
					if len(line) > 2048 {
						o.Truncated = true
						continue
					}
					o.Answers = append(o.Answers, line)
				}
				sort.Strings(o.Answers)
				if o.Truncated {
					o.Status = "partial"
				}
			}
		}()
	}
	for i := range out {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	return out
}
