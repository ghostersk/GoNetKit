package resolver

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

func lookupTXT(domain string) ([]string, error) {
	for _, server := range resolvers {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
		resp, err := dns.Exchange(m, server)
		if err != nil || resp == nil {
			continue
		}
		var results []string
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				results = append(results, txt.Txt...)
			}
		}
		if len(results) > 0 {
			return results, nil
		}
	}
	return nil, fmt.Errorf("no TXT records found")
}

func CheckSPF(domain string) (string, bool) {
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", false
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt, true
		}
	}
	return "", false
}

func CheckDMARC(domain string) (string, bool) {
	dmarc := "_dmarc." + domain
	txts, err := lookupTXT(dmarc)
	if err != nil || len(txts) == 0 {
		return "", false
	}
	return txts[0], true
}

var rbls = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

func CheckBlacklists(ip string) []string {
	var listed []string
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return listed
	}
	reversed := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
	for _, rbl := range rbls {
		query := fmt.Sprintf("%s.%s.", reversed, rbl)
		m := new(dns.Msg)
		m.SetQuestion(query, dns.TypeA)
		for _, resolver := range resolvers {
			resp, err := dns.Exchange(m, resolver)
			if err == nil && resp != nil && len(resp.Answer) > 0 {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						ip := a.A.String()
						if strings.HasPrefix(ip, "127.0.0.") {
							listed = append(listed, rbl)
							break
						}
					}
				}
			}
		}
	}
	return listed
}
