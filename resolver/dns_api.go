package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gonetkit/security"

	"github.com/miekg/dns"
)

var validator = security.NewInputValidator()

// DNSAPIHandler handles DNS lookup requests
func DNSAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Validate and sanitize query parameter
	query := r.URL.Query().Get("query")
	validatedQuery, err := validator.ValidateDNSQuery(query)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Invalid query: " + err.Error()))
		return
	}

	// Validate type parameter
	typeq := r.URL.Query().Get("type")
	if typeq == "" {
		w.WriteHeader(400)
		w.Write([]byte("Missing type parameter"))
		return
	}

	// Validate allowed DNS types
	allowedTypes := map[string]bool{
		"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true,
		"CNAME": true, "PTR": true, "SOA": true, "SPF": true,
		"DKIM": true, "DMARC": true, "WHOIS": true,
	}
	if !allowedTypes[typeq] {
		w.WriteHeader(400)
		w.Write([]byte("Invalid DNS type"))
		return
	}

	// Validate and sanitize server parameter if provided
	dnsServer := r.URL.Query().Get("server")
	if dnsServer != "" {
		// Basic validation for DNS server format
		if len(dnsServer) > 100 || strings.ContainsAny(dnsServer, "\r\n\x00") {
			w.WriteHeader(400)
			w.Write([]byte("Invalid DNS server"))
			return
		}
	}

	var result string

	switch typeq {
	case "WHOIS":
		result = handleWHOISQuery(validatedQuery)
	case "SPF":
		result = handleSPFQuery(validatedQuery, dnsServer)
	case "DMARC":
		result = handleDMARCQuery(validatedQuery, dnsServer)
	case "DKIM":
		result = handleDKIMQuery(validatedQuery, dnsServer, r)
	default:
		result = handleStandardDNSQuery(validatedQuery, typeq, dnsServer)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(result))
}

func handleWHOISQuery(query string) string {
	resp, err := http.Get("https://rdap.org/domain/" + query)
	if err != nil {
		return "WHOIS lookup failed: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Try to parse JSON and extract key info
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err == nil {
		return parseWHOISData(data)
	}
	return string(body)
}

func parseWHOISData(data map[string]interface{}) string {
	var lines []string
	if v, ok := data["ldhName"]; ok {
		lines = append(lines, fmt.Sprintf("Domain: %v", v))
	}
	if v, ok := data["status"]; ok {
		if arr, ok := v.([]interface{}); ok {
			statusList := make([]string, len(arr))
			for i, x := range arr {
				statusList[i] = fmt.Sprintf("%v", x)
			}
			lines = append(lines, fmt.Sprintf("Status: %v", strings.Join(statusList, ", ")))
		} else {
			lines = append(lines, fmt.Sprintf("Status: %v", v))
		}
	}

	// Extract entity information (registrar, registrant)
	if v, ok := data["entities"]; ok {
		registrar, registrant := extractEntityInfo(v)
		if registrar != "" {
			lines = append(lines, registrar)
		}
		if registrant != "" {
			lines = append(lines, registrant)
		}
	}

	// Extract nameservers
	if v, ok := data["nameservers"]; ok {
		if nsarr, ok := v.([]interface{}); ok && len(nsarr) > 0 {
			nslist := make([]string, 0, len(nsarr))
			for _, ns := range nsarr {
				if nsmap, ok := ns.(map[string]interface{}); ok {
					if ldh, ok := nsmap["ldhName"]; ok {
						nslist = append(nslist, fmt.Sprintf("%v", ldh))
					}
				}
			}
			if len(nslist) > 0 {
				lines = append(lines, "Nameservers: "+strings.Join(nslist, ", "))
			}
		}
	}

	return strings.Join(lines, "\n")
}

func extractEntityInfo(entities interface{}) (string, string) {
	// This is a simplified version - the full implementation would be more complex
	// For now, return empty strings
	return "", ""
}

func handleSPFQuery(query, dnsServer string) string {
	var answers []string
	target := dns.Fqdn(query)
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}
		resolvers = []string{dnsServer}
	}

	for _, resolverAddr := range resolvers {
		m := new(dns.Msg)
		m.SetQuestion(target, dns.TypeTXT)
		resp, err := dns.Exchange(m, resolverAddr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			for _, ans := range resp.Answer {
				if t, ok := ans.(*dns.TXT); ok {
					for _, txt := range t.Txt {
						if strings.HasPrefix(txt, "v=spf1") {
							answers = append(answers, txt)
						}
					}
				}
			}
			break
		}
	}

	if len(answers) == 0 {
		return "No SPF record found."
	}
	return "SPF record(s):\n" + strings.Join(answers, "\n")
}

func handleDMARCQuery(query, dnsServer string) string {
	var answers []string
	dmarc := "_dmarc." + query
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dmarc), dns.TypeTXT)
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}
		resolvers = []string{dnsServer}
	}

	for _, resolverAddr := range resolvers {
		resp, err := dns.Exchange(m, resolverAddr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			for _, ans := range resp.Answer {
				if t, ok := ans.(*dns.TXT); ok {
					answers = append(answers, strings.Join(t.Txt, ""))
				}
			}
			break
		}
	}

	if len(answers) == 0 {
		return "No DMARC record found."
	}
	return "DMARC record(s):\n" + strings.Join(answers, "\n")
}

func handleDKIMQuery(query, dnsServer string, r *http.Request) string {
	var answers []string
	domain := query
	selector := r.URL.Query().Get("selector")
	if strings.Contains(query, ":") {
		parts := strings.SplitN(query, ":", 2)
		domain = parts[0]
		selector = parts[1]
	}
	if selector == "" {
		selector = "default"
	}
	if selector == "default" && !strings.Contains(query, ":") {
		answers = append(answers, "Tip: For DKIM, specify selector as domain:selector (e.g. example.com:selector1)")
	}

	dkim := selector + "._domainkey." + domain
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}
		resolvers = []string{dnsServer}
	}

	foundTXT := false
	var cnameTarget string
	for _, resolverAddr := range resolvers {
		// Try TXT first
		mTXT := new(dns.Msg)
		mTXT.SetQuestion(dns.Fqdn(dkim), dns.TypeTXT)
		txtResp, txtErr := dns.Exchange(mTXT, resolverAddr)
		if txtErr == nil && txtResp != nil && len(txtResp.Answer) > 0 {
			for _, ans := range txtResp.Answer {
				if t, ok := ans.(*dns.TXT); ok {
					answers = append(answers, strings.Join(t.Txt, ""))
					foundTXT = true
				}
			}
		}
		if foundTXT {
			break
		}

		// Try CNAME if no TXT found
		mCNAME := new(dns.Msg)
		mCNAME.SetQuestion(dns.Fqdn(dkim), dns.TypeCNAME)
		cnameResp, cnameErr := dns.Exchange(mCNAME, resolverAddr)
		if cnameErr == nil && cnameResp != nil && len(cnameResp.Answer) > 0 {
			for _, ans := range cnameResp.Answer {
				if c, ok := ans.(*dns.CNAME); ok {
					cnameTarget = c.Target
				}
			}
		}
		if cnameTarget != "" {
			// Query TXT at CNAME target
			m2 := new(dns.Msg)
			m2.SetQuestion(cnameTarget, dns.TypeTXT)
			resp2, err2 := dns.Exchange(m2, resolverAddr)
			if err2 == nil && resp2 != nil && len(resp2.Answer) > 0 {
				for _, ans2 := range resp2.Answer {
					if t2, ok := ans2.(*dns.TXT); ok {
						answers = append(answers, strings.Join(t2.Txt, ""))
						foundTXT = true
					}
				}
			}
			if foundTXT {
				answers = append(answers, "(via CNAME: "+cnameTarget+")")
				break
			}
		}
		if foundTXT {
			break
		}
	}

	if len(answers) == 0 || (len(answers) == 1 && strings.HasPrefix(answers[0], "Tip:")) {
		result := "No DKIM record found for selector '" + selector + "'."
		if len(answers) > 0 {
			result += "\n" + answers[0]
		}
		return result
	}
	return "DKIM record(s) for selector '" + selector + "':\n" + strings.Join(answers, "\n")
}

func handleStandardDNSQuery(query, typeq, dnsServer string) string {
	var result string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(query), dns.StringToType[typeq])
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if dnsServer != "" {
		if !strings.Contains(dnsServer, ":") {
			dnsServer = dnsServer + ":53"
		}
		resolvers = []string{dnsServer}
	}

	for _, resolverAddr := range resolvers {
		resp, err := dns.Exchange(m, resolverAddr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			for _, ans := range resp.Answer {
				result += ans.String() + "\n"
			}
			break
		}
	}

	if result == "" {
		result = "No result found."
	}
	return result
}
