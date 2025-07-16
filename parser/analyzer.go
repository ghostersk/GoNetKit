package parser

import (
	"fmt"
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"headeranalyzer/resolver"
)

type Report struct {
	// Basic Information
	From      string
	To        string
	Subject   string
	Date      string
	MessageID string
	UserAgent string
	Priority  string

	// Authentication
	SPFRecord    string
	SPFPass      bool
	SPFDetails   string
	DMARCRecord  string
	DMARCPass    bool
	DMARCDetails string
	DKIM         string
	DKIMPass     bool
	DKIMDetails  string

	// Routing & Security
	Received   []string
	ReturnPath string
	ReplyTo    string
	Blacklists []string
	XMailer    string

	// Content Analysis
	ContentType    string
	Encoding       string
	Authentication string
	SecurityFlags  []string

	// Potential Issues
	Warnings       []string
	SecurityScore  int // 0-100
	DeliveryStatus string

	// Sender Identification
	EnvelopeSender string // Return-Path
	FromDomain     string // Domain from From header
	SendingServer  string // Host/IP from first Received header

	// Header details for security analysis
	SPFHeader   string
	DMARCHeader string
	DKIMHeader  string

	// Encryption
	Encrypted        bool
	EncryptionDetail string

	// All headers for advanced view
	AllHeaders map[string]string

	// Enhanced Analysis
	SpamScore     string
	SpamFlags     []string
	VirusInfo     string
	ARC           []string // ARC chain for forwarded emails
	BIMI          string   // Brand Indicators for Message Identification
	ListInfo      []string // Mailing list information
	AutoReply     bool     // Auto-reply/vacation message detection
	BulkEmail     bool     // Bulk/marketing email detection
	PhishingRisk  string   // Phishing risk assessment
	SpoofingRisk  string   // Spoofing risk assessment
	DeliveryDelay string   // Time analysis between hops
	GeoLocation   string   // Geographic analysis of sending servers
	Compliance    []string // Compliance flags (GDPR, CAN-SPAM, etc.)
	ThreadInfo    string   // Message threading information
	Attachments   []string // Attachment analysis
	URLs          []string // URL analysis
	SenderRep     string   // Sender reputation summary
}

func decodeMIMEHeader(encoded string) string {
	decoder := &mime.WordDecoder{}
	decoded, err := decoder.DecodeHeader(encoded)
	if err != nil {
		// If decoding fails, return the original string
		return encoded
	}
	return decoded
}

func Analyze(raw string) *Report {
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return &Report{
			Warnings: []string{"Failed to parse email headers"},
		}
	}

	h := msg.Header
	allHeaders := make(map[string]string)
	for k, v := range h {
		allHeaders[k] = strings.Join(v, "\n")
	}

	report := &Report{
		From:           decodeMIMEHeader(h.Get("From")),
		To:             decodeMIMEHeader(h.Get("To")),
		Subject:        decodeMIMEHeader(h.Get("Subject")),
		Date:           h.Get("Date"),
		MessageID:      h.Get("Message-ID"),
		UserAgent:      getUserAgent(h),
		Priority:       getPriority(h),
		ReturnPath:     h.Get("Return-Path"),
		ReplyTo:        h.Get("Reply-To"),
		ContentType:    h.Get("Content-Type"),
		Encoding:       h.Get("Content-Transfer-Encoding"),
		Received:       h["Received"],
		XMailer:        h.Get("X-Mailer"),
		Authentication: h.Get("Authentication-Results"),
		AllHeaders:     allHeaders,
	}

	// Extract domain and IP
	domain := extractDomain(report.From)
	ip := extractSenderIP(report.Received)

	// Sender identification
	report.EnvelopeSender = report.ReturnPath
	report.FromDomain = domain
	report.SendingServer = extractSendingServer(report.Received)

	// Security Checks
	report.SecurityFlags = getSecurityFlags(h)
	report.Warnings = analyzeWarnings(h)

	// SPF, DMARC, DKIM header details
	report.SPFHeader = getFirstHeader(h, []string{"Authentication-Results", "Received-SPF"})
	report.DMARCHeader = getFirstHeader(h, []string{"Authentication-Results", "ARC-Authentication-Results"})
	report.DKIMHeader = getFirstHeader(h, []string{"DKIM-Signature", "Authentication-Results"})

	// SPF Check - first try to parse from Authentication-Results header
	report.SPFPass, report.SPFDetails = checkSPFResult(h)
	if !report.SPFPass {
		// Fallback to DNS lookup if not found in headers
		report.SPFRecord, report.SPFPass = resolver.CheckSPF(domain)
		if report.SPFDetails == "" {
			report.SPFDetails = analyzeSPF(report.SPFRecord)
		}
	} else {
		// If SPF passed in headers, still get the record for display
		report.SPFRecord, _ = resolver.CheckSPF(domain)
	}

	// DMARC Check - first try to parse from Authentication-Results header
	report.DMARCPass, report.DMARCDetails = checkDMARCResult(h)
	if !report.DMARCPass {
		// Fallback to DNS lookup if not found in headers
		report.DMARCRecord, report.DMARCPass = resolver.CheckDMARC(domain)
		if report.DMARCDetails == "" {
			report.DMARCDetails = analyzeDMARC(report.DMARCRecord)
		}
	} else {
		// If DMARC passed in headers, still get the record for display
		report.DMARCRecord, _ = resolver.CheckDMARC(domain)
	}

	// DKIM Check
	report.DKIM = h.Get("DKIM-Signature")
	report.DKIMPass, report.DKIMDetails = checkDKIMResult(h, report.DKIM)

	// Blacklist Check
	if ip != "" {
		report.Blacklists = resolver.CheckBlacklists(ip)
	}

	// Encryption analysis
	report.Encrypted, report.EncryptionDetail = analyzeEncryption(report.Received)

	// Calculate Security Score
	report.SecurityScore = calculateSecurityScore(report)

	// Analyze Delivery Status
	report.DeliveryStatus = analyzeDeliveryStatus(report)

	// --- Enhanced Analysis --- //

	// Spam detection (simple heuristic based on subject and content)
	if strings.Contains(strings.ToLower(report.Subject), "free") || strings.Contains(strings.ToLower(report.Subject), "win") {
		report.SpamScore = "High"
		report.SpamFlags = append(report.SpamFlags, "Contains common spam keywords")
	} else {
		report.SpamScore = "Low"
	}

	// Virus scanning (placeholder for integration with virus scanning service)
	if strings.Contains(report.Authentication, "virus") {
		report.VirusInfo = "Virus detected in the message"
	} else {
		report.VirusInfo = "No virus detected"
	}

	// Enhanced Analysis
	report.SpamScore = extractSpamScore(h)
	report.SpamFlags = extractSpamFlags(h)
	report.VirusInfo = extractVirusInfo(h)
	report.ARC = extractARCInfo(h)
	report.ListInfo = extractListInfo(h)
	report.AutoReply = detectAutoReply(h)
	report.BulkEmail = detectBulkEmail(h)
	report.PhishingRisk = assessPhishingRisk(report)
	report.SpoofingRisk = assessSpoofingRisk(report)
	report.DeliveryDelay = analyzeDeliveryDelay(report.Received)
	report.Compliance = extractComplianceFlags(h)
	report.ThreadInfo = extractThreadInfo(h)
	report.Attachments = extractAttachmentInfo(h)
	report.URLs = extractURLInfo(h)

	// BIMI check (placeholder for now)
	report.BIMI = h.Get("BIMI-Location")
	if report.BIMI == "" {
		report.BIMI = "No BIMI record found"
	}

	// Geo location (enhanced analysis)
	if ip != "" {
		geoInfo := analyzeIPGeography(ip, h)
		report.GeoLocation = geoInfo
	}

	// Sender reputation (simplified for now)
	report.SenderRep = assessSenderReputation(report)

	return report
}

func getUserAgent(h mail.Header) string {
	ua := h.Get("User-Agent")
	if ua == "" {
		ua = h.Get("X-Mailer")
	}
	return ua
}

func getPriority(h mail.Header) string {
	priority := h.Get("X-Priority")
	if priority == "" {
		priority = h.Get("Importance")
	}
	return priority
}

func getSecurityFlags(h mail.Header) []string {
	var flags []string
	if h.Get("X-Spam-Flag") != "" {
		flags = append(flags, "Spam Flag Present")
	}
	if h.Get("X-Virus-Scanned") != "" {
		flags = append(flags, "Virus Scanned")
	}
	return flags
}

func analyzeWarnings(h mail.Header) []string {
	var warnings []string
	if h.Get("From") != h.Get("Reply-To") && h.Get("Reply-To") != "" {
		warnings = append(warnings, "Reply-To address differs from From address")
	}
	if h.Get("X-Spam-Score") != "" {
		warnings = append(warnings, "Message was flagged by spam filters")
	}
	return warnings
}

func analyzeSPF(record string) string {
	if record == "" {
		return "No SPF record found - This may cause delivery issues"
	}
	if strings.Contains(record, "~all") {
		return "Soft fail configuration - Some non-authorized servers may send mail"
	}
	if strings.Contains(record, "-all") {
		return "Strict configuration - Only authorized servers can send mail"
	}
	return "SPF record present but not strict"
}

func analyzeDMARC(record string) string {
	if record == "" {
		return "No DMARC record found - This may affect deliverability"
	}
	if strings.Contains(record, "p=none") {
		return "Monitor-only mode - No enforcement"
	}
	if strings.Contains(record, "p=quarantine") {
		return "Suspicious messages may be quarantined"
	}
	if strings.Contains(record, "p=reject") {
		return "Strict enforcement - Failed messages are rejected"
	}
	return "DMARC record present"
}

func checkSPFResult(h mail.Header) (bool, string) {
	// Try to parse Authentication-Results for SPF result
	ar := h.Get("Authentication-Results")
	if ar != "" {
		// Split by semicolon and look for spf= entries
		arParts := strings.Split(ar, ";")
		for _, part := range arParts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "spf=") {
				// Example: spf=pass reason=mailfrom (ip=205.220.166.231, headerfrom=marshcommercial.co.uk)
				if strings.Contains(strings.ToLower(part), "spf=pass") {
					return true, "SPF passed according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "spf=fail") {
					return false, "SPF failed according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "spf=neutral") {
					return false, "SPF neutral according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "spf=softfail") {
					return false, "SPF soft fail according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "spf=temperror") {
					return false, "SPF temporary error according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "spf=permerror") {
					return false, "SPF permanent error according to Authentication-Results: " + part
				}
				// If we found spf= but no recognized result, return the raw text
				return false, "SPF result found but not recognized: " + part
			}
		}
	}

	// Also check Received-SPF header as fallback
	receivedSPF := h.Get("Received-SPF")
	if receivedSPF != "" {
		if strings.Contains(strings.ToLower(receivedSPF), "pass") {
			return true, "SPF passed according to Received-SPF: " + receivedSPF
		}
		if strings.Contains(strings.ToLower(receivedSPF), "fail") {
			return false, "SPF failed according to Received-SPF: " + receivedSPF
		}
	}

	return false, ""
}

func checkDMARCResult(h mail.Header) (bool, string) {
	// Try to parse Authentication-Results for DMARC result
	ar := h.Get("Authentication-Results")
	if ar != "" {
		// Split by semicolon and look for dmarc= entries
		arParts := strings.Split(ar, ";")
		for _, part := range arParts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "dmarc=") {
				// Example: dmarc=pass hse.action=pass header.from=marshcommercial.co.uk
				if strings.Contains(strings.ToLower(part), "dmarc=pass") {
					return true, "DMARC passed according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "dmarc=fail") {
					return false, "DMARC failed according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "dmarc=temperror") {
					return false, "DMARC temporary error according to Authentication-Results: " + part
				}
				if strings.Contains(strings.ToLower(part), "dmarc=permerror") {
					return false, "DMARC permanent error according to Authentication-Results: " + part
				}
				// If we found dmarc= but no recognized result, return the raw text
				return false, "DMARC result found but not recognized: " + part
			}
		}
	}

	return false, ""
}

func checkDKIMResult(h mail.Header, dkimHeader string) (bool, string) {
	// Try to parse Authentication-Results for DKIM result
	ar := h.Get("Authentication-Results")
	if ar != "" {
		arLines := strings.Split(ar, ";")
		for _, line := range arLines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "dkim=") {
				// Example: dkim=pass (signature was verified) header.d=example.com;
				if strings.Contains(line, "pass") {
					return true, line
				}
				if strings.Contains(line, "fail") {
					return false, line
				}
				if strings.Contains(line, "neutral") {
					return false, line
				}
			}
		}
	}
	// Fallback: if DKIM header exists, assume present but not verified
	if dkimHeader != "" {
		return true, "DKIM-Signature header present, but no Authentication-Results found"
	}
	return false, "No DKIM signature found"
}

func calculateSecurityScore(r *Report) int {
	score := 0

	// Base score from authentication
	if r.SPFPass {
		score += 20
	}
	if r.DMARCPass {
		score += 20
	}
	if r.DKIMPass {
		score += 20
	}

	// Penalty for blacklists
	score -= len(r.Blacklists) * 15

	// Bonus for security features
	if len(r.SecurityFlags) > 0 {
		score += 10
	}

	// Penalty for warnings
	score -= len(r.Warnings) * 5

	// Ensure score stays within 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

func analyzeDeliveryStatus(r *Report) string {
	if len(r.Blacklists) > 0 {
		return "High Risk - Listed on blacklists"
	}

	if r.SecurityScore >= 80 {
		return "Excellent - Should deliver reliably"
	} else if r.SecurityScore >= 60 {
		return "Good - May have minor delivery issues"
	} else if r.SecurityScore >= 40 {
		return "Fair - Could face delivery problems"
	} else {
		return "Poor - Likely to have delivery issues"
	}
}

func extractDomain(from string) string {
	r := regexp.MustCompile(`@([a-zA-Z0-9.-]+)`)
	m := r.FindStringSubmatch(from)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func extractSenderIP(received []string) string {
	r := regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)
	for _, line := range received {
		m := r.FindString(line)
		if m != "" && !strings.HasPrefix(m, "127.") {
			return m
		}
	}
	return ""
}

func extractSendingServer(received []string) string {
	if len(received) > 0 {
		r := regexp.MustCompile(`from\s+([^\s]+)`)
		m := r.FindStringSubmatch(received[0])
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func getFirstHeader(h mail.Header, keys []string) string {
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func analyzeEncryption(received []string) (bool, string) {
	for _, line := range received {
		if strings.Contains(strings.ToLower(line), "tls") || strings.Contains(line, "ESMTPS") || strings.Contains(line, "with ESMTPS") || strings.Contains(line, "with TLS") {
			return true, line
		}
	}
	return false, "No evidence of encryption (TLS) found in Received headers"
}

func extractTimeFromReceived(received string) *time.Time {
	// Try to extract timestamp from Received header
	// Format 1: "Tue, 15 Jul 2025 14:47:49 +0200"
	re1 := regexp.MustCompile(`;\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]\d{4})`)
	matches := re1.FindStringSubmatch(received)
	if len(matches) > 1 {
		t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 -0700", matches[1])
		if err == nil {
			return &t
		}
	}

	// Format 2: "Tue, 15 Jul 2025 12:47:33 GMT"
	re2 := regexp.MustCompile(`;\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT)`)
	matches = re2.FindStringSubmatch(received)
	if len(matches) > 1 {
		t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 GMT", matches[1])
		if err == nil {
			return &t
		}
	}

	// Format 3: Extract any timestamp pattern at the end of line
	re3 := regexp.MustCompile(`(\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})`)
	matches = re3.FindStringSubmatch(received)
	if len(matches) > 1 {
		t, err := time.Parse("2 Jan 2006 15:04:05", matches[1])
		if err == nil {
			return &t
		}
	}

	// Format 4: Try with day name prefix
	re4 := regexp.MustCompile(`([A-Za-z]{3},?\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})`)
	matches = re4.FindStringSubmatch(received)
	if len(matches) > 1 {
		// Try different formats
		formats := []string{
			"Mon, 2 Jan 2006 15:04:05",
			"Mon 2 Jan 2006 15:04:05",
			"2 Jan 2006 15:04:05",
		}
		for _, format := range formats {
			t, err := time.Parse(format, matches[1])
			if err == nil {
				return &t
			}
		}
	}

	return nil
}

// Enhanced Analysis Functions

func extractSpamScore(h mail.Header) string {
	// Check various spam score headers
	if score := h.Get("X-Spam-Score"); score != "" {
		return "X-Spam-Score: " + score
	}
	if score := h.Get("X-SpamAssassin-Score"); score != "" {
		return "SpamAssassin Score: " + score
	}
	if score := h.Get("X-Microsoft-Antispam-Mailbox-Delivery"); score != "" {
		return "Microsoft Antispam: " + score
	}
	if score := h.Get("X-Barracuda-Spam-Score"); score != "" {
		return "Barracuda Score: " + score
	}

	// AntiSpamEurope specific (from your example)
	if reason := h.Get("X-antispameurope-REASON"); reason != "" {
		status := h.Get("X-antispameurope-Spamstatus")
		if status != "" {
			return fmt.Sprintf("AntiSpamEurope: %s (%s)", status, reason)
		}
		return "AntiSpamEurope: " + reason
	}

	// Hornetsecurity specific
	if h.Get("X-hornetsecurity-identifier") != "" {
		return "Hornetsecurity Security Gateway processed"
	}

	return "No spam score found"
}

func extractSpamFlags(h mail.Header) []string {
	var flags []string

	// Standard spam flags
	if h.Get("X-Spam-Flag") == "YES" {
		flags = append(flags, "Marked as Spam")
	}
	if h.Get("X-Spam-Status") != "" {
		flags = append(flags, "Spam Status: "+h.Get("X-Spam-Status"))
	}
	if h.Get("X-Spam-Level") != "" {
		flags = append(flags, "Spam Level: "+h.Get("X-Spam-Level"))
	}

	// Microsoft-specific
	if h.Get("X-MS-Exchange-Organization-SCL") != "" {
		flags = append(flags, "Exchange SCL: "+h.Get("X-MS-Exchange-Organization-SCL"))
	}
	if h.Get("X-Microsoft-Antispam") != "" {
		flags = append(flags, "Microsoft Antispam detected")
	}

	// Google-specific
	if h.Get("X-Gm-Message-State") != "" {
		flags = append(flags, "Gmail State: "+h.Get("X-Gm-Message-State"))
	}

	// Hornetsecurity/AntiSpamEurope specific (from your example)
	if h.Get("X-antispameurope-Spamstatus") != "" {
		flags = append(flags, "AntiSpamEurope Status: "+h.Get("X-antispameurope-Spamstatus"))
	}
	if h.Get("X-antispameurope-REASON") != "" {
		flags = append(flags, "AntiSpamEurope Reason: "+h.Get("X-antispameurope-REASON"))
	}
	if h.Get("X-antispameurope-Virusscan") != "" {
		flags = append(flags, "AntiSpamEurope Virus Scan: "+h.Get("X-antispameurope-Virusscan"))
	}

	// Generic detection
	if h.Get("X-Quarantine-ID") != "" {
		flags = append(flags, "Message was quarantined")
	}

	return flags
}

func extractVirusInfo(h mail.Header) string {
	if scan := h.Get("X-Virus-Scanned"); scan != "" {
		status := "Virus Scanned: " + scan
		if clean := h.Get("X-Virus-Status"); clean != "" {
			status += " | Status: " + clean
		}
		return status
	}
	if clam := h.Get("X-Clam-Scanned"); clam != "" {
		return "ClamAV Scanned: " + clam
	}
	if mcafee := h.Get("X-McAfee-Virus-Scanned"); mcafee != "" {
		return "McAfee Scanned: " + mcafee
	}
	return "No virus scanning information found"
}

func extractListInfo(h mail.Header) []string {
	var info []string

	if listId := h.Get("List-ID"); listId != "" {
		info = append(info, "List-ID: "+listId)
	}
	if listPost := h.Get("List-Post"); listPost != "" {
		info = append(info, "List-Post: "+listPost)
	}
	if listUnsubscribe := h.Get("List-Unsubscribe"); listUnsubscribe != "" {
		info = append(info, "Unsubscribe: "+listUnsubscribe)
	}
	if precedence := h.Get("Precedence"); precedence != "" {
		info = append(info, "Precedence: "+precedence)
	}

	return info
}

func detectAutoReply(h mail.Header) bool {
	// Check for auto-reply indicators
	if h.Get("X-Autoreply") != "" || h.Get("Auto-Submitted") != "" {
		return true
	}
	if h.Get("X-Auto-Response-Suppress") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("Subject")), "out of office") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("Subject")), "automatic reply") {
		return true
	}
	return false
}

func detectBulkEmail(h mail.Header) bool {
	// Check for bulk email indicators
	if h.Get("Precedence") == "bulk" || h.Get("Precedence") == "junk" {
		return true
	}
	if h.Get("X-Bulk") != "" || h.Get("X-Campaign-ID") != "" {
		return true
	}
	if h.Get("List-Unsubscribe") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-Mailer")), "mailchimp") ||
		strings.Contains(strings.ToLower(h.Get("X-Mailer")), "constant contact") {
		return true
	}
	return false
}

func assessPhishingRisk(r *Report) string {
	risk := 0
	reasons := []string{}

	// Check for domain mismatches
	if r.EnvelopeSender != "" && r.From != "" {
		envDomain := extractDomain(r.EnvelopeSender)
		fromDomain := extractDomain(r.From)
		if envDomain != "" && fromDomain != "" && envDomain != fromDomain {
			risk += 30
			reasons = append(reasons, "Envelope and From domain mismatch")
		}
	}

	// Check for failed authentication
	if !r.SPFPass {
		risk += 20
		reasons = append(reasons, "SPF failed")
	}
	if !r.DMARCPass {
		risk += 20
		reasons = append(reasons, "DMARC failed")
	}
	if !r.DKIMPass {
		risk += 15
		reasons = append(reasons, "DKIM missing/failed")
	}

	// Check for suspicious reply-to
	if r.ReplyTo != "" && r.ReplyTo != r.From {
		risk += 10
		reasons = append(reasons, "Reply-To differs from From")
	}

	// Assess risk level
	if risk >= 50 {
		return "HIGH RISK: " + strings.Join(reasons, ", ")
	} else if risk >= 25 {
		return "MEDIUM RISK: " + strings.Join(reasons, ", ")
	} else if risk > 0 {
		return "LOW RISK: " + strings.Join(reasons, ", ")
	}

	return "LOW RISK: No significant phishing indicators detected"
}

func assessSpoofingRisk(r *Report) string {
	risks := []string{}

	// Check for display name spoofing
	if strings.Contains(r.From, "<") && strings.Contains(r.From, ">") {
		// Extract display name and email
		re := regexp.MustCompile(`^([^<]+)<([^>]+)>`)
		matches := re.FindStringSubmatch(r.From)
		if len(matches) == 3 {
			displayName := strings.TrimSpace(matches[1])
			email := strings.TrimSpace(matches[2])

			// Check if display name looks like it's trying to spoof another domain
			if strings.Contains(strings.ToLower(displayName), "@") {
				risks = append(risks, "Display name contains @ symbol")
			}

			// Check for common spoofing patterns
			commonDomains := []string{"gmail", "yahoo", "outlook", "hotmail", "microsoft", "apple", "amazon", "paypal", "ebay"}
			for _, domain := range commonDomains {
				if strings.Contains(strings.ToLower(displayName), domain) &&
					!strings.Contains(strings.ToLower(email), domain) {
					risks = append(risks, "Display name suggests "+domain+" but email domain differs")
				}
			}
		}
	}

	// Check for authentication failures
	if !r.SPFPass || !r.DMARCPass {
		risks = append(risks, "Authentication failures increase spoofing risk")
	}

	if len(risks) > 0 {
		return "POTENTIAL SPOOFING: " + strings.Join(risks, ", ")
	}

	return "No obvious spoofing indicators detected"
}

func analyzeDeliveryDelay(received []string) string {
	if len(received) < 2 {
		return "Insufficient data for delay analysis (need at least 2 Received headers)"
	}

	// Try to extract timestamps from received headers
	var timestamps []struct {
		time  time.Time
		index int
	}

	for i, header := range received {
		if t := extractTimeFromReceived(header); t != nil {
			timestamps = append(timestamps, struct {
				time  time.Time
				index int
			}{*t, i})
		}
	}

	if len(timestamps) < 2 {
		return "Could not extract enough timestamps for delay analysis"
	}

	// Calculate delays between consecutive hops
	var delays []string
	totalDelay := time.Duration(0)

	// Sort timestamps by index (received headers are in reverse chronological order)
	for i := 0; i < len(timestamps)-1; i++ {
		// Since Received headers are added in reverse order, we calculate from later to earlier
		var delay time.Duration
		if timestamps[i].index < timestamps[i+1].index {
			delay = timestamps[i].time.Sub(timestamps[i+1].time)
		} else {
			delay = timestamps[i+1].time.Sub(timestamps[i].time)
		}

		if delay > 0 {
			delays = append(delays, fmt.Sprintf("Hop %d→%d: %v", timestamps[i+1].index+1, timestamps[i].index+1, delay))
			totalDelay += delay
		}
	}

	if len(delays) == 0 {
		return "Could not calculate meaningful delivery delays"
	}

	result := fmt.Sprintf("Total delivery time: %v | ", totalDelay)
	result += strings.Join(delays, ", ")

	// Add analysis
	if totalDelay > 24*time.Hour {
		result += " | ⚠️ Unusually long delivery time"
	} else if totalDelay > 1*time.Hour {
		result += " | ⚠️ Slow delivery"
	} else if totalDelay < 1*time.Minute {
		result += " | ✅ Very fast delivery"
	} else {
		result += " | ✅ Normal delivery time"
	}

	return result
}

func extractComplianceFlags(h mail.Header) []string {
	var flags []string

	// CAN-SPAM compliance
	if h.Get("List-Unsubscribe") != "" {
		flags = append(flags, "CAN-SPAM: Unsubscribe link provided")
	}

	// GDPR indicators
	if strings.Contains(strings.ToLower(h.Get("Subject")), "gdpr") ||
		strings.Contains(strings.ToLower(h.Get("Subject")), "privacy policy") {
		flags = append(flags, "GDPR: Privacy-related content detected")
	}

	// Marketing compliance
	if h.Get("X-Campaign-ID") != "" {
		flags = append(flags, "Marketing: Campaign tracking detected")
	}

	// Auto-suppression compliance
	if h.Get("X-Auto-Response-Suppress") != "" {
		flags = append(flags, "Auto-response suppression headers present")
	}

	return flags
}

func extractThreadInfo(h mail.Header) string {
	var info []string

	if threadIndex := h.Get("Thread-Index"); threadIndex != "" {
		info = append(info, "Thread-Index: "+threadIndex)
	}
	if threadTopic := h.Get("Thread-Topic"); threadTopic != "" {
		info = append(info, "Thread-Topic: "+threadTopic)
	}
	if inReplyTo := h.Get("In-Reply-To"); inReplyTo != "" {
		info = append(info, "In-Reply-To: "+inReplyTo)
	}
	if references := h.Get("References"); references != "" {
		info = append(info, "References: "+references)
	}

	if len(info) == 0 {
		return "No threading information available"
	}

	return strings.Join(info, " | ")
}

func extractAttachmentInfo(h mail.Header) []string {
	var attachments []string

	// Look for attachment indicators in headers
	if disposition := h.Get("Content-Disposition"); strings.Contains(strings.ToLower(disposition), "attachment") {
		attachments = append(attachments, "Content-Disposition indicates attachment")
	}

	// Check for common attachment-related headers
	if h.Get("X-Attachment-Id") != "" {
		attachments = append(attachments, "Attachment ID present")
	}

	// Look for MIME boundaries which might indicate attachments
	if contentType := h.Get("Content-Type"); strings.Contains(strings.ToLower(contentType), "multipart") {
		attachments = append(attachments, "Multipart content (may contain attachments)")
	}

	return attachments
}

func extractURLInfo(h mail.Header) []string {
	var urls []string

	// Look for URL-related headers
	if h.Get("X-Originating-URL") != "" {
		urls = append(urls, "Originating URL: "+h.Get("X-Originating-URL"))
	}

	// Check for tracking URLs in headers
	if h.Get("X-Campaign-ID") != "" {
		urls = append(urls, "Campaign tracking detected")
	}

	if h.Get("List-Unsubscribe") != "" {
		urls = append(urls, "Unsubscribe URL present")
	}

	return urls
}

func assessSenderReputation(r *Report) string {
	score := 0
	factors := []string{}

	// Positive factors
	if r.SPFPass {
		score += 25
		factors = append(factors, "+SPF")
	}
	if r.DMARCPass {
		score += 25
		factors = append(factors, "+DMARC")
	}
	if r.DKIMPass {
		score += 20
		factors = append(factors, "+DKIM")
	}
	if r.Encrypted {
		score += 10
		factors = append(factors, "+TLS")
	}

	// Negative factors
	if len(r.Blacklists) > 0 {
		score -= 50
		factors = append(factors, "-Blacklisted")
	}
	if len(r.SpamFlags) > 0 {
		score -= 20
		factors = append(factors, "-Spam flags")
	}
	if r.PhishingRisk != "" && strings.HasPrefix(r.PhishingRisk, "HIGH") {
		score -= 30
		factors = append(factors, "-High phishing risk")
	}

	// Ensure score stays within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	reputation := ""
	if score >= 80 {
		reputation = "EXCELLENT"
	} else if score >= 60 {
		reputation = "GOOD"
	} else if score >= 40 {
		reputation = "FAIR"
	} else if score >= 20 {
		reputation = "POOR"
	} else {
		reputation = "VERY POOR"
	}

	return fmt.Sprintf("%s (%d/100) - Factors: %s", reputation, score, strings.Join(factors, ", "))
}

func extractARCInfo(h mail.Header) []string {
	var arc []string

	// Collect all ARC-related headers
	if arcAuth := h.Get("ARC-Authentication-Results"); arcAuth != "" {
		arc = append(arc, "ARC-Authentication-Results: "+arcAuth)
	}
	if arcSig := h.Get("ARC-Message-Signature"); arcSig != "" {
		arc = append(arc, "ARC-Message-Signature: "+arcSig)
	}
	if arcSeal := h.Get("ARC-Seal"); arcSeal != "" {
		arc = append(arc, "ARC-Seal: "+arcSeal)
	}

	// If no specific ARC headers, check for multiple ARC headers with instance numbers
	for key, values := range h {
		if strings.HasPrefix(key, "ARC-") {
			for _, value := range values {
				arcEntry := key + ": " + value
				// Avoid duplicates
				found := false
				for _, existing := range arc {
					if strings.Contains(existing, value) {
						found = true
						break
					}
				}
				if !found {
					arc = append(arc, arcEntry)
				}
			}
		}
	}

	return arc
}

func analyzeIPGeography(ip string, h mail.Header) string {
	var info []string

	info = append(info, "IP: "+ip)

	// Extract server information from headers
	if mailgunIP := h.Get("X-Mailgun-Sending-Ip"); mailgunIP != "" && mailgunIP == ip {
		info = append(info, "Service: Mailgun Email Service")
	}

	// Look for hostname clues in Received headers
	for _, received := range h["Received"] {
		if strings.Contains(received, ip) {
			// Extract hostname from received header
			re := regexp.MustCompile(`from\s+([^\s\[\(]+)`)
			matches := re.FindStringSubmatch(received)
			if len(matches) > 1 {
				hostname := matches[1]
				info = append(info, "Hostname: "+hostname)

				// Analyze hostname for geographic/service clues
				hostname = strings.ToLower(hostname)
				if strings.Contains(hostname, ".eu.") || strings.Contains(hostname, "europe") {
					info = append(info, "Region: Europe (based on hostname)")
				}
				if strings.Contains(hostname, ".us.") || strings.Contains(hostname, "america") {
					info = append(info, "Region: Americas (based on hostname)")
				}
				if strings.Contains(hostname, ".asia.") || strings.Contains(hostname, "asia") {
					info = append(info, "Region: Asia (based on hostname)")
				}

				// Service detection
				if strings.Contains(hostname, "mailgun") {
					info = append(info, "Service: Mailgun Email Service")
				}
				if strings.Contains(hostname, "sendgrid") {
					info = append(info, "Service: SendGrid Email Service")
				}
				if strings.Contains(hostname, "amazonses") || strings.Contains(hostname, "aws") {
					info = append(info, "Service: Amazon SES")
				}
				if strings.Contains(hostname, "outlook") || strings.Contains(hostname, "microsoft") {
					info = append(info, "Service: Microsoft Exchange/Outlook")
				}
				if strings.Contains(hostname, "google") || strings.Contains(hostname, "gmail") {
					info = append(info, "Service: Google/Gmail")
				}

				break
			}
		}
	}

	// IP range analysis (basic)
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.") {
		info = append(info, "Type: Private/Internal IP")
	} else {
		info = append(info, "Type: Public IP")

		// Basic geographic hints from IP ranges (very basic)
		if strings.HasPrefix(ip, "161.38.") {
			info = append(info, "ISP: Likely European hosting provider")
		}
	}

	info = append(info, "(Full geographic lookup requires external GeoIP service)")

	return strings.Join(info, " | ")
}
