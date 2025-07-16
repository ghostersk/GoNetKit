package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"headeranalyzer/parser"
	"headeranalyzer/passwordgenerator"

	"github.com/getlantern/systray"
	"github.com/miekg/dns"
)

var (
	addr     = flag.String("host", "127.0.0.1", "IP to bind")
	port     = flag.Int("port", 5555, "Port to run on")
	headless = flag.Bool("headless", false, "Force headless mode (disable system tray)")
)

//go:embed web/*
var embeddedFiles embed.FS

func onReady(addrPort string, shutdownCh chan struct{}) {
	var iconPath string
	if runtime.GOOS == "windows" {
		iconPath = "web/favicon.ico"
	} else {
		iconPath = "web/favicon.png"
	}

	iconData, err := fs.ReadFile(embeddedFiles, iconPath)
	if err != nil {
		log.Printf("Failed to load system tray icon (%s): %v", iconPath, err)
		return
	}
	if len(iconData) == 0 {
		log.Printf("System tray icon (%s) is empty", iconPath)
		return
	}
	log.Printf("Loaded system tray icon (%s): %d bytes", iconPath, len(iconData))

	// SetIcon does not return an error, so call it directly
	systray.SetIcon(iconData)

	systray.SetTitle("HeaderAnalyzer")
	systray.SetTooltip("Email Header Analyzer")
	mOpen := systray.AddMenuItem("Open Web UI", "Open the web interface")
	mQuit := systray.AddMenuItem("Quit", "Quit the app")
	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				url := "http://" + addrPort
				openBrowser(url)
			case <-mQuit.ClickedCh:
				systray.Quit()
				close(shutdownCh)
				return
			}
		}
	}()
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}

// isHeadless checks if the system is running in a headless environment
func isHeadless() bool {
	// Check for common headless indicators
	if runtime.GOOS == "windows" {
		// On Windows, assume GUI is available
		return false
	}

	// Check if DISPLAY is set (X11)
	if display := os.Getenv("DISPLAY"); display != "" {
		return false
	}

	// Check if WAYLAND_DISPLAY is set (Wayland)
	if waylandDisplay := os.Getenv("WAYLAND_DISPLAY"); waylandDisplay != "" {
		return false
	}

	// Check if XDG_SESSION_TYPE indicates a graphical session
	if sessionType := os.Getenv("XDG_SESSION_TYPE"); sessionType == "x11" || sessionType == "wayland" {
		return false
	}

	// Check if we're in SSH session
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != "" {
		return true
	}

	// Check if TERM indicates we're in a terminal
	if term := os.Getenv("TERM"); term == "linux" || strings.Contains(term, "tty") {
		return true
	}

	// If none of the above, assume headless on Linux/Unix
	return runtime.GOOS == "linux"
}

func main() {
	flag.Parse()

	// Initialize password generator word list
	passwordgenerator.InitWordList()

	tmpl := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"splitString": func(s, delimiter string) []string {
			return strings.Split(s, delimiter)
		},
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
	}).ParseFS(embeddedFiles, "web/index.html"))

	// Use embedded static files for web assets
	staticFS, err := fs.Sub(embeddedFiles, "web")
	if err != nil {
		panic(err)
	}
	// Serve static files from embedded FS
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Serve favicon and tray icon from embedded FS
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(staticFS, "favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(data)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			headers := r.FormValue("headers")
			report := parser.Analyze(headers)
			tmpl.Execute(w, report)
			return
		}
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
		dnsTmpl := template.Must(template.ParseFS(embeddedFiles, "web/dns.html"))
		dnsTmpl.Execute(w, nil)
	})

	http.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		typeq := r.URL.Query().Get("type")
		if query == "" || typeq == "" {
			w.WriteHeader(400)
			w.Write([]byte("Missing query or type"))
			return
		}
		dnsServer := r.URL.Query().Get("server")
		var result string
		switch typeq {
		case "WHOIS":
			resp, err := http.Get("https://rdap.org/domain/" + query)
			if err != nil {
				result = "WHOIS lookup failed: " + err.Error()
			} else {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				// Try to parse JSON and extract key info
				var data map[string]interface{}
				if err := json.Unmarshal(body, &data); err == nil {
					var lines []string
					if v, ok := data["ldhName"]; ok {
						lines = append(lines, fmt.Sprintf("Domain: %v", v))
					}
					if v, ok := data["status"]; ok {
						if arr, ok := v.([]interface{}); ok {
							lines = append(lines, fmt.Sprintf("Status: %v", strings.Join(func() []string {
								s := make([]string, len(arr))
								for i, x := range arr {
									s[i] = fmt.Sprintf("%v", x)
								}
								return s
							}(), ", ")))
						} else {
							lines = append(lines, fmt.Sprintf("Status: %v", v))
						}
					}
					var registrar, registrarIANA string
					var registrant, registrantEmail, registrantPhone, registrantOrg, registrantCountry string
					if v, ok := data["entities"]; ok {
						if ents, ok := v.([]interface{}); ok {
							for _, ent := range ents {
								if entmap, ok := ent.(map[string]interface{}); ok {
									var rolestr string
									if roles, ok := entmap["roles"]; ok {
										if rlist, ok := roles.([]interface{}); ok {
											for _, r := range rlist {
												rolestr = fmt.Sprintf("%v", r)
												if rolestr == "registrar" {
													if v, ok := entmap["vcardArray"]; ok {
														if vcard, ok := v.([]interface{}); ok && len(vcard) > 1 {
															if props, ok := vcard[1].([]interface{}); ok {
																for _, prop := range props {
																	if arr, ok := prop.([]interface{}); ok && len(arr) > 3 {
																		if arr[0] == "fn" {
																			registrar = fmt.Sprintf("%v", arr[3])
																		}
																		if arr[0] == "org" {
																			registrar = fmt.Sprintf("%v", arr[3])
																		}
																		if arr[0] == "ianaRegistrarId" {
																			registrarIANA = fmt.Sprintf("%v", arr[3])
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
									if rolestr == "registrant" {
										if v, ok := entmap["vcardArray"]; ok {
											if vcard, ok := v.([]interface{}); ok && len(vcard) > 1 {
												if props, ok := vcard[1].([]interface{}); ok {
													for _, prop := range props {
														if arr, ok := prop.([]interface{}); ok && len(arr) > 3 {
															if arr[0] == "fn" {
																registrant = fmt.Sprintf("%v", arr[3])
															}
															if arr[0] == "email" {
																registrantEmail = fmt.Sprintf("%v", arr[3])
															}
															if arr[0] == "tel" {
																registrantPhone = fmt.Sprintf("%v", arr[3])
															}
															if arr[0] == "org" {
																registrantOrg = fmt.Sprintf("%v", arr[3])
															}
															if arr[0] == "adr" {
																if adr, ok := arr[3].([]interface{}); ok && len(adr) > 6 {
																	registrantCountry = fmt.Sprintf("%v", adr[6])
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
					if registrar != "" {
						lines = append(lines, "Registrar: "+registrar)
					}
					if registrarIANA != "" {
						lines = append(lines, "Registrar IANA ID: "+registrarIANA)
					}
					if registrant != "" {
						lines = append(lines, "Registrant: "+registrant)
					}
					if registrantOrg != "" {
						lines = append(lines, "Registrant Org: "+registrantOrg)
					}
					if registrantEmail != "" {
						lines = append(lines, "Registrant Email: "+registrantEmail)
					}
					if registrantPhone != "" {
						lines = append(lines, "Registrant Phone: "+registrantPhone)
					}
					if registrantCountry != "" {
						lines = append(lines, "Registrant Country: "+registrantCountry)
					}
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
					if v, ok := data["secureDNS"]; ok {
						if sec, ok := v.(map[string]interface{}); ok {
							if ds, ok := sec["delegationSigned"]; ok {
								lines = append(lines, fmt.Sprintf("DNSSEC: %v", ds))
							}
						}
					}
					if v, ok := data["events"]; ok {
						if evs, ok := v.([]interface{}); ok {
							for _, ev := range evs {
								if evm, ok := ev.(map[string]interface{}); ok {
									if action, ok := evm["eventAction"]; ok {
										if date, ok := evm["eventDate"]; ok {
											lines = append(lines, fmt.Sprintf("%v: %v", action, date))
										}
									}
								}
							}
						}
					}
					if v, ok := data["remarks"]; ok {
						if rems, ok := v.([]interface{}); ok {
							for _, rem := range rems {
								if remm, ok := rem.(map[string]interface{}); ok {
									if desc, ok := remm["description"]; ok {
										if descarr, ok := desc.([]interface{}); ok && len(descarr) > 0 {
											lines = append(lines, fmt.Sprintf("Remark: %v", descarr[0]))
										}
									}
								}
							}
						}
					}
					result = strings.Join(lines, "\n")
				} else {
					result = string(body)
				}
			}
		default:
			// Special handling for SPF, DKIM, DMARC
			var answers []string
			switch strings.ToUpper(typeq) {
			case "SPF":
				// Query TXT records and filter for SPF
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
					result = "No SPF record found."
				} else {
					result = "SPF record(s):\n" + strings.Join(answers, "\n")
				}
			case "DMARC":
				// Query _dmarc.<domain> TXT
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
					result = "No DMARC record found."
				} else {
					result = "DMARC record(s):\n" + strings.Join(answers, "\n")
				}
			case "DKIM":
				// Query <selector>._domainkey.<domain> TXT, if not found, check CNAME and then TXT at CNAME target
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
					// 1. Query TXT at DKIM name
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
					// 2. If no TXT, query CNAME at DKIM name
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
						// 3. Query TXT at CNAME target
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
					result = "No DKIM record found for selector '" + selector + "'."
					if len(answers) > 0 {
						result += "\n" + answers[0]
					}
				} else {
					result = "DKIM record(s) for selector '" + selector + "':\n" + strings.Join(answers, "\n")
				}
			default:
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
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result))
	})

	http.HandleFunc("/password", func(w http.ResponseWriter, r *http.Request) {
		passwordTmpl := template.Must(template.ParseFS(embeddedFiles, "web/password.html"))
		passwordTmpl.Execute(w, nil)
	})

	http.HandleFunc("/api/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var config passwordgenerator.Config
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid JSON"))
			return
		}

		password, err := passwordgenerator.GeneratePassword(config)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(password))
	})

	http.HandleFunc("/api/password/info", func(w http.ResponseWriter, r *http.Request) {
		count, source, lastUpdate := passwordgenerator.GetWordListInfo()

		info := map[string]interface{}{
			"wordCount":  count,
			"source":     source,
			"lastUpdate": lastUpdate.Format("2006-01-02 15:04:05"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})

	addrPort := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Printf("Listening on http://%s\n", addrPort)

	srv := &http.Server{Addr: addrPort}
	shutdownCh := make(chan struct{})

	go func() {
		log.Fatal(srv.ListenAndServe())
	}()

	// Check if we're in a headless environment
	if *headless || isHeadless() {
		if *headless {
			fmt.Println("Headless mode forced via command line flag.")
		} else {
			fmt.Println("Headless environment detected. System tray disabled.")
		}
		fmt.Printf("Access the web interface at: http://%s\n", addrPort)
		fmt.Println("Press Ctrl+C to stop the server.")

		// Set up signal handling for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Wait for interrupt signal
		<-sigChan
		fmt.Println("\nShutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	} else {
		fmt.Println("GUI environment detected. Starting system tray...")
		systray.Run(func() { onReady(addrPort, shutdownCh) }, func() {})

		<-shutdownCh
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
}
