package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
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
	"headeranalyzer/resolver"

	"github.com/getlantern/systray"
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
		iconPath = "web/favicon.ico"
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

	// Create handlers with separate template sets
	indexHandler := parser.NewHandler(embeddedFiles)
	dnsHandler := resolver.NewHandler(embeddedFiles)
	passwordHandler := passwordgenerator.NewHandler(embeddedFiles)

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

	http.Handle("/", indexHandler)

	http.Handle("/dns", dnsHandler)

	http.HandleFunc("/api/dns", resolver.DNSAPIHandler)

	http.Handle("/password", passwordHandler)

	http.HandleFunc("/api/password", passwordgenerator.PasswordAPIHandler)

	http.HandleFunc("/api/password/info", passwordgenerator.PasswordInfoAPIHandler)

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
