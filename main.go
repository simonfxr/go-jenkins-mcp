package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = ""

func getVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// resolveCacheDir determines the log cache directory. "none" (or "off")
// disables the disk cache; an empty value selects the user cache directory.
// A missing or unwritable directory is not an error: logs then stay in memory.
func resolveCacheDir(flagValue string) string {
	dir := flagValue
	if dir == "" {
		dir = os.Getenv("JENKINS_MCP_CACHE_DIR")
	}
	switch strings.ToLower(dir) {
	case "none", "off":
		return ""
	case "":
		base, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		return filepath.Join(base, "go-jenkins-mcp")
	}
	return dir
}

func newServer(opts *JenkinsOptions) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "jenkins-mcp-go", Version: getVersion()},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)
	opts.addTools(server)
	return server
}

func main() {
	// Prepare options and bind flags directly to fields.
	opts := &JenkinsOptions{}
	var (
		httpAddr string
		useStdio bool
		showVer  bool
		cacheDir string
	)

	flag.StringVar(&opts.URL, "url", "", "Jenkins URL (required)")
	flag.StringVar(&opts.Auth, "auth", "", "Jenkins authentication in format 'user:api_token' (optional if JENKINS_MCP_AUTH env var is set)")
	flag.StringVar(&httpAddr, "http", "", "if set, use streamable HTTP at this address, instead of stdin/stdout")
	flag.BoolVar(&useStdio, "stdio", true, "use stdio transport (ignored if -http is set)")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.StringVar(&cacheDir, "cache-dir", "", "directory for cached build logs (default: JENKINS_MCP_CACHE_DIR or <user cache dir>/go-jenkins-mcp; 'none' disables the disk cache)")
	flag.Parse()

	if showVer {
		fmt.Println(getVersion())
		return
	}

	// Validate required parameters
	if opts.URL == "" {
		fmt.Fprintln(os.Stderr, "Error: -url parameter is required")
		os.Exit(1)
	}

	// Use environment variable if -auth flag is not provided
	if opts.Auth == "" {
		if envAuth := os.Getenv("JENKINS_MCP_AUTH"); envAuth != "" {
			opts.Auth = envAuth
		} else {
			fmt.Fprintln(os.Stderr, "Error: authentication required via -auth parameter or JENKINS_MCP_AUTH environment variable")
			os.Exit(1)
		}
	}

	// Validate auth format
	if !strings.Contains(opts.Auth, ":") {
		fmt.Fprintln(os.Stderr, "Error: -auth must be in format 'user:api_token'")
		os.Exit(1)
	}

	opts.User, opts.Token, _ = strings.Cut(opts.Auth, ":")
	opts.init(resolveCacheDir(cacheDir), defaultFallbackCacheDir())

	log.Printf("Using Jenkins URL: %s", opts.URL)
	log.Printf("Using Jenkins auth for user: %s", opts.User)

	server := newServer(opts)

	// Choose transport
	if httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
		log.Printf("Starting MCP HTTP server on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			log.Fatalf("http server error: %v", err)
		}
	} else if useStdio {
		log.Printf("Starting MCP server over stdio")
		t := &mcp.LoggingTransport{Transport: &mcp.StdioTransport{}, Writer: os.Stderr}
		if err := server.Run(context.Background(), t); err != nil {
			log.Printf("server error: %v", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: no transport selected. Use -http or -stdio.")
		os.Exit(1)
	}
}
