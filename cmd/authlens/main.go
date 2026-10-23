package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexandrmotologa/authlens/internal/fuzzer"
	"github.com/alexandrmotologa/authlens/internal/jwt"
	"github.com/alexandrmotologa/authlens/internal/keys"
	"github.com/alexandrmotologa/authlens/internal/persona"
	"github.com/alexandrmotologa/authlens/internal/server"
)

const version = "1.0.0"

func printBanner() {
	banner := `
    ___         __  __    __                     
   /   | __  __/ /_/ /_  / /   ___  ____  _____
  / /| |/ / / / __/ __ \/ /   / _ \/ __ \/ ___/
 / ___ / /_/ / /_/ / / / /___/  __/ / / (__  ) 
/_/  |_\__,_/\__/_/ /_/_____/\___/_/ /_/____/   v%s
  Local OIDC Provider, PKCE Tracer & JWT Security Lab
`
	fmt.Printf(banner, version)
}

func printHelp() {
	printBanner()
	fmt.Print(`Usage:
  authlens [command] [options]

Commands:
  serve       Start local OIDC server & web studio (default port 9099)
  token       Generate instant JWT bearer token for a simulated persona
  verify      Perform offline cryptographic validation of a JWT token
  test        Execute token tampering attacks against a target backend API
  jwks        Display local JSON Web Key Set (JWKS)
  version     Display version information

Options:
  --port      Port to bind server to (default: 9099)
  --host      Host interface to bind (default: 127.0.0.1)
  --persona   Simulated identity for token command: admin, developer, suspended (default: admin)
  --format    Output format for token: raw, json, curl (default: raw)
  --target    Target backend URL for security test command
  --header    Custom authorization header template (default: "Authorization: Bearer {{token}}")
  --method    HTTP method for test command: GET, POST (default: GET)
`)
}

func main() {
	if len(os.Args) < 2 {
		runServe(9099, "127.0.0.1")
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "serve":
		serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
		port := serveFlags.Int("port", 9099, "Port to listen on")
		host := serveFlags.String("host", "127.0.0.1", "Host to bind to")
		_ = serveFlags.Parse(os.Args[2:])
		runServe(*port, *host)

	case "token":
		tokenFlags := flag.NewFlagSet("token", flag.ExitOnError)
		personaID := tokenFlags.String("persona", "admin", "Persona: admin, developer, suspended")
		format := tokenFlags.String("format", "raw", "Format: raw, json, curl")
		port := tokenFlags.Int("port", 9099, "AuthLens server port")
		_ = tokenFlags.Parse(os.Args[2:])
		runToken(*personaID, *format, *port)

	case "verify":
		if len(os.Args) < 3 {
			fmt.Println("Error: token argument required. Example: authlens verify eyJhbGci...")
			os.Exit(1)
		}
		runVerify(os.Args[2])

	case "test":
		testFlags := flag.NewFlagSet("test", flag.ExitOnError)
		target := testFlags.String("target", "", "Target backend endpoint URL (required)")
		method := testFlags.String("method", "GET", "HTTP method: GET, POST")
		header := testFlags.String("header", "Authorization: Bearer {{token}}", "Header format")
		_ = testFlags.Parse(os.Args[2:])
		if *target == "" {
			fmt.Println("Error: --target URL required. Example: authlens test --target http://localhost:8080/api/users")
			os.Exit(1)
		}
		runTest(*target, *method, *header)

	case "jwks":
		runJWKS()

	case "version", "-v", "--version":
		fmt.Printf("AuthLens v%s\n", version)

	case "help", "-h", "--help":
		printHelp()

	default:
		// Check if user passed flags directly without subcommand, e.g. authlens --port 9099
		if strings.HasPrefix(cmd, "-") {
			serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
			port := serveFlags.Int("port", 9099, "Port to listen on")
			host := serveFlags.String("host", "127.0.0.1", "Host to bind to")
			_ = serveFlags.Parse(os.Args[1:])
			runServe(*port, *host)
			return
		}
		fmt.Printf("Unknown command %q\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func runServe(port int, host string) {
	printBanner()

	cfg := server.Config{
		Host:    host,
		Port:    port,
		BaseURL: fmt.Sprintf("http://%s:%d", host, port),
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		fmt.Printf("Error initializing AuthLens server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] OpenID Connect Provider active on %s\n", cfg.BaseURL)
	fmt.Printf("[+] Discovery Endpoint:  %s/.well-known/openid-configuration\n", cfg.BaseURL)
	fmt.Printf("[+] JWKS Endpoint:       %s/.well-known/jwks.json\n", cfg.BaseURL)
	fmt.Printf("[+] Authorization URL:   %s/oauth/authorize\n", cfg.BaseURL)
	fmt.Printf("[+] Token URL:           %s/oauth/token\n", cfg.BaseURL)
	fmt.Printf("[+] UserInfo URL:        %s/userinfo\n", cfg.BaseURL)
	fmt.Printf("[+] Interactive Studio:  %s\n\n", cfg.BaseURL)
	fmt.Println("Press Ctrl+C to terminate server.")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			fmt.Printf("Server failure: %v\n", err)
			os.Exit(1)
		}
	}()

	<-quit
	fmt.Println("\n[*] Shutting down AuthLens server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	fmt.Println("[+] Server terminated cleanly.")
}

func runToken(personaID, format string, port int) {
	km, err := keys.NewKeyManager()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	registry := persona.NewRegistry()
	p, err := registry.Get(personaID)
	if err != nil {
		fmt.Printf("Error: persona %q not found. Available: admin, developer, suspended\n", personaID)
		os.Exit(1)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	tokenStr, err := jwt.SignPersonaToken(p, km, baseURL, baseURL+"/api", "RS256", 2*time.Hour)
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		os.Exit(1)
	}

	switch format {
	case "raw":
		fmt.Println(tokenStr)
	case "curl":
		fmt.Printf("curl -H \"Authorization: Bearer %s\" %s/userinfo\n", tokenStr, baseURL)
	case "json":
		out := map[string]any{
			"token_type":   "Bearer",
			"access_token": tokenStr,
			"persona":      p.ID,
			"sub":          p.Sub,
			"email":        p.Email,
			"roles":        p.Roles,
			"expires_in":   7200,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Println(tokenStr)
	}
}

func runVerify(tokenStr string) {
	fmt.Println("[*] Decoding JWT 100% offline...")
	decoded, err := jwt.DecodeOffline(tokenStr)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=======================================================")
	fmt.Printf(" Algorithm: %s\n", decoded.Algorithm)
	fmt.Printf(" Key ID:    %s\n", decoded.KeyID)
	fmt.Printf(" Type:      %s\n", decoded.TokenType)
	fmt.Println("-------------------------------------------------------")
	fmt.Printf(" Subject:   %s\n", decoded.Subject)
	fmt.Printf(" Issuer:    %s\n", decoded.Issuer)
	fmt.Printf(" Audience:  %v\n", decoded.Audience)
	if decoded.ExpiresAt != nil {
		fmt.Printf(" Expires:   %s (TTL: %d seconds, Expired: %v)\n", decoded.ExpiresAt.Format(time.RFC3339), decoded.TTLSeconds, decoded.IsExpired)
	}
	if decoded.NotBefore != nil {
		fmt.Printf(" Not Before:%s\n", decoded.NotBefore.Format(time.RFC3339))
	}
	fmt.Println("-------------------------------------------------------")
	fmt.Printf(" Signature: %d bytes (present: %v)\n", decoded.SignatureSize, decoded.HasSignature)
	fmt.Println("=======================================================")

	payloadJSON, _ := json.MarshalIndent(decoded.Payload, "", "  ")
	fmt.Println("\nPayload Claims:")
	fmt.Println(string(payloadJSON))
}

func runTest(targetURL, method, headerFormat string) {
	fmt.Println("[*] Initializing AuthLens Security Fuzzer...")
	km, err := keys.NewKeyManager()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fuzzGen := fuzzer.NewAttackGenerator(km, "http://127.0.0.1:9099")
	p := &persona.Persona{
		Sub:   "usr_security_fuzzer_probe",
		Name:  "Security Probe",
		Email: "probe@local.test",
		Roles: []string{"user"},
	}

	vectors, err := fuzzGen.GenerateAll(p)
	if err != nil {
		fmt.Printf("Error generating test vectors: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Testing target: %s [%s]\n", targetURL, method)
	fmt.Printf("[*] Executing %d adversarial token test vectors...\n\n", len(vectors))

	report := fuzzer.RunSuite(context.Background(), targetURL, method, headerFormat, vectors)

	fmt.Printf("%-32s | %-12s | %-10s | %-10s\n", "Attack Vector", "Severity", "Status", "Verdict")
	fmt.Println(strings.Repeat("-", 72))

	for _, r := range report.Results {
		statusStr := fmt.Sprintf("%d", r.StatusCode)
		if r.StatusCode == 0 {
			statusStr = "CONN_ERR"
		}
		fmt.Printf("%-32s | %-12s | %-10s | %-10s\n", r.VectorName[:min(32, len(r.VectorName))], r.Severity, statusStr, r.Verdict)
	}

	fmt.Println(strings.Repeat("=", 72))
	fmt.Printf("Summary: Total: %d | Secure: %d | Vulnerable: %d | Errors: %d | Security Score: %.1f%%\n",
		report.TotalTests, report.Passed, report.Failed, report.Errors, report.ScorePct)
}

func runJWKS() {
	km, err := keys.NewKeyManager()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	jwks, err := km.GetJWKS()
	if err != nil {
		fmt.Printf("Error building JWKS: %v\n", err)
		os.Exit(1)
	}

	b, _ := json.MarshalIndent(jwks, "", "  ")
	fmt.Println(string(b))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
