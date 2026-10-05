package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/4ym3nn/leasegate/internal/gate"
)

type config struct {
	Mode                   string `json:"mode"`
	Listen                 string `json:"listen"`
	Database               string `json:"database"`
	Cert                   string `json:"cert"`
	Key                    string `json:"key"`
	CA                     string `json:"ca"`
	GrantPrivate           string `json:"grantPrivate"`
	GrantPublic            string `json:"grantPublic"`
	AuditKey               string `json:"auditKey"`
	ReleasePublic          string `json:"releasePublic"`
	Provider               string `json:"provider"`
	ProviderCredentialFile string `json:"providerCredentialFile"`
	RuntimePassword        string `json:"runtimePassword"`
	ProviderPassword       string `json:"providerPassword"`
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: leasegate serve|init|worker|sign-artifact|verify-audit")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "serve", "init":
		path := fs.String("config", "", "configuration file")
		must(fs.Parse(os.Args[2:]))
		var c config
		must(read(*path, &c))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		store, err := gate.Open(ctx, c.Database)
		must(err)
		defer store.Pool.Close()
		if os.Args[1] == "init" {
			must(store.Migrate(ctx))
			must((&gate.Provider{Store: store}).Migrate(ctx))
			for _, p := range []struct{ tenant, name, role string }{{"acme", "alice", "requester"}, {"acme", "approver", "approver"}, {"acme", "operator", "operator"}, {"beta", "bob", "requester"}, {"platform", "operator", "operator"}, {"platform", "auditor", "auditor"}} {
				must(store.Bootstrap(ctx, "spiffe://leasegate.local/tenant/"+p.tenant+"/user/"+p.name, p.tenant, p.role))
			}
			must(roles(ctx, store, c))
			fmt.Println("Schema and synthetic reference identities initialized")
			return
		}
		tlsConfig, err := gate.TLSConfig(c.Cert, c.Key, c.CA)
		must(err)
		var handler http.Handler
		if c.Mode == "provider" {
			secret, err := os.ReadFile(c.ProviderCredentialFile)
			must(err)
			handler = &gate.Provider{Store: store, Credential: strings.TrimSpace(string(secret))}
		} else {
			s := &gate.Server{Store: store, Mode: c.Mode, Slots: make(chan struct{}, 64)}
			s.GrantPublic, err = gate.ReadPublic(c.GrantPublic)
			must(err)
			if c.Mode == "control" {
				s.GrantPrivate, err = gate.ReadPrivate(c.GrantPrivate)
				must(err)
				s.AuditKey, err = gate.ReadPrivate(c.AuditKey)
				must(err)
				s.ReleaseKey, err = gate.ReadPublic(c.ReleasePublic)
				must(err)
			} else if c.Mode == "gateway" {
				if !strings.HasPrefix(c.Provider, "https://") {
					log.Fatal("provider requires HTTPS")
				}
				secret, err := os.ReadFile(c.ProviderCredentialFile)
				must(err)
				s.ProviderCredential = strings.TrimSpace(string(secret))
				if len(s.ProviderCredential) < 32 {
					log.Fatal("provider credential is too short")
				}
				s.Provider = c.Provider
				s.Client = gate.TLSClient(tlsConfig.Clone())
			} else {
				log.Fatal("unknown server mode")
			}
			handler = s
		}
		server := &http.Server{Addr: c.Listen, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
		shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		go func() {
			<-shutdown.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
		}()
		log.Printf("leasegate %s listening on %s with required mTLS", c.Mode, c.Listen)
		err = server.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			must(err)
		}
	case "worker":
		path := fs.String("config", "", "job configuration")
		must(fs.Parse(os.Args[2:]))
		must(worker(*path))
	case "sign-artifact":
		keyPath := fs.String("key", "", "Ed25519 build signing key")
		digest := fs.String("digest", "", "immutable image digest")
		revision := fs.String("revision", "", "source commit")
		must(fs.Parse(os.Args[2:]))
		key, err := gate.ReadPrivate(*keyPath)
		must(err)
		must(json.NewEncoder(os.Stdout).Encode(gate.SignStatement(gate.Statement{ImageDigest: *digest, SourceRevision: *revision, Builder: "leasegate.reference-builder", ExpiresAt: time.Now().Add(time.Hour).Unix()}, key)))
	case "verify-audit":
		path := fs.String("events", "", "audit export")
		witness := fs.String("checkpoint", "", "independently retained checkpoint")
		keyPath := fs.String("key", "", "trusted audit public key")
		must(fs.Parse(os.Args[2:]))
		var export struct {
			Entries    []gate.AuditEntry `json:"entries"`
			Checkpoint gate.Checkpoint   `json:"checkpoint"`
		}
		must(read(*path, &export))
		var cp gate.Checkpoint
		must(read(*witness, &cp))
		key, err := gate.ReadPublic(*keyPath)
		must(err)
		must(gate.VerifyAudit(export.Entries, cp, key))
		fmt.Printf("Verified %d entries against the retained signed checkpoint\n", len(export.Entries))
	default:
		log.Fatal("unknown command")
	}
}
func read(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return gate.StrictJSON(data, v)
}
func roles(ctx context.Context, s *gate.Store, c config) error {
	if !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(c.RuntimePassword) || !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(c.ProviderPassword) {
		return errors.New("fixture role passwords require 24 random bytes encoded as hex")
	}
	for _, r := range []struct{ name, password string }{{"leasegate_runtime", c.RuntimePassword}, {"leasegate_provider", c.ProviderPassword}} {
		var exists bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, r.name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err := s.Pool.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", r.name, r.password)); err != nil {
				return err
			}
		}
	}
	_, err := s.Pool.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO leasegate_runtime,leasegate_provider;
GRANT SELECT,INSERT,UPDATE ON principals,artifacts,jobs,claims,audit_head TO leasegate_runtime;
GRANT SELECT,INSERT ON audit TO leasegate_runtime;
GRANT SELECT ON provider_documents TO leasegate_provider;
GRANT SELECT,INSERT ON provider_exports TO leasegate_provider;`)
	return err
}

type workerConfig struct {
	Gateway      string       `json:"gateway"`
	Cert         string       `json:"cert"`
	Key          string       `json:"key"`
	CA           string       `json:"ca"`
	Request      gate.Execute `json:"request"`
	ProbeAddress string       `json:"probeAddress,omitempty"`
}

func worker(path string) error {
	var c workerConfig
	if err := read(path, &c); err != nil {
		return err
	}
	config, err := gate.TLSConfig(c.Cert, c.Key, c.CA)
	if err != nil {
		return err
	}
	if c.ProbeAddress != "" {
		conn, err := net.DialTimeout("tcp", c.ProbeAddress, time.Second)
		if err == nil {
			conn.Close()
			return errors.New("isolation probe unexpectedly reached the private provider network")
		}
		fmt.Println("PASS: direct provider connection blocked")
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return err
		}
		value := string(status)
		if !strings.Contains(value, "CapEff:\t0000000000000000") || !strings.Contains(value, "NoNewPrivs:\t1") || !strings.Contains(value, "Seccomp:\t2") {
			return errors.New("worker process restrictions missing")
		}
		fmt.Println("PASS: no capabilities, no new privileges, seccomp filtering")
		if file, err := os.OpenFile("/leasegate-write-probe", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			file.Close()
			os.Remove("/leasegate-write-probe")
			return errors.New("worker root filesystem is writable")
		}
		fmt.Println("PASS: root filesystem rejects writes")
	}
	data, _ := json.Marshal(c.Request)
	req, err := http.NewRequest("POST", c.Gateway+"/execute", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := gate.TLSClient(config).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(data) > 8192 {
		return errors.New("invalid gateway response")
	}
	fmt.Printf("HTTP %d %s", resp.StatusCode, data)
	if resp.StatusCode != 201 {
		return errors.New("job did not complete")
	}
	return nil
}
