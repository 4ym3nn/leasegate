package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Server struct {
	Store              *Store
	Mode               string
	GrantPrivate       ed25519.PrivateKey
	GrantPublic        ed25519.PublicKey
	AuditKey           ed25519.PrivateKey
	ReleaseKey         ed25519.PublicKey
	Provider           string
	ProviderCredential string
	Client             *http.Client
	requests           atomic.Int64
	denied             atomic.Int64
	admitted           atomic.Int64
	completed          atomic.Int64
	uncertain          atomic.Int64
	Slots              chan struct{}
}

func TLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, RootCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}, nil
}
func TLSClient(config *tls.Config) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config, MaxIdleConnsPerHost: 8, ResponseHeaderTimeout: 4 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func body(r *http.Request, v any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(data) > 65536 {
		return invalid()
	}
	if err = StrictJSON(data, v); err != nil {
		return invalid()
	}
	return nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	default:
		writeJSON(w, 429, map[string]string{"error": "CAPACITY_LIMIT"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	id, err := IdentityFrom(r)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "IDENTITY_REQUIRED"})
		return
	}
	if r.URL.RawQuery != "" {
		s.failure(w, r, id, invalid())
		return
	}
	if r.Method == "GET" && r.URL.Path == "/health" {
		if err = s.Store.Pool.Ping(ctx); err != nil {
			s.failure(w, r, id, err)
		} else {
			writeJSON(w, 200, map[string]string{"status": "ready", "mode": s.Mode})
		}
		return
	}
	if r.Method == "GET" && r.URL.Path == "/metrics" {
		if err := s.Store.AuthorizeAuditor(ctx, id); err != nil {
			s.failure(w, r, id, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "leasegate_requests_total %d\nleasegate_denied_total %d\nleasegate_admitted_total %d\nleasegate_completed_total %d\nleasegate_uncertain_total %d\n", s.requests.Load(), s.denied.Load(), s.admitted.Load(), s.completed.Load(), s.uncertain.Load())
		return
	}
	if s.Mode == "gateway" {
		if r.Method != "POST" || r.URL.Path != "/execute" {
			writeJSON(w, 404, map[string]string{"error": "NOT_FOUND"})
			return
		}
		var request Execute
		if err = body(r, &request); err != nil {
			s.failure(w, r, id, err)
			return
		}
		if !uuidPattern.MatchString(request.JobID) {
			s.failure(w, r, id, invalid())
			return
		}
		claims, err := VerifyGrant(request.Token, s.GrantPublic, time.Now())
		if err != nil {
			s.failure(w, r, id, deny("INVALID_GRANT"))
			return
		}
		j, err := s.Store.Admit(ctx, id, request, claims)
		if err != nil {
			s.failure(w, r, id, err)
			return
		}
		s.admitted.Add(1)
		receipt, err := s.effect(ctx, j)
		if err != nil {
			s.uncertain.Add(1)
			_ = s.Store.Finish(ctx, j, "")
			writeJSON(w, 503, map[string]any{"status": "uncertain", "jobId": j.ID, "retry": false})
			return
		}
		if err = s.Store.Finish(ctx, j, receipt); err != nil {
			s.uncertain.Add(1)
			writeJSON(w, 202, map[string]any{"status": "completed_audit_pending", "receipt": receipt, "jobId": j.ID, "retry": false})
			return
		}
		s.completed.Add(1)
		writeJSON(w, 201, map[string]any{"status": "completed", "receipt": receipt, "jobId": j.ID, "retry": false})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/artifacts" {
		var a Attestation
		if err = body(r, &a); err == nil {
			err = s.Store.RegisterArtifact(ctx, id, a, s.ReleaseKey)
		}
		if err != nil {
			s.failure(w, r, id, err)
		} else {
			writeJSON(w, 201, map[string]string{"status": "admitted"})
		}
		return
	}
	if r.Method == "POST" && r.URL.Path == "/jobs" {
		var input NewJob
		if err = body(r, &input); err != nil {
			s.failure(w, r, id, err)
			return
		}
		j, err := s.Store.Create(ctx, id, input)
		if err != nil {
			s.failure(w, r, id, err)
		} else {
			writeJSON(w, 201, j)
		}
		return
	}
	if r.Method == "GET" && r.URL.Path == "/audit" {
		entries, cp, err := s.Store.Audit(ctx, id, s.AuditKey)
		if err != nil {
			s.failure(w, r, id, err)
		} else {
			writeJSON(w, 200, map[string]any{"entries": entries, "checkpoint": cp})
		}
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 3 && parts[0] == "principals" && parts[2] == "disable" && r.Method == "POST" {
		if err = s.Store.DisablePrincipal(ctx, id, parts[1]); err != nil {
			s.failure(w, r, id, err)
		} else {
			writeJSON(w, 200, map[string]string{"status": "disabled"})
		}
		return
	}
	if len(parts) >= 2 && parts[0] == "jobs" && uuidPattern.MatchString(parts[1]) {
		jobID := parts[1]
		if len(parts) == 2 && r.Method == "GET" {
			j, err := s.Store.Read(ctx, id, jobID)
			if err != nil {
				s.failure(w, r, id, err)
			} else {
				writeJSON(w, 200, j)
			}
			return
		}
		if len(parts) == 3 && r.Method == "POST" {
			switch parts[2] {
			case "approve":
				err = s.Store.Approve(ctx, id, jobID)
			case "revoke":
				err = s.Store.Revoke(ctx, id, jobID)
			case "delegate":
				var input struct {
					Lifetime int `json:"lifetimeSeconds"`
				}
				if err = body(r, &input); err != nil {
					break
				}
				var j Job
				j, err = s.Store.Delegate(ctx, id, jobID, input.Lifetime)
				if err == nil {
					writeJSON(w, 201, j)
					return
				}
			case "grant":
				var token string
				token, err = s.Store.Issue(ctx, id, jobID, s.GrantPrivate)
				if err == nil {
					writeJSON(w, 200, map[string]string{"token": token})
					return
				}
			default:
				writeJSON(w, 404, map[string]string{"error": "NOT_FOUND"})
				return
			}
			if err != nil {
				s.failure(w, r, id, err)
			} else {
				writeJSON(w, 200, map[string]string{"status": "ok"})
			}
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "NOT_FOUND"})
}
func (s *Server) failure(w http.ResponseWriter, r *http.Request, id Identity, err error) {
	s.denied.Add(1)
	status := 503
	code := "DEPENDENCY_UNAVAILABLE"
	var f *Failure
	if errors.As(err, &f) {
		status = f.Status
		code = f.Code
	}
	s.Store.RecordDenial(r.Context(), id, code)
	writeJSON(w, status, map[string]string{"error": code})
}
func (s *Server) effect(ctx context.Context, j Job) (string, error) {
	data, _ := json.Marshal(ProviderOperation{j.ID, j.Tenant, j.Document, j.Version, j.Destination})
	req, err := http.NewRequestWithContext(ctx, "POST", s.Provider+"/export", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.ProviderCredential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return "", errors.New("provider did not confirm effect")
	}
	var value struct {
		Receipt string `json:"receipt"`
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("invalid provider response")
	}
	if err = StrictJSON(data, &value); err != nil || !uuidPattern.MatchString(value.Receipt) {
		return "", errors.New("invalid receipt")
	}
	return value.Receipt, nil
}
