package gate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGrantBindings(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(2000000000, 0)
	valid := Claims{2, "grant-1", "leasegate", "leasegate-gateway", Subject{"alice", "acme"}, "document.export", Resource{"document", "report", "acme"}, now.Unix(), now.Unix(), now.Unix() + 60, "export", ParameterHash("tenant", "job-1", "1")}
	token, _ := SignGrant(valid, key)
	if _, err := VerifyGrant(token, pub, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Claims){
		"tenant":        func(c *Claims) { c.Resource.Tenant = "beta" },
		"audience":      func(c *Claims) { c.Audience = "other" },
		"issuer":        func(c *Claims) { c.Issuer = "other" },
		"action":        func(c *Claims) { c.Action = "document.delete" },
		"version":       func(c *Claims) { c.Version = 1 },
		"expired":       func(c *Claims) { c.ExpiresAt = now.Unix() },
		"future":        func(c *Claims) { c.NotBefore = now.Unix() + 1 },
		"long lifetime": func(c *Claims) { c.ExpiresAt = now.Unix() + 301 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			token, _ := SignGrant(c, key)
			if _, err := VerifyGrant(token, pub, now); err == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, bad := range []string{token + "=", token + ".extra", "", strings.Repeat("x", 16385)} {
		if _, err := VerifyGrant(bad, pub, now); err == nil {
			t.Fatal("accepted malformed token")
		}
	}
	if _, err := VerifyGrant(token, other, now); err == nil {
		t.Fatal("accepted wrong signing key")
	}
}

func TestAuditWitness(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	entries := []AuditEntry{}
	previous := strings.Repeat("0", 64)
	for i := int64(1); i <= 3; i++ {
		e := AuditEntry{i, previous, auditHash(i, previous, `{"kind":"ADMITTED"}`), `{"kind":"ADMITTED"}`}
		entries = append(entries, e)
		previous = e.Hash
	}
	cp := SignCheckpoint(3, previous, key)
	if err := VerifyAudit(entries, cp, pub); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAudit(entries[:2], cp, pub); err == nil {
		t.Fatal("truncation accepted")
	}
	altered := append([]AuditEntry(nil), entries...)
	altered[1].Payload = `{"kind":"COMPLETED"}`
	if err := VerifyAudit(altered, cp, pub); err == nil {
		t.Fatal("tamper accepted")
	}
	// Recomputing every hash cannot bypass a retained signed checkpoint.
	previous = strings.Repeat("0", 64)
	for i := range altered {
		altered[i].Previous = previous
		altered[i].Hash = auditHash(int64(i+1), previous, altered[i].Payload)
		previous = altered[i].Hash
	}
	if err := VerifyAudit(altered, cp, pub); err == nil {
		t.Fatal("rewritten chain accepted")
	}
	cp.Sequence = 2
	if err := VerifyAudit(entries[:2], cp, pub); err == nil {
		t.Fatal("forged checkpoint accepted")
	}
}

func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"token":"a","token":"b"}`, `{"token":"a","Token":"b"}`, `{"token":"a","unknown":1}`, `{} {}`, `{"token":`, strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		var v Execute
		if err := StrictJSON([]byte(raw), &v); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var v Execute
	if err := StrictJSON([]byte(`{"token":"valid"}`), &v); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityTrustBoundary(t *testing.T) {
	r := httptest.NewRequest("GET", "https://localhost/", nil)
	r.Header.Set("X-Tenant", "acme")
	r.Header.Set("X-Identity", "alice")
	if _, err := IdentityFrom(r); err == nil {
		t.Fatal("trusted headers")
	}
	for _, uri := range []string{"spiffe://evil.local/tenant/acme/user/alice", "spiffe://leasegate.local/tenant/acme/user/alice?role=admin", "spiffe://leasegate.local/tenant/acme/user/a%2Fb", "spiffe://leasegate.local/tenant/acme/admin/alice"} {
		u, _ := url.Parse(uri)
		cert := &x509.Certificate{URIs: []*url.URL{u}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		if _, err := IdentityFrom(r); err == nil {
			t.Fatalf("accepted %s", uri)
		}
	}
	u, _ := url.Parse("spiffe://leasegate.local/tenant/acme/user/alice")
	cert := &x509.Certificate{URIs: []*url.URL{u}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	if id, err := IdentityFrom(r); err != nil || id.Tenant != "acme" {
		t.Fatal(id, err)
	}
	r.TLS.VerifiedChains = nil
	if _, err := IdentityFrom(r); err == nil {
		t.Fatal("accepted unverified certificate")
	}
}

func TestArtifactSignature(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	a := SignStatement(Statement{"sha256:" + strings.Repeat("a", 64), strings.Repeat("b", 40), "leasegate.reference-builder", now.Unix() + 60}, key)
	if err := a.Verify(pub, now); err != nil {
		t.Fatal(err)
	}
	a.Statement.ImageDigest = "sha256:" + strings.Repeat("c", 64)
	if err := a.Verify(pub, now); err == nil {
		t.Fatal("accepted substituted image")
	}
}

func FuzzGrantParser(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) { _, _ = VerifyGrant(token, pub, time.Unix(2000000000, 0)) })
}
