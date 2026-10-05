package gate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

type Subject struct {
	ID     string `json:"id"`
	Tenant string `json:"tenantId"`
}
type Resource struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Tenant string `json:"tenantId"`
}

// Claims uses the Authority Boundary v2 wire format.
type Claims struct {
	Version        int      `json:"version"`
	GrantID        string   `json:"grantId"`
	Issuer         string   `json:"issuer"`
	Audience       string   `json:"audience"`
	Subject        Subject  `json:"subject"`
	Action         string   `json:"action"`
	Resource       Resource `json:"resource"`
	IssuedAt       int64    `json:"issuedAt"`
	NotBefore      int64    `json:"notBefore"`
	ExpiresAt      int64    `json:"expiresAt"`
	Purpose        string   `json:"purpose"`
	ParametersHash string   `json:"parametersHash"`
}

func ReadPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	value, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Ed25519 private key required")
	}
	return value, nil
}
func ReadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	value, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Ed25519 public key required")
	}
	return value, nil
}

func SignGrant(claims Claims, key ed25519.PrivateKey) (string, error) {
	header := []byte(`{"alg":"EdDSA","kid":"leasegate-v1","typ":"authority-boundary+jws"}`)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	return signing + "." + b64.EncodeToString(ed25519.Sign(key, []byte(signing))), nil
}
func VerifyGrant(token string, key ed25519.PublicKey, now time.Time) (Claims, error) {
	var claims Claims
	if len(token) > 16384 {
		return claims, errors.New("invalid grant")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("invalid grant")
	}
	decoded := make([][]byte, 3)
	for i, p := range parts {
		value, err := b64.Strict().DecodeString(p)
		if err != nil || b64.EncodeToString(value) != p {
			return claims, errors.New("invalid encoding")
		}
		decoded[i] = value
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := StrictJSON(decoded[0], &header); err != nil || header.Alg != "EdDSA" || header.Kid != "leasegate-v1" || header.Typ != "authority-boundary+jws" {
		return claims, errors.New("invalid header")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), decoded[2]) {
		return claims, errors.New("invalid signature")
	}
	if err := StrictJSON(decoded[1], &claims); err != nil {
		return claims, errors.New("invalid claims")
	}
	if claims.Version != 2 || claims.Issuer != "leasegate" || claims.Audience != "leasegate-gateway" || claims.GrantID == "" || len(claims.GrantID) > 128 || claims.Action != "document.export" || claims.Resource.Type != "document" || claims.Subject.Tenant != claims.Resource.Tenant || claims.Subject.ID == "" || claims.Subject.Tenant == "" || claims.Resource.ID == "" || claims.ExpiresAt <= claims.NotBefore || claims.IssuedAt > claims.NotBefore || claims.ExpiresAt-claims.IssuedAt > 300 || claims.IssuedAt < 0 || now.Unix() < claims.NotBefore || now.Unix() >= claims.ExpiresAt {
		return claims, errors.New("invalid grant binding or lifetime")
	}
	return claims, nil
}

// Parameters are intentionally limited to validated ASCII strings. This is the
// interoperable subset of Authority Boundary's canonical JSON parameter format.
func ParameterHash(destination, jobID, version string) string {
	data, _ := json.Marshal(map[string]string{"destination": destination, "jobId": jobID, "version": version})
	sum := sha256.Sum256(data)
	return b64.EncodeToString(sum[:])
}
func Digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

type Statement struct {
	ImageDigest    string `json:"imageDigest"`
	SourceRevision string `json:"sourceRevision"`
	Builder        string `json:"builder"`
	ExpiresAt      int64  `json:"expiresAt"`
}
type Attestation struct {
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"`
}

func SignStatement(statement Statement, key ed25519.PrivateKey) Attestation {
	data, _ := json.Marshal(statement)
	return Attestation{statement, b64.EncodeToString(ed25519.Sign(key, append([]byte("leasegate-build-v1\n"), data...)))}
}
func (a Attestation) Verify(key ed25519.PublicKey, now time.Time) error {
	data, _ := json.Marshal(a.Statement)
	sig, err := b64.Strict().DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte("leasegate-build-v1\n"), data...), sig) {
		return errors.New("invalid artifact signature")
	}
	if !imagePattern.MatchString(a.Statement.ImageDigest) || !revisionPattern.MatchString(a.Statement.SourceRevision) || a.Statement.Builder != "leasegate.reference-builder" || a.Statement.ExpiresAt <= now.Unix() {
		return errors.New("artifact policy rejected")
	}
	return nil
}

type AuditEntry struct {
	Sequence int64  `json:"sequence"`
	Previous string `json:"previous"`
	Hash     string `json:"hash"`
	Payload  string `json:"payload"`
}
type Checkpoint struct {
	Sequence  int64  `json:"sequence"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

func auditHash(sequence int64, previous, payload string) string {
	return Digest([]byte(fmt.Sprintf("leasegate-audit-v1\n%d\n%s\n%s", sequence, previous, payload)))
}
func checkpointBytes(sequence int64, hash string) []byte {
	return []byte(fmt.Sprintf("leasegate-checkpoint-v1\n%d\n%s", sequence, hash))
}
func SignCheckpoint(sequence int64, hash string, key ed25519.PrivateKey) Checkpoint {
	return Checkpoint{sequence, hash, b64.EncodeToString(ed25519.Sign(key, checkpointBytes(sequence, hash)))}
}
func VerifyAudit(entries []AuditEntry, checkpoint Checkpoint, key ed25519.PublicKey) error {
	sig, err := b64.Strict().DecodeString(checkpoint.Signature)
	if err != nil || !ed25519.Verify(key, checkpointBytes(checkpoint.Sequence, checkpoint.Hash), sig) {
		return errors.New("checkpoint signature invalid")
	}
	previous := strings.Repeat("0", 64)
	for i, entry := range entries {
		if entry.Sequence != int64(i+1) || entry.Previous != previous || entry.Hash != auditHash(entry.Sequence, entry.Previous, entry.Payload) {
			return fmt.Errorf("audit chain invalid at entry %d", i+1)
		}
		previous = entry.Hash
	}
	if int64(len(entries)) != checkpoint.Sequence || previous != checkpoint.Hash {
		return errors.New("audit does not match independently retained checkpoint")
	}
	return nil
}
