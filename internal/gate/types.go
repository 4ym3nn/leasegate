package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$`)
var imagePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Identity struct {
	URI    string
	Tenant string
	Kind   string
	Name   string
}

func IdentityFrom(r *http.Request) (Identity, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, errors.New("mTLS required")
	}
	cert := r.TLS.PeerCertificates[0]
	if len(cert.URIs) != 1 {
		return Identity{}, errors.New("exactly one workload identity required")
	}
	u := cert.URIs[0]
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "spiffe" || u.Host != "leasegate.local" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || len(parts) != 4 || parts[0] != "tenant" || !namePattern.MatchString(parts[1]) || (parts[2] != "user" && parts[2] != "job") || !namePattern.MatchString(parts[3]) {
		return Identity{}, errors.New("invalid workload identity")
	}
	return Identity{u.String(), parts[1], parts[2], parts[3]}, nil
}

type Job struct {
	ID          string    `json:"id"`
	Tenant      string    `json:"tenant"`
	Requester   string    `json:"requester"`
	Document    string    `json:"document"`
	Version     string    `json:"version"`
	Destination string    `json:"destination"`
	ImageDigest string    `json:"imageDigest"`
	Parent      string    `json:"parent,omitempty"`
	State       string    `json:"state"`
	Revoked     bool      `json:"revoked"`
	ExpiresAt   time.Time `json:"expiresAt"`
	ApprovedBy  string    `json:"approvedBy,omitempty"`
	Receipt     string    `json:"receipt,omitempty"`
	AdmissionID string    `json:"admissionId,omitempty"`
}
type NewJob struct {
	Document    string `json:"document"`
	Version     string `json:"version"`
	Destination string `json:"destination"`
	ImageDigest string `json:"imageDigest"`
	Lifetime    int    `json:"lifetimeSeconds"`
}
type Execute struct {
	Token       string `json:"token"`
	JobID       string `json:"jobId"`
	Document    string `json:"document"`
	Version     string `json:"version"`
	Destination string `json:"destination"`
}
type Failure struct {
	Status int
	Code   string
}

func (f *Failure) Error() string { return f.Code }
func deny(code string) error     { return &Failure{403, code} }
func invalid() error             { return &Failure{400, "INVALID_REQUEST"} }

func StrictJSON(data []byte, value any) error {
	// Duplicate object keys are rejected to keep signed inputs unambiguous.
	var visit func(*json.Decoder, int) error
	visit = func(d *json.Decoder, depth int) error {
		if depth > 32 {
			return errors.New("JSON too deep")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				// encoding/json matches struct fields without regard to case.
				// Reject aliases as duplicates as well as identical spellings.
				key = strings.ToLower(key)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[key] = true
				if err := visit(d, depth+1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := visit(d, depth+1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	first := json.NewDecoder(bytes.NewReader(data))
	if err := visit(first, 0); err != nil {
		return err
	}
	if _, err := first.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}
