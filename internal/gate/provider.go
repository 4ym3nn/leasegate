package gate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type ProviderOperation struct {
	JobID       string `json:"jobId"`
	Tenant      string `json:"tenant"`
	Document    string `json:"document"`
	Version     string `json:"version"`
	Destination string `json:"destination"`
}
type Provider struct {
	Store      *Store
	Credential string
}

func (p *Provider) Migrate(ctx context.Context) error {
	_, err := p.Store.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS provider_documents(tenant TEXT NOT NULL,id TEXT NOT NULL,version TEXT NOT NULL,content JSONB NOT NULL,PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS provider_exports(job_id UUID PRIMARY KEY,receipt UUID UNIQUE NOT NULL,operation_hash TEXT NOT NULL,tenant TEXT NOT NULL,destination TEXT NOT NULL,content JSONB NOT NULL,created_at TIMESTAMPTZ DEFAULT clock_timestamp());
INSERT INTO provider_documents VALUES ('acme','quarterly-report','1','{"total":4200,"owner":"acme"}'),('beta','quarterly-report','1','{"total":900,"owner":"beta"}') ON CONFLICT DO NOTHING;`)
	return err
}
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := IdentityFrom(r)
	if err != nil || id.URI != "spiffe://leasegate.local/tenant/platform/user/gateway" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+p.Credential)) != 1 {
		writeJSON(w, 403, map[string]string{"error": "PROVIDER_AUTH_REQUIRED"})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/export" || r.URL.RawQuery != "" {
		writeJSON(w, 404, map[string]string{"error": "NOT_FOUND"})
		return
	}
	var op ProviderOperation
	if err = body(r, &op); err != nil || !uuidPattern.MatchString(op.JobID) || !namePattern.MatchString(op.Tenant) || !namePattern.MatchString(op.Document) || !namePattern.MatchString(op.Version) || (op.Destination != "tenant" && op.Destination != "external") {
		writeJSON(w, 400, map[string]string{"error": "INVALID_REQUEST"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	data, _ := json.Marshal(op)
	hash := Digest(data)
	receipt := uuid()
	tag, err := p.Store.Pool.Exec(ctx, `INSERT INTO provider_exports(job_id,receipt,operation_hash,tenant,destination,content) SELECT $1,$2,$3,tenant,$4,content FROM provider_documents WHERE tenant=$5 AND id=$6 AND version=$7 ON CONFLICT(job_id) DO NOTHING`, op.JobID, receipt, hash, op.Destination, op.Tenant, op.Document, op.Version)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "PROVIDER_UNAVAILABLE"})
		return
	}
	status := 201
	if tag.RowsAffected() == 0 {
		status = 200
		var savedHash string
		err = p.Store.Pool.QueryRow(ctx, `SELECT receipt::text,operation_hash FROM provider_exports WHERE job_id=$1`, op.JobID).Scan(&receipt, &savedHash)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && savedHash != hash) {
			writeJSON(w, 409, map[string]string{"error": "RESOURCE_VERSION_OR_OPERATION_CHANGED"})
			return
		}
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "PROVIDER_UNAVAILABLE"})
			return
		}
	}
	writeJSON(w, status, map[string]string{"receipt": receipt})
}
