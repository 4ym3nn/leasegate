package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 16
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	config.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "4000"
	config.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "8000"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool}, nil
}
func (s *Store) Migrate(ctx context.Context) error { _, err := s.Pool.Exec(ctx, schema); return err }
func (s *Store) Bootstrap(ctx context.Context, identity, tenant, role string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO principals(identity,tenant,role) VALUES($1,$2,$3) ON CONFLICT(identity) DO NOTHING`, identity, tenant, role)
	return err
}

// All policy mutations and admissions take the same transaction-scoped lock.
// This conservative v1 design provides a precise cross-replica ordering point.
func (s *Store) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// A cancelled request still needs rollback, but a broken database
		// connection must not leave cleanup waiting without a deadline.
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(70421001)`); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func role(ctx context.Context, tx pgx.Tx, id Identity, allowed ...string) error {
	if id.Kind != "user" {
		return deny("USER_IDENTITY_REQUIRED")
	}
	var found string
	err := tx.QueryRow(ctx, `SELECT role FROM principals WHERE identity=$1 AND tenant=$2 AND enabled`, id.URI, id.Tenant).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return deny("IDENTITY_DISABLED")
	}
	if err != nil {
		return err
	}
	for _, v := range allowed {
		if v == found {
			return nil
		}
	}
	return deny("ROLE_DENIED")
}
func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func event(ctx context.Context, tx pgx.Tx, actor, kind, job string, detail map[string]string) error {
	var sequence int64
	var previous string
	if err := tx.QueryRow(ctx, `SELECT sequence,hash FROM audit_head WHERE singleton=1 FOR UPDATE`).Scan(&sequence, &previous); err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Actor  string            `json:"actor"`
		Kind   string            `json:"kind"`
		Job    string            `json:"job,omitempty"`
		At     string            `json:"at"`
		Detail map[string]string `json:"detail,omitempty"`
	}{actor, kind, job, time.Now().UTC().Format(time.RFC3339Nano), detail})
	if err != nil {
		return err
	}
	sequence++
	hash := auditHash(sequence, previous, string(payload))
	if _, err = tx.Exec(ctx, `INSERT INTO audit VALUES($1,$2,$3,$4)`, sequence, previous, hash, string(payload)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE audit_head SET sequence=$1,hash=$2 WHERE singleton=1`, sequence, hash)
	return err
}
func getJob(ctx context.Context, tx pgx.Tx, id string) (Job, error) {
	var j Job
	err := tx.QueryRow(ctx, `SELECT id::text,tenant,requester,document,version,destination,image_digest,COALESCE(parent::text,''),state,revoked,expires_at,COALESCE(approved_by,''),COALESCE(receipt,''),COALESCE(admission_id,'') FROM jobs WHERE id=$1`, id).Scan(&j.ID, &j.Tenant, &j.Requester, &j.Document, &j.Version, &j.Destination, &j.ImageDigest, &j.Parent, &j.State, &j.Revoked, &j.ExpiresAt, &j.ApprovedBy, &j.Receipt, &j.AdmissionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, &Failure{404, "JOB_NOT_FOUND"}
	}
	return j, err
}
func checkChain(ctx context.Context, tx pgx.Tx, leaf Job) error {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM principals WHERE identity=$1 AND tenant=$2`, leaf.Requester, leaf.Tenant).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return deny("REQUESTER_REVOKED")
	}
	var artifactValid bool
	if err := tx.QueryRow(ctx, `SELECT expires_at > clock_timestamp() FROM artifacts WHERE digest=$1`, leaf.ImageDigest).Scan(&artifactValid); err != nil {
		return err
	}
	if !artifactValid {
		return deny("ARTIFACT_EXPIRED")
	}
	j := leaf
	for depth := 0; depth < 8; depth++ {
		if j.Revoked {
			return deny("LEASE_REVOKED")
		}
		if !now.Before(j.ExpiresAt) {
			return deny("LEASE_EXPIRED")
		}
		if j.State == "pending" {
			return deny("APPROVAL_REQUIRED")
		}
		if j.Tenant != leaf.Tenant || j.Requester != leaf.Requester || j.Document != leaf.Document || j.Version != leaf.Version || j.Destination != leaf.Destination || j.ImageDigest != leaf.ImageDigest || leaf.ExpiresAt.After(j.ExpiresAt) {
			return deny("DELEGATION_EXPANDED")
		}
		if j.Destination == "external" && (j.ApprovedBy == "" || j.ApprovedBy == j.Requester) {
			return deny("APPROVAL_REQUIRED")
		}
		if j.Parent == "" {
			return nil
		}
		var err error
		j, err = getJob(ctx, tx, j.Parent)
		if err != nil {
			return err
		}
	}
	return deny("DELEGATION_DEPTH_EXCEEDED")
}
func (s *Store) RegisterArtifact(ctx context.Context, id Identity, a Attestation, key ed25519.PublicKey) error {
	if err := a.Verify(key, time.Now()); err != nil {
		return deny("ARTIFACT_REJECTED")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if id.Tenant != "platform" {
			return deny("PLATFORM_OPERATOR_REQUIRED")
		}
		if err := role(ctx, tx, id, "operator"); err != nil {
			return err
		}
		data, _ := json.Marshal(a.Statement)
		if _, err := tx.Exec(ctx, `INSERT INTO artifacts(digest,statement,signature,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(digest) DO UPDATE SET statement=EXCLUDED.statement,signature=EXCLUDED.signature,expires_at=EXCLUDED.expires_at`, a.Statement.ImageDigest, data, a.Signature, time.Unix(a.Statement.ExpiresAt, 0)); err != nil {
			return err
		}
		return event(ctx, tx, id.URI, "ARTIFACT_ADMITTED", "", map[string]string{"digest": a.Statement.ImageDigest})
	})
}
func (s *Store) Create(ctx context.Context, id Identity, n NewJob) (Job, error) {
	var j Job
	if !namePattern.MatchString(n.Document) || !namePattern.MatchString(n.Version) || (n.Destination != "tenant" && n.Destination != "external") || !imagePattern.MatchString(n.ImageDigest) || n.Lifetime < 1 || n.Lifetime > 300 {
		return j, invalid()
	}
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		if err := role(ctx, tx, id, "requester"); err != nil {
			return err
		}
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1 AND expires_at>clock_timestamp())`, n.ImageDigest).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return deny("ARTIFACT_NOT_ADMITTED")
		}
		state := "active"
		if n.Destination == "external" {
			state = "pending"
		}
		jobID := uuid()
		_, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant,requester,document,version,destination,image_digest,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+($9*interval '1 second'))`, jobID, id.Tenant, id.URI, n.Document, n.Version, n.Destination, n.ImageDigest, state, n.Lifetime)
		if err != nil {
			return err
		}
		if err = event(ctx, tx, id.URI, "JOB_CREATED", jobID, map[string]string{"state": state}); err != nil {
			return err
		}
		j, err = getJob(ctx, tx, jobID)
		return err
	})
	return j, err
}
func (s *Store) Read(ctx context.Context, id Identity, jobID string) (Job, error) {
	var j Job
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		var err error
		j, err = getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if j.Tenant != id.Tenant {
			return deny("TENANT_DENIED")
		}
		if err = role(ctx, tx, id, "requester", "approver", "operator"); err != nil {
			return err
		}
		if id.URI != j.Requester {
			if err = role(ctx, tx, id, "approver", "operator"); err != nil {
				return err
			}
		}
		return nil
	})
	return j, err
}
func (s *Store) Approve(ctx context.Context, id Identity, jobID string) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		j, err := getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if j.Tenant != id.Tenant {
			return deny("TENANT_DENIED")
		}
		if j.Requester == id.URI {
			return deny("SELF_APPROVAL_DENIED")
		}
		if err = role(ctx, tx, id, "approver"); err != nil {
			return err
		}
		if j.Revoked || j.State != "pending" || !time.Now().Before(j.ExpiresAt) {
			return deny("JOB_NOT_APPROVABLE")
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET state='active',approved_by=$1 WHERE id=$2`, id.URI, j.ID); err != nil {
			return err
		}
		return event(ctx, tx, id.URI, "APPROVED", j.ID, map[string]string{"imageDigest": j.ImageDigest, "destination": j.Destination, "version": j.Version})
	})
}
func (s *Store) Revoke(ctx context.Context, id Identity, jobID string) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		j, err := getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if j.Tenant != id.Tenant {
			return deny("TENANT_DENIED")
		}
		if err = role(ctx, tx, id, "requester", "operator"); err != nil {
			return err
		}
		if j.Requester != id.URI {
			if err = role(ctx, tx, id, "operator"); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET revoked=TRUE WHERE id=$1`, j.ID); err != nil {
			return err
		}
		return event(ctx, tx, id.URI, "REVOKED", j.ID, nil)
	})
}
func (s *Store) DisablePrincipal(ctx context.Context, id Identity, name string) error {
	if !namePattern.MatchString(name) {
		return invalid()
	}
	uri := "spiffe://leasegate.local/tenant/" + id.Tenant + "/user/" + name
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if err := role(ctx, tx, id, "operator"); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE principals SET enabled=FALSE WHERE identity=$1 AND tenant=$2`, uri, id.Tenant)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return &Failure{404, "PRINCIPAL_NOT_FOUND"}
		}
		return event(ctx, tx, id.URI, "PRINCIPAL_DISABLED", "", map[string]string{"identity": uri})
	})
}
func (s *Store) Delegate(ctx context.Context, id Identity, jobID string, lifetime int) (Job, error) {
	var child Job
	if lifetime < 1 || lifetime > 300 {
		return child, invalid()
	}
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		parent, err := getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if parent.Requester != id.URI || parent.Tenant != id.Tenant {
			return deny("DELEGATION_DENIED")
		}
		if err = role(ctx, tx, id, "requester"); err != nil {
			return err
		}
		if err = checkChain(ctx, tx, parent); err != nil {
			return err
		}
		expires := time.Now().Add(time.Duration(lifetime) * time.Second)
		if expires.After(parent.ExpiresAt) {
			return deny("DELEGATION_EXPANDED")
		}
		childID := uuid()
		_, err = tx.Exec(ctx, `INSERT INTO jobs(id,tenant,requester,document,version,destination,image_digest,parent,state,expires_at,approved_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10)`, childID, parent.Tenant, parent.Requester, parent.Document, parent.Version, parent.Destination, parent.ImageDigest, parent.ID, expires, parent.ApprovedBy)
		if err != nil {
			return err
		}
		child, err = getJob(ctx, tx, childID)
		if err != nil {
			return err
		}
		if err = checkChain(ctx, tx, child); err != nil {
			return err
		}
		return event(ctx, tx, id.URI, "DELEGATED", childID, map[string]string{"parent": parent.ID})
	})
	return child, err
}
func (s *Store) Issue(ctx context.Context, id Identity, jobID string, key ed25519.PrivateKey) (string, error) {
	var token string
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		j, err := getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if j.Tenant != id.Tenant || j.Requester != id.URI {
			return deny("GRANT_DENIED")
		}
		if err = role(ctx, tx, id, "requester"); err != nil {
			return err
		}
		if err = checkChain(ctx, tx, j); err != nil {
			return err
		}
		if j.State != "active" {
			return deny("JOB_ALREADY_ADMITTED")
		}
		now := time.Now().Unix()
		if j.ExpiresAt.Unix() <= now {
			return deny("LEASE_EXPIRED")
		}
		claims := Claims{2, uuid(), "leasegate", "leasegate-gateway", Subject{j.Requester, j.Tenant}, "document.export", Resource{"document", j.Document, j.Tenant}, now, now, j.ExpiresAt.Unix(), "Approved document export", ParameterHash(j.Destination, j.ID, j.Version)}
		token, err = SignGrant(claims, key)
		if err != nil {
			return err
		}
		return event(ctx, tx, id.URI, "GRANT_ISSUED", j.ID, map[string]string{"grantId": claims.GrantID})
	})
	return token, err
}
func (s *Store) Admit(ctx context.Context, id Identity, request Execute, claims Claims) (Job, error) {
	var j Job
	if id.Kind != "job" || id.Name != request.JobID {
		return j, deny("WORKLOAD_BINDING_DENIED")
	}
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		var err error
		j, err = getJob(ctx, tx, request.JobID)
		if err != nil {
			return err
		}
		if j.Tenant != id.Tenant || claims.Subject.Tenant != j.Tenant || claims.Subject.ID != j.Requester || claims.Resource.ID != j.Document || request.Document != j.Document || request.Version != j.Version || request.Destination != j.Destination || claims.ParametersHash != ParameterHash(j.Destination, j.ID, j.Version) {
			return deny("OPERATION_BINDING_DENIED")
		}
		if err = checkChain(ctx, tx, j); err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if now.Unix() < claims.NotBefore || now.Unix() >= claims.ExpiresAt {
			return deny("GRANT_EXPIRED")
		}
		if j.State != "active" {
			return &Failure{409, "JOB_ALREADY_ADMITTED"}
		}
		// A delegation tree shares one execution budget. Creating a child must
		// never multiply the approved side effect.
		root := j
		for root.Parent != "" {
			root, err = getJob(ctx, tx, root.Parent)
			if err != nil {
				return err
			}
		}
		var consumed bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM claims WHERE root_id=$1)`, root.ID).Scan(&consumed); err != nil {
			return err
		}
		if consumed {
			return &Failure{409, "DELEGATION_BUDGET_CONSUMED"}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO claims(grant_id,job_id,root_id) VALUES($1,$2,$3)`, claims.GrantID, j.ID, root.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET state='admitted',admission_id=$1 WHERE id=$2`, claims.GrantID, j.ID); err != nil {
			return err
		}
		j.State = "admitted"
		j.AdmissionID = claims.GrantID
		return event(ctx, tx, id.URI, "ADMITTED", j.ID, map[string]string{"grantId": claims.GrantID})
	})
	return j, err
}
func (s *Store) Finish(ctx context.Context, j Job, receipt string) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		state := "completed"
		kind := "COMPLETED"
		if receipt == "" {
			state = "uncertain"
			kind = "OUTCOME_UNCERTAIN"
		}
		tag, err := tx.Exec(ctx, `UPDATE jobs SET state=$1,receipt=$2 WHERE id=$3 AND state='admitted' AND admission_id=$4`, state, receipt, j.ID, j.AdmissionID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("invalid completion transition")
		}
		return event(ctx, tx, "gateway", kind, j.ID, map[string]string{"receipt": receipt, "grantId": j.AdmissionID})
	})
}
func (s *Store) RecordDenial(ctx context.Context, id Identity, code string) {
	_ = s.transaction(ctx, func(tx pgx.Tx) error { return event(ctx, tx, id.URI, "DENIED", "", map[string]string{"code": code}) })
}
func (s *Store) AuthorizeAuditor(ctx context.Context, id Identity) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if id.Tenant != "platform" {
			return deny("AUDITOR_REQUIRED")
		}
		return role(ctx, tx, id, "auditor")
	})
}
func (s *Store) Audit(ctx context.Context, id Identity, key ed25519.PrivateKey) ([]AuditEntry, Checkpoint, error) {
	entries := []AuditEntry{}
	var checkpoint Checkpoint
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		if id.Tenant != "platform" {
			return deny("AUDITOR_REQUIRED")
		}
		if err := role(ctx, tx, id, "auditor"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT sequence,previous,hash,payload FROM audit ORDER BY sequence`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AuditEntry
			if err = rows.Scan(&e.Sequence, &e.Previous, &e.Hash, &e.Payload); err != nil {
				return err
			}
			entries = append(entries, e)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		var seq int64
		var hash string
		if err = tx.QueryRow(ctx, `SELECT sequence,hash FROM audit_head WHERE singleton=1`).Scan(&seq, &hash); err != nil {
			return err
		}
		checkpoint = SignCheckpoint(seq, hash, key)
		return nil
	})
	return entries, checkpoint, err
}
