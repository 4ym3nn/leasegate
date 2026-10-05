CREATE TABLE IF NOT EXISTS principals (
  identity TEXT PRIMARY KEY, tenant TEXT NOT NULL, role TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS artifacts (
  digest TEXT PRIMARY KEY, statement JSONB NOT NULL, signature TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY, tenant TEXT NOT NULL, requester TEXT NOT NULL REFERENCES principals(identity),
  document TEXT NOT NULL, version TEXT NOT NULL, destination TEXT NOT NULL,
  image_digest TEXT NOT NULL REFERENCES artifacts(digest), parent UUID REFERENCES jobs(id),
  state TEXT NOT NULL CHECK (state IN ('pending','active','admitted','completed','uncertain')),
  revoked BOOLEAN NOT NULL DEFAULT FALSE, expires_at TIMESTAMPTZ NOT NULL,
  approved_by TEXT, receipt TEXT, admission_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS claims (
  grant_id TEXT PRIMARY KEY, job_id UUID NOT NULL UNIQUE REFERENCES jobs(id),
  root_id UUID NOT NULL UNIQUE REFERENCES jobs(id),
  admitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS audit_head (singleton INT PRIMARY KEY CHECK(singleton=1), sequence BIGINT NOT NULL, hash TEXT NOT NULL);
INSERT INTO audit_head VALUES (1,0,repeat('0',64)) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS audit (
  sequence BIGINT PRIMARY KEY, previous TEXT NOT NULL, hash TEXT NOT NULL, payload TEXT NOT NULL
);
