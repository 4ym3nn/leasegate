# Threat model

## Protected assets and adversary

Assets are tenant document content, provider credentials, approval integrity, execution budgets, current revocation state and verifiable admission history.

Assume an authenticated tenant user may submit arbitrary API bodies, race and replay requests, retain a stale grant or attempt to substitute job parameters. Assume job code may misuse its own valid certificate and token, inspect its own container filesystem or contact network destinations available to it. Tests exercise the reference environment only.

The policy service, gateways, provider, PostgreSQL administration, Docker daemon, host launcher, CA, release signer and audit signer are trusted. A grant's image digest is an admission policy binding; the certificate alone does not cryptographically attest the currently executing binary. The fixture host issues a certificate and launches the selected image. A malicious launcher or copied certificate defeats that provenance assumption.

## Invariants and evidence

| Invariant | Evidence |
| --- | --- |
| Identity headers cannot change tenant or caller | Certificate parser tests and cross-tenant HTTP checks. |
| An operation cannot change its approved scope | Version/destination substitution tests and tenant-filtered provider export inspection. |
| Revoked authority cannot obtain a later admission | Ancestor and principal revocation checks, both gateway replicas and database restart. |
| Delegation cannot increase use count or expiry | Root-budget constraint and sibling/parent execution checks. |
| No effect precedes durable admission evidence | Forced audit permission failure rolls back claims and leaves the provider untouched. |
| Concurrent retries cannot duplicate admission | 32 requests across two processes, one success and one provider record. |
| Provider access does not expose its secret to a worker | Narrow container mounts and a direct network connection check from the worker. |
| Rewritten or truncated audit exports fail verification | Offline tests against a retained signed checkpoint, including a fully recomputed hash chain. |

These are implementation tests, not a formal proof or an independent security audit. Passing tests establishes behavior in the tested environment, not absence of all vulnerabilities.

## Boundaries that matter

**Revocation ordering:** a request already admitted can finish after revocation. There is no distributed transaction spanning the policy database and an arbitrary external provider.

**Uncertain completion:** an unanswered provider request may already have performed its effect. The gateway consumes the budget and never retries automatically. Provider idempotency supports investigation but this version has no automatic recovery controller.

**Audit witness:** the signer can issue new checkpoints. Hash chains do not establish completeness without a separately retained checkpoint. Trusted administrative deletion, full backup rollback or signing-key compromise requires external evidence to detect.

**Container isolation:** containers share the host kernel. This design does not defend against kernel exploits, a malicious Docker administrator or hostile tenants requiring VM-strength isolation. Shared worker networking and host-issued certificates are explicit limitations.

**Availability:** the global lock, full audit export, 64-request service limit and 16-connection pool favor a bounded reference deployment. Denial traffic can consume audit storage; no distributed rate limiter, retention service or automatic failover is implemented.

**Privacy:** audit records contain identity URIs, job IDs, timestamps, reasons and receipts. They omit tokens, private keys, provider credentials and document bodies. Access is restricted to an enabled platform auditor, but operators still need a retention policy before a real deployment.

**Supply chain:** statements use a project-specific Ed25519 format and a local trusted signer. They are not SLSA provenance or Sigstore verification. The trusted builder must protect its key and produce the stated image from the stated source. Tests check signature and digest substitution, not builder compromise.

**Database transport:** the Compose fixture uses isolated Docker networks with PostgreSQL TLS disabled. Remote databases require verified TLS and a revised network deployment. Never reuse fixture configuration for a remote production database.
