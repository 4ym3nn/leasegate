# Operations

## Local lifecycle

`make demo` uses only the `leasegate` Compose project. It creates synthetic Acme and Beta documents and fixture identities. The database volume persists between runs. Running the demo renews leaf certificates, recreates service containers, refreshes the admitted build statement and creates new jobs. Source must be committed before a statement is generated.

`make clean-services` stops containers while preserving data. To deliberately discard all LeaseGate fixture state, stop services, remove the `leasegate_data` volume and remove `.local/`. Do not delete keys while retaining a database whose passwords, artifact trust and audit history depend on those keys. A fresh CA is needed after the two-day fixture CA expires.

Services bind only loopback ports on the host. The fixture PostgreSQL administrator is used only by initialization and integration tests. Routine services receive reduced database roles.

## Investigating an uncertain job

1. Read the job as its requester or tenant operator. Retain its job ID, admission ID, image digest and current state.
2. Export audit evidence as the platform auditor and retain a signed checkpoint outside service write access.
3. Have a trusted provider administrator inspect `provider_exports` by exact `job_id`. The row contains the operation hash, receipt, tenant, destination and exported content snapshot.
4. Compare the provider evidence with the immutable job and audit admission. Record the outcome in the incident record. This release intentionally provides no generic replay or force-complete endpoint.

An `admitted` state after a crash does not establish that the provider did nothing. A missing completion event does not prove an absent side effect. Creating another root job is a new authorization decision and may duplicate an existing effect.

## Metrics and audit

```sh
curl --fail --cacert .local/ca.crt \
  --cert .local/auditor.crt --key .local/auditor.key \
  https://localhost:18441/metrics
```

Counters are local to each process and reset on restart. They are operational hints, not authoritative accounting. Admission history comes from the database audit stream. A metrics or audit read requires current auditor authorization; disabling the principal also disables those reads.

Audit verification authenticates a checkpoint with `.local/audit.pub` and checks every sequence number, previous hash and payload hash. Transfer the public key and initial checkpoint through a trusted channel. Do not accept a replacement public key supplied alongside suspicious evidence.

## Deployment review

Before adapting the reference system to real workloads, resolve these application-specific decisions:

- How workload certificates are issued, rotated and bound to independently attested code.
- Whether containers provide sufficient isolation and whether workers require separate networks or microVMs.
- How the real provider enforces exact resource versions, idempotency and receipt reconciliation.
- Where database backups, external audit checkpoints and signing keys are protected.
- How policy updates, artifact withdrawal, key rotation, tenant provisioning and schema migrations are operated.
- What load, storage growth and recovery objectives are required; this version has no scale or availability benchmark claim.

No production-readiness or independent-audit claim is made by this repository.
