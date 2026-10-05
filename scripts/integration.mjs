import assert from 'node:assert/strict';
import https from 'node:https';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

const local = resolve('.local');
const ca = readFileSync(`${local}/ca.crt`);
const imageDigest = readFileSync(`${local}/image-id`, 'utf8').trim();
const composeArgs = ['compose', '--env-file', '.local/demo.env'];
const compose = (...args) => execFileSync('docker', [...composeArgs, ...args], { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
const sql = query => compose('exec', '-T', 'postgres', 'psql', '-U', 'fixture_admin', '-d', 'leasegate', '-v', 'ON_ERROR_STOP=1', '-At', '-c', query).trim();
let passed = 0;
const checks = [];
async function check(name, fn) {
  const start = performance.now();
  await fn();
  checks.push({ name, passed: true, durationMs: Math.round(performance.now() - start) });
  passed++;
  console.log(`PASS ${name}`);
}
export function request(actor, port, method, path, body, headers = {}) {
  const data = typeof body === 'string' ? body : body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: 'localhost', port, method, path, ca, minVersion: 'TLSv1.3', cert: readFileSync(`${local}/${actor}.crt`), key: readFileSync(`${local}/${actor}.key`), agent: false, headers: { 'content-type': 'application/json', ...headers }, timeout: 12000 }, res => {
      let text = '';
      res.setEncoding('utf8');res.on('data', x => text += x);
      res.on('end', () => { let body; try { body = JSON.parse(text); } catch { body = text; } resolve({ status: res.statusCode, body }); });
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.end(data);
  });
}
const control = (actor, method, path, body, headers) => request(actor, 18440, method, path, body, headers);
async function expect(promise, status, error) {
  const r = await promise;
  // Do not print response bodies: successful grant responses contain secrets.
  assert.equal(r.status, status, `expected HTTP ${status}, received ${r.status} (${r.body?.error ?? r.body?.status ?? 'response'})`);
  if (error) assert.equal(r.body.error, error);
  return r.body;
}
const create = (overrides = {}, actor = 'alice') => expect(control(actor, 'POST', '/jobs', { document: 'quarterly-report', version: '1', destination: 'tenant', imageDigest, lifetimeSeconds: 240, ...overrides }), 201);
const grant = async (job, actor = 'alice') => (await expect(control(actor, 'POST', `/jobs/${job.id}/grant`), 200)).token;
const cert = (job, tenant = 'acme', name = `job-${job.id}`) => { execFileSync('node', ['scripts/fixtures.mjs', 'job', job.id, tenant, name], { stdio: 'pipe' }); return name; };
const payload = (job, token) => ({ token, jobId: job.id, document: job.document, version: job.version, destination: job.destination });
const execute = (job, token, port = 18441, changes = {}, actor = `job-${job.id}`) => request(actor, port, 'POST', '/execute', { ...payload(job, token), ...changes });
const revoke = job => expect(control('alice', 'POST', `/jobs/${job.id}/revoke`), 200);

await check('signed artifact admission and image substitution rejection', async () => {
  const a = JSON.parse(readFileSync(`${local}/attestation.json`));
  await expect(control('platform-operator', 'POST', '/artifacts', { ...a, statement: { ...a.statement, imageDigest: `sha256:${'0'.repeat(64)}` } }), 403, 'ARTIFACT_REJECTED');
  await expect(control('alice', 'POST', '/artifacts', a), 403);
  await expect(control('platform-operator', 'POST', '/artifacts', a), 201);
  await expect(control('alice', 'POST', '/jobs', { document: 'quarterly-report', version: '1', destination: 'tenant', imageDigest: `sha256:${'0'.repeat(64)}`, lifetimeSeconds: 60 }), 403, 'ARTIFACT_NOT_ADMITTED');
});

await check('independent approval, tenant isolation and immutable inputs', async () => {
  const j = await create({ destination: 'external' });
  await expect(control('alice', 'POST', `/jobs/${j.id}/grant`), 403, 'APPROVAL_REQUIRED');
  await expect(control('alice', 'POST', `/jobs/${j.id}/approve`), 403, 'SELF_APPROVAL_DENIED');
  await expect(control('bob', 'GET', `/jobs/${j.id}`, undefined, { 'x-tenant': 'acme', 'x-role': 'operator' }), 403, 'TENANT_DENIED');
  await expect(control('approver', 'POST', `/jobs/${j.id}/approve`), 200);
  const token = await grant(j); cert(j);
  await expect(execute(j, token, 18441, { destination: 'tenant' }), 403, 'OPERATION_BINDING_DENIED');
  await expect(execute(j, token, 18441, { version: '2' }), 403, 'OPERATION_BINDING_DENIED');
  await expect(execute(j, token), 201);
  assert.equal(sql(`SELECT tenant || ':' || destination || ':' || (content->>'owner') FROM provider_exports WHERE job_id='${j.id}'`), 'acme:external:acme');
});

await check('job certificate binding and cross-tenant workload rejection', async () => {
  const j = await create();const token = await grant(j);cert(j);
  await expect(execute(j, token, 18441, {}, 'alice'), 403, 'WORKLOAD_BINDING_DENIED');
  cert(j, 'beta', `wrong-${j.id}`);
  await expect(execute(j, token, 18441, {}, `wrong-${j.id}`), 403, 'OPERATION_BINDING_DENIED');
  await expect(execute(j, token), 201);
});

await check('32 concurrent submissions to two gateways admit one effect', async () => {
  const j = await create();const token = await grant(j);cert(j);
  const results = await Promise.all(Array.from({ length: 32 }, (_, i) => execute(j, token, i % 2 ? 18441 : 18442)));
  assert.equal(results.filter(r => r.status === 201).length, 1);
  assert.equal(results.filter(r => r.status === 409).length, 31);
  assert.equal(sql(`SELECT count(*) FROM provider_exports WHERE job_id='${j.id}'`), '1');
});

await check('delegation cannot expand expiry or multiply execution budget', async () => {
  const root = await create();
  await expect(control('alice', 'POST', `/jobs/${root.id}/delegate`, { lifetimeSeconds: 300 }), 403, 'DELEGATION_EXPANDED');
  const children = [];
  for (let i = 0; i < 2; i++) children.push(await expect(control('alice', 'POST', `/jobs/${root.id}/delegate`, { lifetimeSeconds: 120 }), 201));
  const rootToken = await grant(root); cert(root);
  for (const j of children) cert(j);
  const tokens = await Promise.all(children.map(j => grant(j)));
  await expect(execute(children[0], tokens[0]), 201);
  await expect(execute(children[1], tokens[1], 18442), 409, 'DELEGATION_BUDGET_CONSUMED');
  await expect(execute(root, rootToken), 409, 'DELEGATION_BUDGET_CONSUMED');
});

let revoked, revokedToken;
await check('concurrent revocation and execution obey the committed audit order', async () => {
  const jobs = [];
  for (let i = 0; i < 8; i++) { const j = await create(); const token = await grant(j); cert(j); jobs.push({ j, token }); }
  await Promise.all(jobs.map(async ({ j, token }, i) => {
    const actions = [() => execute(j, token, i % 2 ? 18441 : 18442), () => revoke(j)];
    if (i % 2) actions.reverse();
    await Promise.all(actions.map(action => action()));
    await expect(execute(j, token), 403, 'LEASE_REVOKED');
  }));
  const audit = await expect(control('auditor', 'GET', '/audit'), 200);
  const events = audit.entries.map(e => ({ sequence: e.sequence, ...JSON.parse(e.payload) }));
  for (const { j } of jobs) {
    const admission = events.find(e => e.job === j.id && e.kind === 'ADMITTED');
    const revocation = events.find(e => e.job === j.id && e.kind === 'REVOKED');
    assert(revocation);
    if (admission) assert(admission.sequence < revocation.sequence, 'admission ordered after committed revocation');
  }
});

await check('ancestor revocation denies already issued child grants on both replicas', async () => {
  const root = await create();
  revoked = await expect(control('alice', 'POST', `/jobs/${root.id}/delegate`, { lifetimeSeconds: 120 }), 201);
  revokedToken = await grant(revoked);cert(revoked);
  await revoke(root);
  for (const port of [18441, 18442]) await expect(execute(revoked, revokedToken, port), 403, 'LEASE_REVOKED');
});

await check('isolated worker runs the approved image and cannot reach provider directly', async () => {
  const j = await create();const token = await grant(j);cert(j);
  const providerID = compose('ps', '-q', 'provider').trim();
  const info = JSON.parse(execFileSync('docker', ['inspect', providerID], { encoding: 'utf8' }))[0];
  const ip = info.NetworkSettings.Networks.leasegate_backend.IPAddress;
  const config = { gateway: 'https://gateway-a:8443', cert: '/run/job.crt', key: '/run/job.key', ca: '/run/ca.crt', request: payload(j, token), probeAddress: `${ip}:8443` };
  writeFileSync(`${local}/worker.json`, JSON.stringify(config), { mode: 0o644 });
  const mounts = [['worker.json', 'config.json'], [`job-${j.id}.crt`, 'job.crt'], [`job-${j.id}.key`, 'job.key'], ['ca.crt', 'ca.crt']].flatMap(([host, container]) => ['--mount', `type=bind,src=${local}/${host},dst=/run/${container},readonly`]);
  const output = execFileSync('docker', ['run', '--rm', '--network', 'leasegate_workers', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '32', '--memory', '64m', '--user', '65532:65532', ...mounts, j.imageDigest, 'worker', '--config', '/run/config.json'], { encoding: 'utf8', timeout: 20000 });
  assert.match(output, /PASS: direct provider connection blocked/);
  assert.match(output, /PASS: no capabilities/);
  assert.match(output, /HTTP 201/);
  console.log(output.trim());
});

await check('resource version change fails without exporting content', async () => {
  const j = await create({ version: 'nonexistent' });const token = await grant(j);cert(j);
  const r = await expect(execute(j, token), 503);
  assert.equal(r.status, 'uncertain');assert.equal(r.retry, false);
  assert.equal(sql(`SELECT count(*) FROM provider_exports WHERE job_id='${j.id}'`), '0');
  await expect(execute(j, token), 409);
});

await check('provider outage records uncertainty and prohibits blind retries', async () => {
  const j = await create();const token = await grant(j);cert(j);
  compose('stop', 'provider');
  try { const r = await expect(execute(j, token), 503);assert.equal(r.status, 'uncertain');assert.equal(r.retry, false); }
  finally { compose('start', 'provider'); }
  await expect(execute(j, token, 18442), 409);
  assert.equal((await expect(control('alice', 'GET', `/jobs/${j.id}`), 200)).state, 'uncertain');
});

await check('database outage fails closed and revocation survives restart', async () => {
  const j = await create();const token = await grant(j);cert(j);
  compose('stop', 'postgres');
  try { await expect(execute(j, token), 503, 'DEPENDENCY_UNAVAILABLE'); }
  finally { compose('up', '-d', '--wait', 'postgres'); }
  compose('restart', 'gateway-a', 'gateway-b');
  for (const port of [18441, 18442]) {
    for (let i=0;i<30;i++) { try { if ((await request('auditor', port, 'GET', '/health')).status===200) break; } catch {} await new Promise(r=>setTimeout(r,250)); }
    await expect(execute(revoked, revokedToken, port), 403, 'LEASE_REVOKED');
  }
  await expect(execute(j, token), 201);
});

await check('grant expiry and ambiguous JSON fail closed', async () => {
  const j = await create({ lifetimeSeconds: 2 });const token = await grant(j);cert(j);
  await new Promise(r=>setTimeout(r,2100));
  await expect(execute(j, token), 403, 'INVALID_GRANT');
  await expect(control('alice', 'POST', '/jobs', '{"document":"a","Document":"b"}'), 400, 'INVALID_REQUEST');
});

await check('disabling the requester invalidates outstanding job grants', async () => {
  const name = `revocation-${randomUUID()}`;
  const identity = `spiffe://leasegate.local/tenant/acme/user/${name}`;
  sql(`INSERT INTO principals(identity,tenant,role) VALUES('${identity}','acme','requester')`);
  execFileSync('node', ['scripts/fixtures.mjs', 'user', name, 'acme', name], { stdio: 'pipe' });
  const j = await create({}, name); const token = await grant(j, name); cert(j);
  await expect(control('operator', 'POST', `/principals/${name}/disable`), 200);
  await expect(execute(j, token), 403, 'REQUESTER_REVOKED');
  await expect(control(name, 'POST', '/jobs', { document: 'quarterly-report', version: '1', destination: 'tenant', imageDigest, lifetimeSeconds: 60 }), 403, 'IDENTITY_DISABLED');
});

await check('audit persistence failure rolls back admission before any effect', async () => {
  const j = await create(); const token = await grant(j); cert(j);
  sql('REVOKE INSERT ON audit FROM leasegate_runtime');
  try { await expect(execute(j, token), 503, 'DEPENDENCY_UNAVAILABLE'); }
  finally { sql('GRANT INSERT ON audit TO leasegate_runtime'); }
  assert.equal(sql(`SELECT count(*) FROM provider_exports WHERE job_id='${j.id}'`), '0');
  assert.equal(sql(`SELECT count(*) FROM claims WHERE job_id='${j.id}'`), '0');
  await expect(execute(j, token), 201);
});

await check('database roles isolate provider data and prohibit audit rewriting', async () => {
  for (const query of ['SET ROLE leasegate_runtime; UPDATE audit SET payload=payload WHERE false', 'SET ROLE leasegate_runtime; SELECT * FROM provider_documents', 'SET ROLE leasegate_provider; SELECT * FROM jobs']) {
    assert.throws(() => sql(query), /permission denied/);
  }
});

mkdirSync('reports', { recursive: true });
const { interoperability } = await import('../integrations/check.mjs');
await interoperability({ check, create, grant, cert, execute, expect, request, payload });

await check('audit export verifies offline and detects edits and truncation', async () => {
  await expect(control('alice', 'GET', '/audit'), 403);
  const audit = await expect(control('auditor', 'GET', '/audit'), 200);
  mkdirSync('reports', { recursive: true });
  writeFileSync('reports/audit.json', JSON.stringify(audit, null, 2));
  writeFileSync('reports/checkpoint.json', JSON.stringify(audit.checkpoint));
  writeFileSync('reports/audit.pub', readFileSync('.local/audit.pub'));
  const args = ['verify-audit', '--events', 'reports/audit.json', '--checkpoint', 'reports/checkpoint.json', '--key', '.local/audit.pub'];
  console.log(execFileSync('bin/leasegate', args, { encoding: 'utf8' }).trim());
  const truncated = { ...audit, entries: audit.entries.slice(0, -1) };
  writeFileSync('reports/altered.json', JSON.stringify(truncated));
  assert.throws(() => execFileSync('bin/leasegate', args.map(x => x === 'reports/audit.json' ? 'reports/altered.json' : x), { stdio: 'pipe' }));
  truncated.entries[0].payload += ' ';
  writeFileSync('reports/altered.json', JSON.stringify(truncated));
  assert.throws(() => execFileSync('bin/leasegate', args.map(x => x === 'reports/audit.json' ? 'reports/altered.json' : x), { stdio: 'pipe' }));
  assert(!JSON.stringify(audit).includes('eyJhbGci'), 'audit leaked a token');
});

writeFileSync('reports/integration.json', JSON.stringify({ passed, checks }, null, 2));
console.log(`\n${passed} integration checks passed. Reports saved in reports/.`);
