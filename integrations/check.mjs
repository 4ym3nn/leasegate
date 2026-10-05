import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { verifyDelegation, signDelegation } from 'authority-boundary';
import { parseScenario, runScenario, toJUnit, toSarif } from 'authztrace';

export async function interoperability({ check, create, grant, cert, execute, expect, request, payload }) {
  await check('Authority Boundary verifies Go grants and Go admits SDK grants', async () => {
    const job = await create(); const token = await grant(job); cert(job);
    const claims = await verifyDelegation(token, { resolve: async kid => kid === 'leasegate-v1' ? readFileSync('.local/grant.pub', 'utf8') : undefined });
    const parameters = { destination: job.destination, jobId: job.id, version: job.version };
    assert.equal(claims.parametersHash, createHash('sha256').update(JSON.stringify(parameters)).digest('base64url'));
    assert.equal(claims.resource.tenantId, 'acme');
    const signed = await signDelegation({ ...claims, grantId: randomUUID() }, { keyId: 'leasegate-v1', privateKey: readFileSync('.local/grant.key', 'utf8') });
    await expect(execute(job, signed), 201);
  });
  await check('AuthzTrace exercises revoke then execute against the real mTLS gateway', async () => {
    const job = await create(); const token = await grant(job); const worker = cert(job);
    const scenario = parseScenario(JSON.stringify({ version: 1, name: 'LeaseGate revocation at execution time', variables: {},
      actors: { requester: { headers: { 'x-fixture-actor': 'alice' } }, worker: { headers: { 'x-fixture-actor': worker } } },
      targets: { control: { type: 'http', baseUrl: 'https://localhost:18440', headers: {} }, gateway: { type: 'http', baseUrl: 'https://localhost:18442', headers: {} } },
      steps: [
        { kind: 'http', id: 'revoke', actor: 'requester', target: 'control', method: 'POST', path: `/jobs/${job.id}/revoke`, headers: {}, expect: { status: 200 } },
        { kind: 'http', id: 'execute', actor: 'worker', target: 'gateway', method: 'POST', path: '/execute', headers: {}, body: payload(job, token), expect: { status: 403, path: 'body.error', equals: 'LEASE_REVOKED' } },
        { kind: 'http', id: 'no-completion', actor: 'requester', target: 'control', method: 'GET', path: `/jobs/${job.id}`, headers: {}, expect: { status: 200, path: 'body.receipt', absent: true } },
      ],
    }));
    // This adapter selects local test certificates. The selector is never sent
    // to LeaseGate and is not a production identity mechanism.
    const fixtureFetch = async (input, init = {}) => {
      const url = new URL(String(input));
      assert(['https://localhost:18440', 'https://localhost:18442'].includes(url.origin));
      const headers = new Headers(init.headers);
      const actor = headers.get('x-fixture-actor');
      assert(['alice', worker].includes(actor));
      headers.delete('x-fixture-actor');
      const result = await request(actor, Number(url.port), init.method ?? 'GET', url.pathname, init.body, Object.fromEntries(headers));
      return new Response(JSON.stringify(result.body), { status: result.status, headers: { 'content-type': 'application/json' } });
    };
    const result = await runScenario(scenario, { fetch: fixtureFetch });
    writeFileSync('reports/authztrace.json', JSON.stringify(result, null, 2));
    writeFileSync('reports/authztrace.xml', toJUnit(result));
    writeFileSync('reports/authztrace.sarif', toSarif(result));
    assert.equal(result.passed, true, JSON.stringify(result.findings));
  });
}
