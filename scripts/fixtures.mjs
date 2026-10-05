import { mkdirSync, existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

const local = resolve('.local');
mkdirSync(local, { recursive: true, mode: 0o700 });
chmodSync(local, 0o700);
const save = (name, data, mode = 0o444) => writeFileSync(`${local}/${name}`, data, { mode });
const json = (name, value) => save(name, JSON.stringify(value, null, 2) + '\n');
const openssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
if (!existsSync(`${local}/ca.key`)) {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=LeaseGate local fixture CA', '-keyout', `${local}/ca.key`, '-out', `${local}/ca.crt`, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  chmodSync(`${local}/ca.key`, 0o600);
}
function certificate(name, tenant, kind, identity, server = false) {
  if (!/^[a-zA-Z0-9_-]+$/.test(name + tenant + identity)) throw new Error('invalid fixture identity');
  const base = `${local}/${name}`;
  const uri = `spiffe://leasegate.local/tenant/${tenant}/${kind}/${identity}`;
  const dns = server ? `,DNS:localhost,IP:127.0.0.1,DNS:${name}${name === 'gateway' ? ',DNS:gateway-a,DNS:gateway-b' : ''}` : '';
  save(`${name}.ext`, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth${server ? ',serverAuth' : ''}\nsubjectAltName=URI:${uri}${dns}\n`);
  openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', `/CN=${name}`, '-keyout', `${base}.key`, '-out', `${base}.csr`);
  openssl('x509', '-req', '-in', `${base}.csr`, '-CA', `${local}/ca.crt`, '-CAkey', `${local}/ca.key`, '-set_serial', `0x${randomBytes(16).toString('hex')}`, '-days', '1', '-extfile', `${base}.ext`, '-out', `${base}.crt`);
  chmodSync(`${base}.key`, 0o444);
}

if (process.argv[2] === 'job') {
  const [id, tenant = 'acme', name = `job-${id}`] = process.argv.slice(3);
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('job UUID required');
  certificate(name, tenant, 'job', id);
  process.exit(0);
}
for (const name of ['control', 'gateway', 'provider']) certificate(name, 'platform', 'user', name, true);
for (const [name, tenant, identity] of [['alice', 'acme', 'alice'], ['approver', 'acme', 'approver'], ['operator', 'acme', 'operator'], ['bob', 'beta', 'bob'], ['platform-operator', 'platform', 'operator'], ['auditor', 'platform', 'auditor']]) certificate(name, tenant, 'user', identity);
for (const name of ['grant', 'audit', 'release']) {
  if (!existsSync(`${local}/${name}.key`)) {
    openssl('genpkey', '-algorithm', 'ED25519', '-out', `${local}/${name}.key`);
    openssl('pkey', '-in', `${local}/${name}.key`, '-pubout', '-out', `${local}/${name}.pub`);
    chmodSync(`${local}/${name}.key`, name === 'release' ? 0o600 : 0o444);
  }
}
if (!existsSync(`${local}/secrets.json`)) {
  save('secrets.json', JSON.stringify(Object.fromEntries(['database', 'runtime', 'provider', 'credential'].map(k => [k, randomBytes(24).toString('hex')]))), 0o600);
}
const secrets = JSON.parse(readFileSync(`${local}/secrets.json`));
save('demo.env', `LEASEGATE_DB_PASSWORD=${secrets.database}\n`, 0o600);
save('provider.secret', secrets.credential + '\n');
const db = (user, pass, host = 'postgres:5432') => `postgres://${user}:${pass}@${host}/leasegate?sslmode=disable`;
json('admin.json', { database: db('fixture_admin', secrets.database, '127.0.0.1:55449'), runtimePassword: secrets.runtime, providerPassword: secrets.provider });
const common = { listen: ':8443', database: db('leasegate_runtime', secrets.runtime), cert: '/run/server.crt', key: '/run/server.key', ca: '/run/ca.crt', grantPublic: '/run/grant.pub' };
json('control.json', { ...common, mode: 'control', grantPrivate: '/run/grant.key', auditKey: '/run/audit.key', releasePublic: '/run/release.pub' });
json('gateway.json', { ...common, mode: 'gateway', provider: 'https://provider:8443', providerCredentialFile: '/run/provider.secret' });
json('provider.json', { ...common, mode: 'provider', database: db('leasegate_provider', secrets.provider), providerCredentialFile: '/run/provider.secret' });
console.log('Local CA, fixture identities and service configuration ready in .local/');
