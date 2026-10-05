#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node scripts/fixtures.mjs
docker compose --env-file .local/demo.env up -d --wait postgres
bin/leasegate init --config .local/admin.json
docker build --quiet -t leasegate:local . > .local/image-id
docker compose --env-file .local/demo.env up -d --force-recreate provider control gateway-a gateway-b
for port in 18440 18441 18442; do
  ready=false
  for attempt in {1..30}; do
    if curl --silent --fail --max-time 2 --cacert .local/ca.crt --cert .local/auditor.crt --key .local/auditor.key "https://localhost:$port/health" > /dev/null; then ready=true; break; fi
    sleep 1
  done
  if [ "$ready" != true ]; then echo "Service on port $port did not become ready" >&2; exit 1; fi
done
bin/leasegate sign-artifact --key .local/release.key --digest "$(cat .local/image-id)" --revision "$(git rev-parse HEAD)" > .local/attestation.json
node scripts/integration.mjs
