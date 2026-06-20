#!/bin/bash
# Certbot deploy hook for cert-renew
# Called by certbot after a successful renewal.
# Certbot sets RENEWED_DOMAINS and RENEWED_LINEAGE.

set -euo pipefail

API_KEY="${ACME_WEBHOOK_API_KEY:?ACME_WEBHOOK_API_KEY not set}"
WEBHOOK_URL="${ACME_WEBHOOK_URL:-http://localhost:8000}"
DOMAIN=$(echo "$RENEWED_DOMAINS" | awk '{print $1}')

python3 -c "
import json, os, sys
from urllib.request import Request, urlopen

webhook_url = os.environ['WEBHOOK_URL']
api_key = os.environ['API_KEY']
domain = os.environ['DOMAIN']
lineage = os.environ['RENEWED_LINEAGE']

def read_pem(name):
    path = os.path.join(lineage, name)
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None

payload = json.dumps({
    'domain': domain,
    'cert_pem': read_pem('cert.pem') or '',
    'chain_pem': read_pem('chain.pem'),
    'fullchain_pem': read_pem('fullchain.pem') or '',
    'privkey_pem': read_pem('privkey.pem') or '',
}).encode()

req = Request(
    f'{webhook_url}/acme/deploy',
    data=payload,
    headers={
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
    },
    method='POST',
)
try:
    resp = urlopen(req, timeout=30)
    print(f'deploy response ({resp.status}): {resp.read().decode()}', flush=True)
except Exception as e:
    print(f'deploy error: {e}', flush=True)
    sys.exit(1)
"