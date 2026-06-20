#!/bin/bash
# One-time ACME account registration for GlobalSign Atlas.
#
# Usage:
#   ./scripts/register-acme.sh <eab-kid> <eab-hmac-key> <email>
#
# GlobalSign requires External Account Binding (EAB). Obtain the
# KID and HMAC key from the Atlas portal:
#   API Credentials → Request an ACME MAC
#
# After registration, the account is stored in the certbot config
# directory. Subsequent renewals no longer need the EAB credentials.

set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <eab-kid> <eab-hmac-key> <email>" >&2
    exit 1
fi

EAB_KID="$1"
EAB_HMAC_KEY="$2"
EMAIL="$3"

SERVER="https://emea.acme.atlas.globalsign.com/directory"
CONFIG_DIR="/data/cert-renew/letsencrypt"

if [ -f "$CONFIG_DIR/accounts/acme.atlas.globalsign.com/directory" ]; then
    echo "ACME account already registered for GlobalSign."
    echo "To re-register, remove: $CONFIG_DIR/accounts/"
    exit 0
fi

certbot register \
    --server "$SERVER" \
    --eab-kid "$EAB_KID" \
    --eab-hmac-key "$EAB_HMAC_KEY" \
    --email "$EMAIL" \
    --agree-tos \
    --config-dir "$CONFIG_DIR" \
    --work-dir /tmp/certbot-work \
    --logs-dir /tmp/certbot-logs \
    -n

echo ""
echo "Registration successful. You can now issue certificates:"
echo ""
echo "  certbot certonly \\"
echo "    --manual --preferred-challenges dns-01 \\"
echo "    --manual-auth-hook 'curl -X POST http://localhost:8000/acme/auth ...' \\"
echo "    --manual-cleanup-hook 'curl -X POST http://localhost:8000/acme/cleanup ...' \\"
echo "    --deploy-hook /opt/deploy-hook.sh \\"
echo "    --server $SERVER \\"
echo "    --config-dir $CONFIG_DIR \\"
echo "    -d example.com"
