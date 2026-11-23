#!/bin/sh
# Check the signature on the agentgateway index digest named in agentgateway.lock.json.
#
# The identity and the OIDC issuer are the values in the signing certificate read
# on 2026-11-23. They are exact strings. This does not accept another repository,
# and it does not take a wildcard.
#
#   verify-signature.sh /path/to/cosign
#
# cosign is not in this repository. This script does not download it, and it does
# not download the image. It runs cosign verify. A proxy already set in the
# environment is left as it is. The command checks the claims, the transparency
# log, and the certificate chain. It does not skip those checks.
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "usage: verify-signature.sh <path-to-cosign>" >&2
    exit 2
fi
cosign=$1
if [ ! -x "$cosign" ]; then
    echo "cosign is not an executable file: $cosign" >&2
    exit 2
fi

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
lock=$here/agentgateway.lock.json

parsed=$(python3 - "$lock" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
repository = data["image"]["repository"]
digest = data["image"]["index"]
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", repository):
    raise SystemExit("lock repository is not a registry name")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("lock index is not a sha256 digest")
sys.stdout.write(repository + "\n" + digest + "\n")
PY
) || exit 1

repository=$(printf '%s\n' "$parsed" | sed -n '1p')
digest=$(printf '%s\n' "$parsed" | sed -n '2p')
if [ -z "$repository" ] || [ -z "$digest" ]; then
    echo "lock file did not yield a repository and an index digest" >&2
    exit 1
fi

# SAN URI of the signing certificate. Upstream workflow only.
identity='https://github.com/agentgateway/agentgateway/.github/workflows/release.yml@refs/tags/v1.7.0'
# OIDC issuer in that certificate.
issuer='https://token.actions.githubusercontent.com'

exec "$cosign" verify \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$repository@$digest"
