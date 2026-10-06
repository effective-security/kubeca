#!/bin/bash
# Key ceremony, step 2: generate the issuing CA key and CSR on the issuing
# KMS, then sign the CSR with the root key on the root KMS. The two KMS
# configs stay separate, as in a real ceremony where the root KMS is offline:
# only the CSR travels to the root and only the certificate comes back.
#
# Outputs (<out> is the --out prefix): <out>.key (issuing KMS key URI, 0600),
# <out>.csr, <out>.pem (issued by the root). An existing <out>.pem is kept
# unless --force is given.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: gen_ca.sh --out PREFIX --key-label LABEL --csr-profile FILE --cert-profile NAME --hsm-config FILE --ca-config FILE --root-ca FILE --root-ca-key FILE [--root-hsm-config FILE] [--force]
  --out PREFIX           output prefix: PREFIX.key, PREFIX.csr, PREFIX.pem
  --key-label LABEL      label of the key generated on the issuing KMS/HSM
  --csr-profile FILE     hsm-tool CSR profile (subject, key algorithm)
  --cert-profile NAME    profile in --ca-config the root signs with (is_ca, max_path_len)
  --hsm-config FILE      xpki token config of the issuing KMS/HSM (where the key is generated)
  --root-hsm-config FILE xpki token config of the root KMS/HSM (default: --hsm-config)
  --ca-config FILE       xpki CA config with the profiles
  --root-ca FILE         root certificate (PEM)
  --root-ca-key FILE     root key reference (the .key written by gen_root.sh)
  --force                regenerate even if PREFIX.pem exists
Environment: HSM_TOOL, XPKI_TOOL override the tool paths (default: PATH, then ./bin).
USAGE
}

die() { printf 'gen_ca: %s\n' "$*" >&2; exit 1; }

OUT=; KEY_LABEL=; CSR_PROFILE=; CERT_PROFILE=; HSM_CONFIG=; ROOT_HSM_CONFIG=; CA_CONFIG=; ROOT_CA=; ROOT_CA_KEY=; FORCE=NO
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out|--key-label|--csr-profile|--cert-profile|--hsm-config|--root-hsm-config|--ca-config|--root-ca|--root-ca-key)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            case "$1" in
                --out) OUT=$2 ;;
                --key-label) KEY_LABEL=$2 ;;
                --csr-profile) CSR_PROFILE=$2 ;;
                --cert-profile) CERT_PROFILE=$2 ;;
                --hsm-config) HSM_CONFIG=$2 ;;
                --root-hsm-config) ROOT_HSM_CONFIG=$2 ;;
                --ca-config) CA_CONFIG=$2 ;;
                --root-ca) ROOT_CA=$2 ;;
                --root-ca-key) ROOT_CA_KEY=$2 ;;
            esac
            shift 2 ;;
        --force) FORCE=YES; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "invalid argument $1: use --help" ;;
    esac
done
for v in OUT KEY_LABEL CSR_PROFILE CERT_PROFILE HSM_CONFIG CA_CONFIG ROOT_CA ROOT_CA_KEY; do
    [[ -n "${!v}" ]] || die "--$(tr '_' '-' <<< "${v,,}") is required"
done
ROOT_HSM_CONFIG=${ROOT_HSM_CONFIG:-$HSM_CONFIG}
for f in "$CSR_PROFILE" "$HSM_CONFIG" "$ROOT_HSM_CONFIG" "$CA_CONFIG" "$ROOT_CA" "$ROOT_CA_KEY"; do
    [[ -f "$f" ]] || die "file not found: $f"
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
HSM_TOOL=${HSM_TOOL:-$(command -v hsm-tool || echo "$script_dir/../bin/hsm-tool")}
XPKI_TOOL=${XPKI_TOOL:-$(command -v xpki-tool || echo "$script_dir/../bin/xpki-tool")}
[[ -x "$HSM_TOOL" ]] || die "hsm-tool not found: run 'make tools' or set HSM_TOOL"

if [[ -f "$OUT.pem" && "$FORCE" != YES ]]; then
    echo "gen_ca: $OUT.pem exists, keeping it (use --force to regenerate)"
    exit 0
fi
mkdir -p -- "$(dirname -- "$OUT")"

echo "gen_ca: generating key $KEY_LABEL and CSR on $HSM_CONFIG"
"$HSM_TOOL" --cfg "$HSM_CONFIG" csr create \
    --csr-profile "$CSR_PROFILE" \
    --key-label "$KEY_LABEL" \
    --output "$OUT"
chmod 600 -- "$OUT.key"

echo "gen_ca: signing $OUT.csr with the root key on $ROOT_HSM_CONFIG, profile $CERT_PROFILE"
"$HSM_TOOL" --cfg "$ROOT_HSM_CONFIG" csr sign \
    --ca-cert "$ROOT_CA" \
    --ca-key "$ROOT_CA_KEY" \
    --ca-config "$CA_CONFIG" \
    --profile "$CERT_PROFILE" \
    --output "$OUT" \
    "$OUT.csr"

echo "gen_ca: wrote $OUT.pem, $OUT.csr, $OUT.key (key URI, 0600)"
if [[ -x "$XPKI_TOOL" ]]; then
    echo "gen_ca: validating the chain against $ROOT_CA"
    "$XPKI_TOOL" cert validate "$OUT.pem" --root "$ROOT_CA" >/dev/null
    "$XPKI_TOOL" cert info "$OUT.pem" | sed -n '1,12p'
fi
