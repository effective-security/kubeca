#!/bin/bash
# Key ceremony, step 1: generate the root CA key on the root KMS and a
# self-signed root certificate.
#
# Outputs (<out> is the --out prefix): <out>.key (the KMS key URI, mode 0600),
# <out>.csr, <out>.pem. An existing <out>.pem is kept unless --force is given,
# so a rerun never replaces a root by accident.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: gen_root.sh --out PREFIX --key-label LABEL --csr-profile FILE --cert-profile NAME --hsm-config FILE --ca-config FILE [--force]
  --out PREFIX         output prefix: PREFIX.key, PREFIX.csr, PREFIX.pem
  --key-label LABEL    label of the key generated on the KMS/HSM
  --csr-profile FILE   hsm-tool CSR profile (subject, key algorithm)
  --cert-profile NAME  profile in --ca-config to issue the root with (ca_constraint.is_ca)
  --hsm-config FILE    xpki token config of the root KMS/HSM
  --ca-config FILE     xpki CA config with the profiles
  --force              regenerate even if PREFIX.pem exists
Environment: HSM_TOOL, XPKI_TOOL override the tool paths (default: PATH, then ./bin).
USAGE
}

die() { printf 'gen_root: %s\n' "$*" >&2; exit 1; }

OUT=; KEY_LABEL=; CSR_PROFILE=; CERT_PROFILE=; HSM_CONFIG=; CA_CONFIG=; FORCE=NO
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out|--key-label|--csr-profile|--cert-profile|--hsm-config|--ca-config)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            case "$1" in
                --out) OUT=$2 ;;
                --key-label) KEY_LABEL=$2 ;;
                --csr-profile) CSR_PROFILE=$2 ;;
                --cert-profile) CERT_PROFILE=$2 ;;
                --hsm-config) HSM_CONFIG=$2 ;;
                --ca-config) CA_CONFIG=$2 ;;
            esac
            shift 2 ;;
        --force) FORCE=YES; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "invalid argument $1: use --help" ;;
    esac
done
for v in OUT KEY_LABEL CSR_PROFILE CERT_PROFILE HSM_CONFIG CA_CONFIG; do
    [[ -n "${!v}" ]] || die "--$(tr '_' '-' <<< "${v,,}") is required"
done
for f in "$CSR_PROFILE" "$HSM_CONFIG" "$CA_CONFIG"; do
    [[ -f "$f" ]] || die "file not found: $f"
done

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
HSM_TOOL=${HSM_TOOL:-$(command -v hsm-tool || echo "$script_dir/../bin/hsm-tool")}
XPKI_TOOL=${XPKI_TOOL:-$(command -v xpki-tool || echo "$script_dir/../bin/xpki-tool")}
[[ -x "$HSM_TOOL" ]] || die "hsm-tool not found: run 'make tools' or set HSM_TOOL"

if [[ -f "$OUT.pem" && "$FORCE" != YES ]]; then
    echo "gen_root: $OUT.pem exists, keeping it (use --force to regenerate)"
    exit 0
fi
mkdir -p -- "$(dirname -- "$OUT")"

echo "gen_root: generating key $KEY_LABEL on $HSM_CONFIG and self-signing with profile $CERT_PROFILE"
"$HSM_TOOL" --cfg "$HSM_CONFIG" csr gen-cert \
    --self-sign \
    --ca-config "$CA_CONFIG" \
    --csr-profile "$CSR_PROFILE" \
    --profile "$CERT_PROFILE" \
    --key-label "$KEY_LABEL" \
    --output "$OUT"

chmod 600 -- "$OUT.key"
echo "gen_root: wrote $OUT.pem, $OUT.csr, $OUT.key (key URI, 0600)"
if [[ -x "$XPKI_TOOL" ]]; then
    "$XPKI_TOOL" cert info "$OUT.pem" | sed -n '1,12p'
fi
