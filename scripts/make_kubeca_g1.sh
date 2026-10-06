#!/bin/bash
# Issuing CA (G1) ceremony wrapper. Environment: HSM_CONFIG (issuing KMS token
# config), ROOT_HSM_CONFIG (root KMS token config; default HSM_CONFIG),
# CA_CONFIG, CSR_FOLDER, OUT_DIR, KEY_LABEL, ROOT_CA, ROOT_CA_KEY, optional
# FORCE=--force.
set -euo pipefail

: "${HSM_CONFIG:?set HSM_CONFIG}" "${CA_CONFIG:?set CA_CONFIG}" "${CSR_FOLDER:?set CSR_FOLDER}" \
  "${OUT_DIR:?set OUT_DIR}" "${KEY_LABEL:?set KEY_LABEL}" "${ROOT_CA:?set ROOT_CA}" "${ROOT_CA_KEY:?set ROOT_CA_KEY}"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
echo "*** kubeca G1: ${OUT_DIR}/kubeca_ca_g1_${KEY_LABEL}"
"$script_dir/gen_ca.sh" \
	--out "${OUT_DIR}/kubeca_ca_g1_${KEY_LABEL}" \
	--key-label "KUBECA_G1_${KEY_LABEL}" \
	--csr-profile "etc/csr_profile/${CSR_FOLDER}/kubeca_ca_g1.yaml" \
	--cert-profile L1_CA \
	--hsm-config "${HSM_CONFIG}" \
	--root-hsm-config "${ROOT_HSM_CONFIG:-$HSM_CONFIG}" \
	--ca-config "${CA_CONFIG}" \
	--root-ca "${ROOT_CA}" \
	--root-ca-key "${ROOT_CA_KEY}" \
	${FORCE:-}
