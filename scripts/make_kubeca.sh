#!/bin/bash
# Root CA ceremony wrapper. Environment: HSM_CONFIG (root KMS token config),
# CA_CONFIG, CSR_FOLDER (etc/csr_profile/<folder>), OUT_DIR, KEY_LABEL,
# optional FORCE=--force.
set -euo pipefail

: "${HSM_CONFIG:?set HSM_CONFIG}" "${CA_CONFIG:?set CA_CONFIG}" "${CSR_FOLDER:?set CSR_FOLDER}" \
  "${OUT_DIR:?set OUT_DIR}" "${KEY_LABEL:?set KEY_LABEL}"

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
echo "*** kubeca root: ${OUT_DIR}/kubeca_root_${KEY_LABEL}"
mkdir -p "${OUT_DIR}"
"$script_dir/gen_root.sh" \
	--out "${OUT_DIR}/kubeca_root_${KEY_LABEL}" \
	--key-label "KUBECA_ROOT_${KEY_LABEL}" \
	--csr-profile "etc/csr_profile/${CSR_FOLDER}/kubeca_root.yaml" \
	--cert-profile ROOT \
	--hsm-config "${HSM_CONFIG}" \
	--ca-config "${CA_CONFIG}" \
	${FORCE:-}
