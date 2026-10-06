#!/bin/bash
# Deploy the dummy workload with the kubecertinit init container, wait for it,
# and verify: the CSR was signed, the Pod holds tls.key/tls.csr/tls.crt, the
# certificate chains to the ceremony root, and kubeca logged JSON lines.
# Environment: NAMESPACE (kubeca), RELEASE (kubeca), OUT_DIR (.tmp),
# KEY_LABEL (local). The workload namespace is fixed by the manifests.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
NAMESPACE=${NAMESPACE:-kubeca}
RELEASE=${RELEASE:-kubeca}
OUT_DIR=${OUT_DIR:-.tmp}
KEY_LABEL=${KEY_LABEL:-local}
# namespace of examples/initcontainer/{rbac,dummy-deployment}.yaml
APP_NAMESPACE=shop
ROOT="$OUT_DIR/kubeca_root_$KEY_LABEL.pem"
XPKI_TOOL=${XPKI_TOOL:-$(command -v xpki-tool || echo ./bin/xpki-tool)}
kubectl config current-context | grep -q minikube || { echo "current context is not minikube" >&2; exit 1; }

echo "*** deploying the dummy workload"
kubectl apply -f examples/initcontainer/rbac.yaml
kubectl apply -f examples/initcontainer/dummy-deployment.yaml
# a fresh Pod every run, so the running kubeca signs a new CSR
kubectl -n "$APP_NAMESPACE" rollout restart deploy/web
kubectl -n "$APP_NAMESPACE" rollout status deploy/web --timeout=180s || {
    echo "*** rollout failed; init container logs:"
    kubectl -n "$APP_NAMESPACE" logs deploy/web -c certificate-init --tail=50 || true
    echo "*** kubeca logs:"
    kubectl -n "$NAMESPACE" logs deploy/"$RELEASE" --tail=50 || true
    exit 1
}

pod=$(kubectl -n "$APP_NAMESPACE" get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
echo "*** CSRs"
kubectl get csr -l app=web
echo "*** init container log"
kubectl -n "$APP_NAMESPACE" logs "$pod" -c certificate-init

echo "*** files in the Pod"
kubectl -n "$APP_NAMESPACE" exec "$pod" -c web -- ls -l /etc/tls
kubectl -n "$APP_NAMESPACE" exec "$pod" -c web -- cat /etc/tls/tls.crt > "$OUT_DIR/minikube_web_$KEY_LABEL.pem"

echo "*** certificate"
# standalone, so a validation failure aborts the test under set -e
"$XPKI_TOOL" cert validate "$OUT_DIR/minikube_web_$KEY_LABEL.pem" --root "$ROOT" >/dev/null
echo "chain validates against $ROOT"
"$XPKI_TOOL" cert info "$OUT_DIR/minikube_web_$KEY_LABEL.pem" | sed -n '1,40p'

echo "*** kubeca logs (last 20 lines)"
kubectl -n "$NAMESPACE" logs deploy/"$RELEASE" --tail=20 | tee "$OUT_DIR/kubeca_$KEY_LABEL.log"
echo "*** log format check: every line is a JSON object with time, level, pkg"
python3 -I - "$OUT_DIR/kubeca_$KEY_LABEL.log" <<'PY'
import json, sys
bad = 0
for n, line in enumerate(open(sys.argv[1]), 1):
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except ValueError:
        print(f"line {n}: not JSON: {line[:120]}")
        bad += 1
        continue
    missing = [k for k in ("time", "level", "pkg") if k not in obj]
    if missing:
        print(f"line {n}: missing {missing}: {line[:120]}")
        bad += 1
print("log format:", "OK" if bad == 0 else f"{bad} bad line(s)")
sys.exit(1 if bad else 0)
PY
echo "*** PASS"
