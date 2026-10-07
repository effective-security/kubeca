#!/bin/bash
# Install kubeca into minikube with the certificates of the local ceremony:
# creates the namespace and the certs Secret the chart expects
# (<release>-certs-secret-tf with kubeca_ca_g1.pem, kubeca_ca_g1.key,
# kubeca_root.pem), applies the CRDs, installs the chart with
# examples/kubeca/minikube.yaml (which also creates the ClusterIssuer) and
# waits for the rollout. Environment: NAMESPACE (kubeca), RELEASE (kubeca),
# OUT_DIR (.tmp), KEY_LABEL (local).
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
NAMESPACE=${NAMESPACE:-kubeca}
RELEASE=${RELEASE:-kubeca}
OUT_DIR=${OUT_DIR:-.tmp}
KEY_LABEL=${KEY_LABEL:-local}
G1="$OUT_DIR/kubeca_ca_g1_$KEY_LABEL"
ROOT="$OUT_DIR/kubeca_root_$KEY_LABEL"
for f in "$G1.pem" "$G1.key" "$ROOT.pem"; do
    [[ -f "$f" ]] || { echo "$f missing: run make kubeca-ceremony-local" >&2; exit 1; }
done
kubectl config current-context | grep -q minikube || { echo "current context is not minikube" >&2; exit 1; }

echo "*** namespace $NAMESPACE and certs Secret"
kubectl get ns "$NAMESPACE" >/dev/null 2>&1 || kubectl create ns "$NAMESPACE"
kubectl -n "$NAMESPACE" create secret generic "$RELEASE-certs-secret-tf" \
    --from-file=kubeca_ca_g1.pem="$G1.pem" \
    --from-file=kubeca_ca_g1.key="$G1.key" \
    --from-file=kubeca_root.pem="$ROOT.pem" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "*** CRDs (helm installs crds/ on install only, never on upgrade)"
kubectl apply -f examples/kubeca/crds/

echo "*** helm upgrade --install $RELEASE"
# fullnameOverride keeps every chart resource (Deployment, certs Secret) named
# after the release, whatever the release name is
helm upgrade --install "$RELEASE" examples/kubeca -n "$NAMESPACE" -f examples/kubeca/minikube.yaml \
    --set fullnameOverride="$RELEASE" --wait --timeout 3m
# the image tag does not change between builds: restart to pick up a reloaded image
kubectl -n "$NAMESPACE" rollout restart deploy/"$RELEASE"
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE" --timeout=120s

echo "*** waiting for the controller to stay up"
for _ in $(seq 1 12); do
    sleep 5
    pod=$(kubectl -n "$NAMESPACE" get pod -l app.kubernetes.io/instance="$RELEASE" \
        --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    restarts=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 1)
    # the caBundle is patched by whichever replica started first, so it is
    # checked on the configuration rather than in this Pod's log
    ca_bundle=$(kubectl get mutatingwebhookconfiguration "$RELEASE-pod-injector" -o jsonpath='{.webhooks[0].clientConfig.caBundle}' 2>/dev/null || true)
    if [[ -n "$pod" && "$restarts" == 0 && -n "$ca_bundle" ]] && kubectl -n "$NAMESPACE" logs "$pod" | grep -q '"status":"starting controller"'; then
        kubectl -n "$NAMESPACE" get pods
        echo "*** kubeca is running: $pod"
        exit 0
    fi
done
echo "*** kubeca did not stay up; logs:" >&2
kubectl -n "$NAMESPACE" get pods
kubectl -n "$NAMESPACE" logs deploy/"$RELEASE" --tail=30 || true
exit 1
