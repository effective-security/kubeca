#!/bin/bash
# Verify the operator and the (deprecated) init-container flow in minikube.
#
# Operator (examples/shop/e2e): the chart's ClusterIssuer is Ready, the
# Certificate e2e-api-tls is issued into a kubernetes.io/tls Secret the
# Deployment mounts, the chain validates against the ceremony root, the CA
# bundle ConfigMap exists, the certificate is renewed with a new key within
# its 5-minute lifetime (next revision) and the certmonitor of the running
# Pod logs the new certificate, the labeled Pod e2e-worker gets the
# webhook-injected volume and its own Certificate, and the chart's
# ValidatingAdmissionPolicy type-checks and denies a Pod-controlled
# Certificate created by another user.
#
# Init container (examples/initcontainer): the CSR is approved by the
# in-process approver (-approve=enforce) and signed, the certmonitor of the
# Pod loads the certificate the init container wrote, the chain validates,
# and kubeca logged JSON lines.
#
# The workload containers run certmonitor (distroless: no shell, ls or
# cat), so nothing here execs into them: their log says which certificate
# they loaded, and the certificates are read from the Secrets and the CSR.
#
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

# serial_dec turns a colon-separated hex serial (status.serialNumber, the
# Secret's serial annotation) into the decimal form certmonitor prints.
serial_dec() {
    python3 -I -c 'import sys; print(int(sys.argv[1].replace(":", ""), 16))' "$1"
}

# monitor_serial <pod> <container> prints the serial of the last certificate
# certmonitor logged in that container, or nothing.
monitor_serial() {
    # a container that is not up yet has no log: an empty answer, not an
    # error (set -e would end the caller's retry loop)
    { kubectl -n "$APP_NAMESPACE" logs "$1" -c "$2" 2>/dev/null || true; } | sed -n 's/^  serial number: //p' | tail -1
}

# current_pod <deployment>: the Pod of the Deployment's current ReplicaSet,
# the one with the Deployment's revision. After a rollout the old Pods stay
# a while, and an apply that changes the template followed by a restart
# creates two ReplicaSets whose Pods can share a creation second, so the
# newest Pod by creation time can be one about to be deleted.
current_pod() {
    local revision hash
    revision=$(kubectl -n "$APP_NAMESPACE" get deploy "$1" -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')
    hash=$(kubectl -n "$APP_NAMESPACE" get rs -l app="$1" \
        -o jsonpath="{.items[?(@.metadata.annotations.deployment\.kubernetes\.io/revision==\"$revision\")].metadata.labels.pod-template-hash}")
    [[ -n "$hash" ]] || { echo "no ReplicaSet of revision $revision for deployment $1" >&2; return 1; }
    kubectl -n "$APP_NAMESPACE" get pod -l app="$1",pod-template-hash="$hash" -o jsonpath='{.items[0].metadata.name}'
}

# wait_monitor <pod> <container> <secret> <seconds>: wait until the last
# certificate certmonitor logged is the one the Secret holds now (the
# kubelet updates a Secret volume within about a minute, certmonitor polls
# the files every -interval).
wait_monitor() {
    local pod=$1 container=$2 secret=$3 want got=""
    for _ in $(seq 1 "$4"); do
        want=$(serial_dec "$(kubectl -n "$APP_NAMESPACE" get secret "$secret" -o jsonpath='{.metadata.annotations.kubeca\.effectivesecurity/serial}' 2>/dev/null || true)" 2>/dev/null || true)
        got=$(monitor_serial "$pod" "$container")
        [[ -n "$got" && "$got" == "$want" ]] && return 0
        sleep 1
    done
    echo "$pod/$container: certmonitor logged serial ${got:-none}, Secret $secret holds $want" >&2
    kubectl -n "$APP_NAMESPACE" logs "$pod" -c "$container" --tail=30 >&2 || true
    return 1
}

# ---------------------------------------------------------------------------
# Operator
# ---------------------------------------------------------------------------
echo "*** ClusterIssuer (created by the chart)"
kubectl wait --for=condition=Ready clusterissuer/kubeca --timeout=60s
kubectl get clusterissuer kubeca

echo "*** operator workload"
kubectl apply -f examples/shop/namespace.yaml
# a fresh Pod every run: the webhook injects it again and the garbage
# collector removes the Certificate and Secret of the previous one (the
# Certificate is deleted here as well, so the Pod controller never meets
# the previous Pod's Certificate)
kubectl -n "$APP_NAMESPACE" delete pod e2e-worker --ignore-not-found --wait=true
kubectl -n "$APP_NAMESPACE" delete certificate e2e-worker --ignore-not-found --wait=true
# a fresh Certificate and issuance every run, deleted before the apply so
# that the Ready condition the wait observes is this run's (a Certificate
# kept from the previous run would still read Ready=True until the
# controller handles the Secret deletion)
kubectl -n "$APP_NAMESPACE" delete certificate e2e-api-tls --ignore-not-found --wait=true
kubectl -n "$APP_NAMESPACE" delete secret e2e-api-tls --ignore-not-found
kubectl apply -f examples/shop/e2e/workload.yaml
kubectl -n "$APP_NAMESPACE" wait --for=condition=Ready certificate/e2e-api-tls --timeout=120s
kubectl -n "$APP_NAMESPACE" get certificates
revision=$(kubectl -n "$APP_NAMESPACE" get certificate e2e-api-tls -o jsonpath='{.status.revision}')
echo "e2e-api-tls revision $revision"
kubectl -n "$APP_NAMESPACE" get secret e2e-api-tls -o jsonpath='{.type}{"\n"}' | grep -q '^kubernetes.io/tls$'
for key in tls.crt tls.key ca.crt; do
    kubectl -n "$APP_NAMESPACE" get secret e2e-api-tls -o jsonpath="{.data.$(echo "$key" | sed 's/\./\\./g')}" | base64 -d > "$OUT_DIR/minikube_api_${key}_$KEY_LABEL"
    [[ -s "$OUT_DIR/minikube_api_${key}_$KEY_LABEL" ]] || { echo "Secret e2e-api-tls: $key is empty" >&2; exit 1; }
done
"$XPKI_TOOL" cert validate "$OUT_DIR/minikube_api_tls.crt_$KEY_LABEL" --root "$ROOT" >/dev/null
echo "e2e-api-tls chains to $ROOT"
"$XPKI_TOOL" cert info "$OUT_DIR/minikube_api_tls.crt_$KEY_LABEL" | sed -n '1,30p'
diff -q "$OUT_DIR/minikube_api_ca.crt_$KEY_LABEL" "$ROOT" >/dev/null && echo "ca.crt is the ceremony root"
kubectl -n "$APP_NAMESPACE" get configmap kubeca-ca -o jsonpath='{.data.ca\.crt}' | diff -q - "$ROOT" >/dev/null && echo "ConfigMap kubeca-ca holds the root"

# a fresh Pod every run, so its certmonitor starts on this run's Secret
kubectl -n "$APP_NAMESPACE" rollout restart deploy/e2e-api
kubectl -n "$APP_NAMESPACE" rollout status deploy/e2e-api --timeout=120s
api_pod=$(current_pod e2e-api)
wait_monitor "$api_pod" api e2e-api-tls 90
echo "$api_pod: certmonitor loaded the certificate of e2e-api-tls"

echo "*** waiting for the renewal of e2e-api-tls (5m lifetime, renewBefore 2m: about 3 min)"
serial=$(kubectl -n "$APP_NAMESPACE" get certificate e2e-api-tls -o jsonpath='{.status.serialNumber}')
key_before=$(kubectl -n "$APP_NAMESPACE" get secret e2e-api-tls -o jsonpath='{.data.tls\.key}')
for _ in $(seq 1 60); do
    sleep 5
    now=$(kubectl -n "$APP_NAMESPACE" get certificate e2e-api-tls -o jsonpath='{.status.revision}')
    [[ "$now" -gt "$revision" ]] && break
done
[[ "$now" -gt "$revision" ]] || { echo "e2e-api-tls was not renewed (revision $now)" >&2; kubectl -n "$APP_NAMESPACE" describe certificate e2e-api-tls; exit 1; }
[[ "$(kubectl -n "$APP_NAMESPACE" get certificate e2e-api-tls -o jsonpath='{.status.serialNumber}')" != "$serial" ]] || { echo "serial did not change" >&2; exit 1; }
[[ "$(kubectl -n "$APP_NAMESPACE" get secret e2e-api-tls -o jsonpath='{.data.tls\.key}')" != "$key_before" ]] || { echo "key did not rotate" >&2; exit 1; }
echo "e2e-api-tls renewed: revision $now, new serial and key"
kubectl -n "$APP_NAMESPACE" get events --field-selector involvedObject.name=e2e-api-tls | tail -5
# the running Pod sees the renewal without a restart
wait_monitor "$api_pod" api e2e-api-tls 150
kubectl -n "$APP_NAMESPACE" logs "$api_pod" -c api | grep -q 'certificate reloaded' || { echo "$api_pod: no reload logged" >&2; exit 1; }
echo "$api_pod: certmonitor reloaded the renewed certificate"
kubectl -n "$APP_NAMESPACE" logs "$api_pod" -c api | tail -10

echo "*** injected Pod"
kubectl -n "$APP_NAMESPACE" wait --for=condition=Ready pod/e2e-worker --timeout=120s
kubectl -n "$APP_NAMESPACE" get pod e2e-worker -o jsonpath='{.metadata.annotations.kubeca\.effectivesecurity/secret-name}{"\n"}' | grep -q '^e2e-worker-tls$'
kubectl -n "$APP_NAMESPACE" get pod e2e-worker -o jsonpath='{.spec.volumes[*].secret.secretName}{"\n"}' | grep -q 'e2e-worker-tls'
kubectl -n "$APP_NAMESPACE" wait --for=condition=Ready certificate/e2e-worker --timeout=60s
kubectl -n "$APP_NAMESPACE" get certificate e2e-worker -o jsonpath='{.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}{"\n"}' | grep -q '^Pod/e2e-worker$'
# the mounted files are the Secret's: certmonitor in the Pod logs its serial
# (the Pod controller re-issues once the Pod has an IP, so wait for it)
wait_monitor e2e-worker worker e2e-worker-tls 90
kubectl -n "$APP_NAMESPACE" get secret e2e-worker-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$OUT_DIR/minikube_worker_$KEY_LABEL.pem"
"$XPKI_TOOL" cert validate "$OUT_DIR/minikube_worker_$KEY_LABEL.pem" --root "$ROOT" >/dev/null
"$XPKI_TOOL" cert info "$OUT_DIR/minikube_worker_$KEY_LABEL.pem" | grep -i -E "DNS|URI|IP" | head -10
echo "e2e-worker: injected Secret, owned Certificate, chain validates"

echo "*** admission policy: only the operator writes Pod-controlled Certificates"
policy="$RELEASE-pod-certificates"
kubectl get validatingadmissionpolicy "$policy" >/dev/null
# kube-controller-manager type-checks the expressions against the CRD schema
for _ in $(seq 1 30); do
    checked=$(kubectl get validatingadmissionpolicy "$policy" -o jsonpath='{.status.observedGeneration}')
    [[ -n "$checked" ]] && break
    sleep 1
done
warnings=$(kubectl get validatingadmissionpolicy "$policy" -o jsonpath='{.status.typeChecking.expressionWarnings}')
[[ -n "$checked" && -z "$warnings" ]] || { echo "policy $policy: generation ${checked:-not checked}, warnings: $warnings" >&2; exit 1; }
worker_uid=$(kubectl -n "$APP_NAMESPACE" get pod e2e-worker -o jsonpath='{.metadata.uid}')
forged="$OUT_DIR/minikube_forged_$KEY_LABEL.yaml"
cat > "$forged" <<EOF
apiVersion: kubeca.effectivesecurity/v1alpha1
kind: Certificate
metadata:
  name: e2e-forged
  namespace: $APP_NAMESPACE
  ownerReferences:
    - apiVersion: v1
      kind: Pod
      name: e2e-worker
      uid: $worker_uid
      controller: true
spec:
  issuerRef:
    name: kubeca
  secretName: e2e-forged
  uris: [spiffe://cluster.local/ns/$APP_NAMESPACE/sa/e2e-worker]
EOF
# system:masters spares the RBAC setup; admission applies to every user
if out=$(kubectl --as=e2e-author --as-group=system:masters create -f "$forged" 2>&1); then
    kubectl -n "$APP_NAMESPACE" delete certificate e2e-forged --ignore-not-found
    echo "a forged Pod-controlled Certificate was accepted" >&2
    exit 1
fi
grep -q 'only the kubeca operator may create a Certificate controlled by a Pod' <<<"$out" || { echo "unexpected error: $out" >&2; exit 1; }
echo "forged Certificate denied by $policy"

# ---------------------------------------------------------------------------
# Init container (deprecated)
# ---------------------------------------------------------------------------
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

# the Pod of the current ReplicaSet and its CSR (kubecertinit names it
# <pod>-<namespace>-<random>): Pods of an earlier rollout may still be
# terminating, and their CSRs remain
pod=$(current_pod web)
echo "*** CSRs"
kubectl get csr -l app=web
csr=$(kubectl get csr -l app=web -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep "^$pod-$APP_NAMESPACE-" | tail -1 || true)
[[ -n "$csr" ]] || { echo "no CSR of $pod" >&2; exit 1; }
kubectl get csr "$csr" -o jsonpath='{.status.conditions[*].type}{"\n"}' | grep -q Approved || { echo "$csr was not approved by the in-process approver" >&2; exit 1; }
echo "$csr approved by the in-process approver"
echo "*** init container log"
kubectl -n "$APP_NAMESPACE" logs "$pod" -c certificate-init

echo "*** certificate in the Pod"
# what the init container wrote is the CSR's certificate; certmonitor in
# the web container loaded it (tls.crt and a matching tls.key are there)
kubectl get csr "$csr" -o jsonpath='{.status.certificate}' | base64 -d > "$OUT_DIR/minikube_web_$KEY_LABEL.pem"
for _ in $(seq 1 30); do
    kubectl -n "$APP_NAMESPACE" logs "$pod" -c web 2>/dev/null | grep -q 'certificate loaded' && break
    sleep 1
done
kubectl -n "$APP_NAMESPACE" logs "$pod" -c web | grep -q 'certificate loaded' || { echo "$pod: certmonitor loaded no certificate" >&2; kubectl -n "$APP_NAMESPACE" logs "$pod" -c web --tail=20 >&2; exit 1; }
kubectl -n "$APP_NAMESPACE" logs "$pod" -c web

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
