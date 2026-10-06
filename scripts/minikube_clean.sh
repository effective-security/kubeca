#!/bin/bash
# Remove the minikube test: the dummy workload, the chart release and both
# namespaces. The local-kms containers and .tmp are left alone.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
NAMESPACE=${NAMESPACE:-kubeca}
RELEASE=${RELEASE:-kubeca}
# namespace of examples/initcontainer/{rbac,dummy-deployment}.yaml
APP_NAMESPACE=shop
kubectl config current-context | grep -q minikube || { echo "current context is not minikube" >&2; exit 1; }
kubectl delete -f examples/initcontainer/dummy-deployment.yaml --ignore-not-found
# rbac.yaml also holds the shop Namespace, so this removes the workload namespace
kubectl delete -f examples/initcontainer/rbac.yaml --ignore-not-found
helm uninstall "$RELEASE" -n "$NAMESPACE" 2>/dev/null || true
kubectl delete ns "$NAMESPACE" --ignore-not-found
# no matching CSR is not a failure (grep exits 1 on no match)
kubectl get csr -o name | { grep -- "-$APP_NAMESPACE-" || true; } | xargs -r kubectl delete
