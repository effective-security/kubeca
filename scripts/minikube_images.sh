#!/bin/bash
# Build the kubeca and kubecertinit images from bin/ (make build change_log)
# and load them into minikube. The tag is fixed to main: examples/kubeca/minikube.yaml
# and examples/initcontainer/dummy-deployment.yaml reference it.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
IMAGE_TAG=main
for bin in kubeca kubecertinit; do
    [[ -x "bin/$bin" ]] || { echo "bin/$bin missing: run make build" >&2; exit 1; }
done
[[ -f change_log.txt ]] || { echo "change_log.txt missing: run make change_log" >&2; exit 1; }
for name in kubeca kubecertinit; do
    image="effectivesecurity/$name:$IMAGE_TAG"
    echo "*** building $image"
    docker build -q -f "Dockerfile.$name" -t "$image" . >/dev/null
    echo "*** loading $image into minikube"
    minikube image load "$image"
done
minikube image ls | grep effectivesecurity
