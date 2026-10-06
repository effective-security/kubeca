include .project/gomod-project.mk

SHA := $(shell git rev-parse HEAD)

BUILD_FLAGS=
# LDFLAGS sets the build version reported by -version (internal/version).
LDFLAGS=-ldflags "-X github.com/effective-security/kubeca/internal/version.build=$(GIT_VERSION)"

.PHONY: *

.SILENT:

default: help

all: clean folders tools generate build test change_log

#
# clean produced files
#
clean:
	echo "Running clean"
	go clean
	rm -rf \
		./bin \
		./.gopath \
		${COVPATH} \

GOLANGCI_LINT_VERSION ?= v2.13.2

tools:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/go-phorce/cov-report/cmd/cov-report@latest
	go install github.com/mattn/goveralls@latest
	go install github.com/effective-security/xpki/cmd/hsm-tool@latest
	go install github.com/effective-security/xpki/cmd/xpki-tool@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

folders:

version:
	echo "$(GIT_VERSION)"

build_kube:
	echo "*** Building kubeca"
	go build ${BUILD_FLAGS} ${LDFLAGS} -o ${PROJ_ROOT}/bin/kubeca ./cmd/kubeca

build_kubecertinitt:
	echo "*** Building kubecertinit"
	go build ${BUILD_FLAGS} ${LDFLAGS} -o ${PROJ_ROOT}/bin/kubecertinit ./cmd/kubecertinit

build: build_kube build_kubecertinitt

change_log:
	echo "Recent changes" > ./change_log.txt
	echo "Build Version: $(GIT_VERSION)" >> ./change_log.txt
	echo "Commit: $(GIT_HASH)" >> ./change_log.txt
	echo "==================================" >> ./change_log.txt
	git log -n 20 --pretty=oneline --abbrev-commit >> ./change_log.txt

commit_version:
	git add .; git commit -m "Updated version"

coveralls-github:
	echo "Running coveralls"
	goveralls -v -coverprofile=coverage.out -service=github -package ./...

docker: change_log
	docker build --no-cache -f Dockerfile.kubeca -t effectivesecurity/kubeca:main .
	docker build --no-cache -f Dockerfile.kubecertinit -t effectivesecurity/kubecertinit:main .

docker-compose:
	docker compose -f docker-compose.yml up --abort-on-container-exit

docker-push: docker
	[ ! -z ${DOCKER_PASSWORD} ] && echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin || echo "skipping docker login"
	docker push effectivesecurity/kubeca:main
	docker push effectivesecurity/kubecertinit:main
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effectivesecurity/kubeca:${DOCKER_NUMBER} || echo "kubeca: skipping docker version, pushing latest only"
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effectivesecurity/kubecertinit:${DOCKER_NUMBER} || echo "kubecertinit: skipping docker version, pushing latest only"

# ---------------------------------------------------------------------------
# Key ceremony and local test (Documentation/key-ceremony.md, README "Local
# test with minikube"). Outputs go to .tmp/ (ignored by Git).
# ---------------------------------------------------------------------------
# KEY_LABEL names the local ceremony output (.tmp/kubeca_*_<label>). The AWS
# targets use AWS_KEY_LABEL: a timestamp evaluated once per make invocation
# unless set; `kubeca-ceremony-aws` runs both AWS steps with one label, and a
# later `kubeca-g1-aws` needs the root's label (AWS_KEY_LABEL=<label>).
KEY_LABEL ?= local
ifndef AWS_KEY_LABEL
AWS_KEY_LABEL := $(shell date '+%y%m%d%H%M%S')
endif
export AWS_DEFAULT_REGION ?= us-west-2
# local-kms ignores credentials; the SDK still requires them.
LOCAL_KMS_ENV=AWS_ACCESS_KEY_ID=notusedbyemulator AWS_SECRET_ACCESS_KEY=notusedbyemulator AWS_DEFAULT_REGION=$(AWS_DEFAULT_REGION)
OUT_DIR ?= .tmp

start-local-kms:
	echo "*** starting local-kms (kms1 root :14599, kms2 issuing :24599)"
	docker compose -f docker-compose.yml up -d
	./scripts/wait_tcp.sh localhost:14599 localhost:24599

stop-local-kms:
	docker compose -f docker-compose.yml down

# Root CA on kms1, self-signed, key label KUBECA_ROOT_local.
kubeca-root-local:
	echo "*** kubeca-root-local"
	$(LOCAL_KMS_ENV) HSM_CONFIG=./etc/aws-dev-kms-local1.yaml \
	CA_CONFIG=./etc/ca-config.bootstrap.yaml CSR_FOLDER=dev OUT_DIR=$(OUT_DIR) KEY_LABEL=$(KEY_LABEL) \
	./scripts/make_kubeca.sh

# Issuing CA G1: key on kms2, CSR signed by the root key on kms1. Depends on
# the root target so `make -j` keeps the order; an existing root is kept.
kubeca-g1-local: kubeca-root-local
	echo "*** kubeca-g1-local"
	$(LOCAL_KMS_ENV) HSM_CONFIG=./etc/aws-dev-kms-local2.yaml ROOT_HSM_CONFIG=./etc/aws-dev-kms-local1.yaml \
	CA_CONFIG=./etc/ca-config.bootstrap.yaml CSR_FOLDER=dev OUT_DIR=$(OUT_DIR) KEY_LABEL=$(KEY_LABEL) \
	ROOT_CA=$(OUT_DIR)/kubeca_root_$(KEY_LABEL).pem ROOT_CA_KEY=$(OUT_DIR)/kubeca_root_$(KEY_LABEL).key \
	./scripts/make_kubeca_g1.sh

kubeca-ceremony-local: kubeca-g1-local
	echo "*** ceremony done: $(OUT_DIR)/kubeca_root_$(KEY_LABEL).pem, $(OUT_DIR)/kubeca_ca_g1_$(KEY_LABEL).{pem,key}"

# Real KMS: the root KMS config is ROOT_HSM_CONFIG, the issuing one HSM_CONFIG;
# both default to the region config in the chart. AWS_KEY_LABEL is a timestamp
# unless set; FORCE=--force regenerates.
HSM_CONFIG ?= ./examples/kubeca/etc/aws-kms-$(AWS_DEFAULT_REGION).yaml
ROOT_HSM_CONFIG ?= $(HSM_CONFIG)

kubeca-root-aws:
	echo "*** kubeca-root-aws"
	HSM_CONFIG=$(ROOT_HSM_CONFIG) CA_CONFIG=./etc/ca-config.bootstrap.yaml CSR_FOLDER=prod \
	OUT_DIR=$(OUT_DIR) KEY_LABEL=$(AWS_KEY_LABEL) ./scripts/make_kubeca.sh

kubeca-g1-aws:
	echo "*** kubeca-g1-aws"
	HSM_CONFIG=$(HSM_CONFIG) ROOT_HSM_CONFIG=$(ROOT_HSM_CONFIG) CA_CONFIG=./etc/ca-config.bootstrap.yaml CSR_FOLDER=prod \
	OUT_DIR=$(OUT_DIR) KEY_LABEL=$(AWS_KEY_LABEL) \
	ROOT_CA=$(OUT_DIR)/kubeca_root_$(AWS_KEY_LABEL).pem ROOT_CA_KEY=$(OUT_DIR)/kubeca_root_$(AWS_KEY_LABEL).key \
	./scripts/make_kubeca_g1.sh

# Both AWS steps with one label, in order.
kubeca-ceremony-aws:
	echo "*** kubeca-ceremony-aws, label $(AWS_KEY_LABEL)"
	$(MAKE) kubeca-root-aws AWS_KEY_LABEL=$(AWS_KEY_LABEL)
	$(MAKE) kubeca-g1-aws AWS_KEY_LABEL=$(AWS_KEY_LABEL)

# minikube: build the images, load them, install the chart with the ceremony
# output, deploy a dummy workload with the init container and verify it.
minikube-images: build change_log
	./scripts/minikube_images.sh

minikube-deploy:
	OUT_DIR=$(OUT_DIR) KEY_LABEL=$(KEY_LABEL) ./scripts/minikube_deploy.sh

minikube-test:
	OUT_DIR=$(OUT_DIR) KEY_LABEL=$(KEY_LABEL) ./scripts/minikube_test.sh

minikube-clean:
	./scripts/minikube_clean.sh

# Sequential by recipe, so `make -j` cannot reorder the stages.
minikube-all:
	$(MAKE) start-local-kms
	$(MAKE) kubeca-ceremony-local
	$(MAKE) minikube-images
	$(MAKE) minikube-deploy
	$(MAKE) minikube-test
