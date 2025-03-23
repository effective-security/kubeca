include .project/gomod-project.mk

SHA := $(shell git rev-parse HEAD)

export GOPRIVATE=github.com/effective-security
export GO111MODULE=on
BUILD_FLAGS=

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

tools:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/go-phorce/cov-report/cmd/cov-report@latest
	go install github.com/mattn/goveralls@latest
	go install github.com/effective-security/xpki/cmd/hsm-tool@latest
	go install github.com/effective-security/xpki/cmd/xpki-tool@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

folders:

version:
	echo "*** building version $(GIT_VERSION)"
	gofmt -r '"GIT_VERSION" -> "$(GIT_VERSION)"' internal/version/current.template > internal/version/current.go

build_kube:
	echo "*** Building kubeca"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/kubeca ./cmd/kubeca

build_kubecertinitt:
	echo "*** Building kubecertinit"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/kubecertinit ./cmd/kubecertinit

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
	docker-compose -f docker-compose.dev.yml up --abort-on-container-exit

docker-push: docker
	[ ! -z ${DOCKER_PASSWORD} ] && echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin || echo "skipping docker login"
	docker push effectivesecurity/kubeca:main
	docker push effectivesecurity/kubecertinit:main
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effectivesecurity/kubeca:${DOCKER_NUMBER} || echo "kubeca: skipping docker version, pushing latest only"
	#[ ! -z ${DOCKER_NUMBER} ] && docker push effectivesecurity/kubecertinit:${DOCKER_NUMBER} || echo "kubecertinit: skipping docker version, pushing latest only"
