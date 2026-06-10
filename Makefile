BPF_CLANG  := clang-18
BPF_TARGET ?= $(shell go env GOARCH)

.PHONY: all build build-harden build-tracepod clean generate test lint fmt helm-lint record-fixtures

all: build

## Generate BPF objects from the running kernel's BTF.
## Run this on a native Linux machine before building the sensor.
generate: internal/probe/vmlinux.h
	rm -f internal/probe/openat_*bpf*.go internal/probe/openat_*bpf*.o
	BPF_CLANG=$(BPF_CLANG) BPF_TARGET=$(BPF_TARGET) \
	  go generate ./internal/probe/

internal/probe/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

## Build the sensor binary (Linux only — requires 'make generate' first).
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/sensor ./cmd/sensor/

## Build the hardener binary.
build-harden:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/harden ./cmd/harden/

## Build the CLI binary.
build-tracepod:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/tracepod ./cmd/tracepod/

## Run unit tests.
test:
	go test ./...

## Run golangci-lint.
lint:
	golangci-lint run

## Format all Go source files.
fmt:
	gofmt -l -w ./...

## Lint the Helm chart.
helm-lint:
	helm lint helm/tracepod

clean:
	rm -rf bin/

## Build sensor Docker image for local development inside the k8s-dev Lima VM.
## arm64 BPF objects are committed to git so no clang/bpftool needed.
sensor-image:
	docker build --platform linux/$(shell go env GOARCH) \
	  -f Dockerfile.sensor -t tracepod-sensor:dev .

## Run full e2e tests (sensor profiles nginx → harden → validate) inside the
## k8s-dev Lima VM. Requires: limactl + 'limactl start k8s-dev' first.
e2e:
	limactl shell k8s-dev -- bash -c "cd $(shell pwd) && bash hack/e2e/run-e2e.sh"

## Run e2e directly on the current Linux host (CI mode).
## Requires: Docker, kind, kubectl, helm, go — and sensor binary pre-built.
e2e-ci:
	bash hack/e2e/run-e2e.sh

## Record profile fixtures (testdata/profile-fixtures/v<N>/) from a live sensor
## run against representative workloads. Requires: limactl + 'limactl start k8s-dev'.
## Fixtures are recorded artifacts — never hand-edit them.
record-fixtures:
	limactl shell k8s-dev -- bash -c "cd $(shell pwd) && bash hack/record-profile-fixtures.sh"
