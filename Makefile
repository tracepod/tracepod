BPF_CLANG  := clang-18
BPF_TARGET ?= $(shell go env GOARCH)

.PHONY: all build build-harden build-tracepod clean generate test

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

clean:
	rm -rf bin/
