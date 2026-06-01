.PHONY: all image extract clean fmt lint test check test-vm help

# beskar7-inspector build system.
#
# The shipped artifact is a static x86_64-musl binary used directly as the
# initramfs /init (see Dockerfile). `make image` builds it and extracts the two
# boot files an operator serves to iPXE: vmlinuz + initrd.img.

IMAGE_NAME ?= beskar7-inspector
VERSION    ?= dev
BUILD_DIR  ?= build
TARGET     := x86_64-unknown-linux-musl

all: check image

help:
	@echo "beskar7-inspector"
	@echo ""
	@echo "  make check     - fmt check + clippy (-D warnings) + tests"
	@echo "  make test      - cargo test (unit + contract)"
	@echo "  make image     - build vmlinuz + initrd.img into $(BUILD_DIR)/"
	@echo "  make test-vm   - boot the built image in QEMU (needs qemu-system-x86_64)"
	@echo "  make clean     - remove $(BUILD_DIR)/ and the docker image"
	@echo ""
	@echo "  IMAGE_NAME=$(IMAGE_NAME)  VERSION=$(VERSION)  BUILD_DIR=$(BUILD_DIR)"

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test --all-targets

check: fmt lint test

# Build the initramfs image and extract vmlinuz + initrd.img.
image: extract

extract:
	docker build -t $(IMAGE_NAME):$(VERSION) .
	@mkdir -p $(BUILD_DIR)
	docker create --name $(IMAGE_NAME)-extract $(IMAGE_NAME):$(VERSION)
	docker cp $(IMAGE_NAME)-extract:/vmlinuz $(BUILD_DIR)/vmlinuz
	docker cp $(IMAGE_NAME)-extract:/initrd.img $(BUILD_DIR)/initrd.img
	docker rm $(IMAGE_NAME)-extract
	@echo "built:" && ls -lh $(BUILD_DIR)/vmlinuz $(BUILD_DIR)/initrd.img

clean:
	rm -rf $(BUILD_DIR)
	docker rmi $(IMAGE_NAME):$(VERSION) 2>/dev/null || true

# Smoke-boot the image in QEMU. The beskar7.* params are normally rendered
# per-host by the controller's /boot endpoint; substitute reachable values here.
# Without a live callback the run stops in Phase 1 (no report acceptance), which
# is enough to confirm the binary boots as PID 1 and parses the cmdline.
BESKAR7_API       ?= https://beskar7.example.com:8082
BESKAR7_NAMESPACE ?= default
BESKAR7_HOST      ?= test-vm
test-vm: image
	@command -v qemu-system-x86_64 >/dev/null || { echo "install qemu-system-x86"; exit 1; }
	qemu-system-x86_64 \
		-m 2048 -nographic -serial mon:stdio \
		-kernel $(BUILD_DIR)/vmlinuz -initrd $(BUILD_DIR)/initrd.img \
		-append "console=ttyS0 beskar7.api=$(BESKAR7_API) beskar7.namespace=$(BESKAR7_NAMESPACE) beskar7.host=$(BESKAR7_HOST) beskar7.debug=true"

.DEFAULT_GOAL := help
