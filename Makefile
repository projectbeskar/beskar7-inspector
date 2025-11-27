.PHONY: all build clean deploy test test-vm help

# Configuration
IMAGE_NAME := beskar7-inspector
VERSION := 1.0
BUILD_DIR := build
BOOT_SERVER ?= boot.example.com
BOOT_PATH ?= /var/www/boot/inspector/

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

all: build

help:
	@echo "Beskar7-Inspector Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build        - Build inspection image (vmlinuz + initrd.img)"
	@echo "  clean        - Clean build artifacts"
	@echo "  deploy       - Deploy to boot server"
	@echo "  test         - Run tests"
	@echo "  test-vm      - Test in QEMU"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  BOOT_SERVER  - Boot server hostname (default: boot.example.com)"
	@echo "  BOOT_PATH    - Path on boot server (default: /var/www/boot/inspector/)"

build:
	@echo "$(GREEN)Building Beskar7-Inspector image...$(NC)"
	@mkdir -p $(BUILD_DIR)
	docker build -t $(IMAGE_NAME):$(VERSION) .
	@echo "$(GREEN)Extracting kernel and initrd...$(NC)"
	docker create --name $(IMAGE_NAME)-tmp $(IMAGE_NAME):$(VERSION)
	docker cp $(IMAGE_NAME)-tmp:/vmlinuz $(BUILD_DIR)/vmlinuz
	docker cp $(IMAGE_NAME)-tmp:/initrd.img $(BUILD_DIR)/initrd.img
	docker rm $(IMAGE_NAME)-tmp
	@echo "$(GREEN)Build complete!$(NC)"
	@echo "Output: $(BUILD_DIR)/vmlinuz, $(BUILD_DIR)/initrd.img"
	@ls -lh $(BUILD_DIR)/

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf $(BUILD_DIR)
	docker rmi $(IMAGE_NAME):$(VERSION) 2>/dev/null || true
	@echo "$(GREEN)Clean complete$(NC)"

deploy: build
	@echo "$(GREEN)Deploying to $(BOOT_SERVER):$(BOOT_PATH)$(NC)"
	@if [ -z "$(BOOT_SERVER)" ]; then \
		echo "$(RED)ERROR: BOOT_SERVER not set$(NC)"; \
		exit 1; \
	fi
	scp $(BUILD_DIR)/vmlinuz $(BOOT_SERVER):$(BOOT_PATH)/
	scp $(BUILD_DIR)/initrd.img $(BOOT_SERVER):$(BOOT_PATH)/
	@echo "$(GREEN)Deployment complete$(NC)"

test:
	@echo "$(GREEN)Running tests...$(NC)"
	@if [ -d tests ]; then \
		for test in tests/test-*.sh; do \
			echo "Running $$test..."; \
			bash $$test || exit 1; \
		done; \
	fi
	@echo "$(GREEN)All tests passed$(NC)"

test-vm: build
	@echo "$(GREEN)Testing in QEMU...$(NC)"
	@which qemu-system-x86_64 > /dev/null 2>&1 || { \
		echo "$(RED)ERROR: QEMU not installed. Install with: apt install qemu-system-x86$(NC)"; \
		exit 1; \
	}
	qemu-system-x86_64 \
		-m 2048 \
		-kernel $(BUILD_DIR)/vmlinuz \
		-initrd $(BUILD_DIR)/initrd.img \
		-append "console=ttyS0 beskar7.api=http://localhost:8082 beskar7.namespace=default beskar7.host=test-vm beskar7.debug=true" \
		-nographic \
		-serial mon:stdio

# Development helpers
dev-shell:
	@echo "$(GREEN)Starting development shell...$(NC)"
	docker run -it --rm \
		-v $(PWD)/scripts:/scripts \
		alpine:3.19 /bin/sh

validate-scripts:
	@echo "$(GREEN)Validating scripts...$(NC)"
	@for script in scripts/*.sh; do \
		echo "Checking $$script..."; \
		bash -n $$script || exit 1; \
	done
	@echo "$(GREEN)All scripts valid$(NC)"

.DEFAULT_GOAL := help

