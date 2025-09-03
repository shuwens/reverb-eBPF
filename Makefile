# Makefile for eBPF I/O Amplification Tracers
# Supports both simple and multi-layer tracer compilation

# Tool versions and paths - Updated for Ubuntu compatibility
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= $(shell which bpftool 2>/dev/null || echo "/usr/lib/linux-tools/$(shell uname -r)/bpftool")
LIBBPF_DIR ?= /usr/include
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Check if bpftool exists, if not try alternatives
ifeq ($(shell test -x $(BPFTOOL) && echo yes),yes)
    BPFTOOL_CMD = $(BPFTOOL)
else
    BPFTOOL_CMD = $(shell find /usr -name bpftool 2>/dev/null | head -1)
endif

# If still no bpftool found, we'll build it
ifeq ($(BPFTOOL_CMD),)
    BPFTOOL_CMD = $(BUILD_DIR)/bpftool
    NEED_BPFTOOL = 1
endif

# Directories
BPF_DIR := bpf
BUILD_DIR := build
SRC_DIR := src

# Compiler flags - Updated for compatibility
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(BUILD_DIR) -I/usr/local/include
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member

USER_CFLAGS := -g -O2 -Wall -I$(BUILD_DIR)
USER_LDFLAGS := -lelf -lz

# Try to use pkg-config for libbpf if available
ifeq ($(shell pkg-config --exists libbpf && echo yes),yes)
    USER_CFLAGS += $(shell pkg-config --cflags libbpf)
    USER_LDFLAGS += $(shell pkg-config --libs libbpf)
else
    USER_CFLAGS += -I/usr/local/include
    USER_LDFLAGS += -L/usr/local/lib -lbpf
endif

# ========== SIMPLE TRACER FILES ==========
SIMPLE_BPF_SRC := simple_io_tracer.bpf.c
SIMPLE_BPF_OBJ := $(BUILD_DIR)/simple_io_tracer.bpf.o
SIMPLE_BPF_SKEL := $(BUILD_DIR)/simple_io_tracer.skel.h

SIMPLE_USER_SRC := simple_io_tracer.c
SIMPLE_USER_OBJ := $(BUILD_DIR)/simple_io_tracer.o
SIMPLE_TARGET := $(BUILD_DIR)/simple_io_tracer

# ========== MULTI-LAYER TRACER FILES ==========
MULTI_BPF_SRC := multilayer_io_tracer.bpf.c
MULTI_BPF_OBJ := $(BUILD_DIR)/multilayer_io_tracer.bpf.o
MULTI_BPF_SKEL := $(BUILD_DIR)/multilayer_io_tracer.skel.h

MULTI_USER_SRC := multilayer_io_tracer.c
MULTI_USER_OBJ := $(BUILD_DIR)/multilayer_io_tracer.o
MULTI_TARGET := $(BUILD_DIR)/multilayer_io_tracer

# VMLinux header (for better BPF type definitions)
VMLINUX_H := $(BUILD_DIR)/vmlinux.h

# All targets
ALL_TARGETS := $(SIMPLE_TARGET) $(MULTI_TARGET)

.PHONY: all simple multi clean install test setup check help debug

# Default: build both tracers
all: simple multi

# Build only simple tracer
simple: $(SIMPLE_TARGET)
	@echo "Simple I/O tracer built successfully!"

# Build only multi-layer tracer
multi: $(MULTI_TARGET)
	@echo "Multi-layer I/O tracer built successfully!"

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h for BPF type definitions
$(VMLINUX_H): | $(BUILD_DIR)
	@echo "Generating vmlinux.h..."
	@if [ -x "$(BPFTOOL_CMD)" ]; then \
		$(BPFTOOL_CMD) btf dump file /sys/kernel/btf/vmlinux format c > $@ || \
		(echo "Downloading pre-built vmlinux.h..." && \
		 curl -s https://raw.githubusercontent.com/libbpf/libbpf/master/src/btf.h > $@); \
	else \
		echo "Creating minimal vmlinux.h..."; \
		echo '#ifndef __VMLINUX_H__' > $@; \
		echo '#define __VMLINUX_H__' >> $@; \
		echo '#include <linux/types.h>' >> $@; \
		echo '#endif' >> $@; \
	fi

# Build bpftool if needed
$(BUILD_DIR)/bpftool: | $(BUILD_DIR)
ifdef NEED_BPFTOOL
	@echo "Building bpftool from source..."
	@cd $(BUILD_DIR) && \
	git clone --depth 1 https://github.com/libbpf/bpftool.git bpftool-src && \
	cd bpftool-src/src && \
	make && \
	cp bpftool ../bpftool
endif

# ========== SIMPLE TRACER BUILD RULES ==========

# Compile Simple BPF program
$(SIMPLE_BPF_OBJ): $(SIMPLE_BPF_SRC) $(VMLINUX_H) | $(BUILD_DIR)
	@echo "[SIMPLE] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[SIMPLE] BPF program compiled successfully"

# Generate Simple BPF skeleton
$(SIMPLE_BPF_SKEL): $(SIMPLE_BPF_OBJ) $(BPFTOOL_CMD) | $(BUILD_DIR)
	@echo "[SIMPLE] Generating BPF skeleton..."
	$(BPFTOOL_CMD) gen skeleton $< > $@
	@echo "[SIMPLE] BPF skeleton generated"

# Compile Simple userspace program
$(SIMPLE_USER_OBJ): $(SIMPLE_USER_SRC) $(SIMPLE_BPF_SKEL) | $(BUILD_DIR)
	@echo "[SIMPLE] Compiling userspace program..."
	$(CC) $(USER_CFLAGS) -c $< -o $@

# Link Simple executable
$(SIMPLE_TARGET): $(SIMPLE_USER_OBJ)
	@echo "[SIMPLE] Linking executable..."
	$(CC) $< -o $@ $(USER_LDFLAGS)
	@echo "[SIMPLE] Build complete! Executable: $(SIMPLE_TARGET)"

# ========== MULTI-LAYER TRACER BUILD RULES ==========

# Compile Multi-layer BPF program
$(MULTI_BPF_OBJ): $(MULTI_BPF_SRC) $(VMLINUX_H) | $(BUILD_DIR)
	@echo "[MULTI] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[MULTI] BPF program compiled successfully"

# Generate Multi-layer BPF skeleton
$(MULTI_BPF_SKEL): $(MULTI_BPF_OBJ) $(BPFTOOL_CMD) | $(BUILD_DIR)
	@echo "[MULTI] Generating BPF skeleton..."
	$(BPFTOOL_CMD) gen skeleton $< > $@
	@echo "[MULTI] BPF skeleton generated"

# Compile Multi-layer userspace program
$(MULTI_USER_OBJ): $(MULTI_USER_SRC) $(MULTI_BPF_SKEL) | $(BUILD_DIR)
	@echo "[MULTI] Compiling userspace program..."
	$(CC) $(USER_CFLAGS) -c $< -o $@

# Link Multi-layer executable
$(MULTI_TARGET): $(MULTI_USER_OBJ)
	@echo "[MULTI] Linking executable..."
	$(CC) $< -o $@ $(USER_LDFLAGS)
	@echo "[MULTI] Build complete! Executable: $(MULTI_TARGET)"

# Install system dependencies (Ubuntu/Debian)
setup:
	@echo "Installing dependencies..."
	sudo apt-get update
	@echo "Installing basic build dependencies..."
	sudo apt-get install -y \
		clang \
		llvm \
		libelf-dev \
		zlib1g-dev \
		pkg-config \
		make \
		gcc \
		linux-headers-$(shell uname -r)
	@echo "Installing BPF tools..."
	sudo apt-get install -y linux-tools-common linux-tools-$(shell uname -r) || \
		sudo apt-get install -y linux-tools-generic
	@echo "Checking for libbpf..."
	@if ! pkg-config --exists libbpf; then \
		echo "Installing libbpf from source..."; \
		$(MAKE) install-libbpf; \
	else \
		echo "libbpf already available"; \
		sudo apt-get install -y libbpf-dev || true; \
	fi
	@echo "Installing Python dependencies for analysis..."
	sudo apt-get install -y python3-pip python3-dev
	pip3 install --user pandas matplotlib seaborn numpy
	@echo "Dependencies installed successfully!"
	@echo "Verifying installation..."
	@$(MAKE) check-system

# Clean build files
clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# Install the tracers
install: $(ALL_TARGETS)
	@echo "Installing tracers..."
	sudo cp $(SIMPLE_TARGET) /usr/local/bin/simple_io_tracer
	sudo cp $(MULTI_TARGET) /usr/local/bin/multilayer_io_tracer
	sudo chmod +x /usr/local/bin/simple_io_tracer
	sudo chmod +x /usr/local/bin/multilayer_io_tracer
	@echo "Tracers installed to /usr/local/bin/"
	@echo "  - simple_io_tracer: Basic I/O amplification tracking"
	@echo "  - multilayer_io_tracer: Complete storage stack analysis"

# ========== TEST TARGETS ==========

# Test simple tracer (requires root)
test-simple: $(SIMPLE_TARGET)
	@echo "Testing simple I/O tracer..."
	@echo "This will trace for 5 seconds. Run some I/O operations in another terminal."
	sudo $(SIMPLE_TARGET) -d 5 -v

# Test multi-layer tracer (requires root)
test-multi: $(MULTI_TARGET)
	@echo "Testing multi-layer I/O tracer..."
	@echo "This will trace all storage layers for 5 seconds."
	sudo $(MULTI_TARGET) -d 5 -v

# Test both tracers
test: test-simple test-multi

# Run multi-layer with correlation mode
test-correlate: $(MULTI_TARGET)
	@echo "Testing multi-layer tracer with request correlation..."
	sudo $(MULTI_TARGET) -c -v -d 10

# Test 100-byte write amplification
test-100byte: $(MULTI_TARGET)
	@echo "Testing 100-byte write amplification..."
	@echo "Creating test program..."
	@echo '#include <stdio.h>\n#include <fcntl.h>\n#include <unistd.h>\nint main() { int fd = open("test.dat", O_CREAT|O_WRONLY|O_DIRECT, 0644); char buf[100]; write(fd, buf, 100); fsync(fd); close(fd); unlink("test.dat"); return 0; }' | gcc -x c -o /tmp/test_100byte -
	@echo "Starting multi-layer tracer..."
	sudo $(MULTI_TARGET) -c -q -d 3 &
	@sleep 1
	@echo "Writing 100 bytes..."
	@/tmp/test_100byte
	@wait
	@rm -f /tmp/test_100byte

# ========== STORAGE SYSTEM SPECIFIC TESTS ==========

# Run with MinIO test
test-minio-simple: $(SIMPLE_TARGET)
	@echo "Starting MinIO trace with simple tracer (10 seconds)..."
	@echo "Make sure MinIO is running and perform some S3 operations"
	sudo $(SIMPLE_TARGET) -d 10 -j -o minio_simple_trace.json

test-minio-multi: $(MULTI_TARGET)
	@echo "Starting MinIO trace with multi-layer tracer (10 seconds)..."
	@echo "Make sure MinIO is running and perform some S3 operations"
	sudo $(MULTI_TARGET) -s minio -c -d 10 -j -o minio_multi_trace.json

# Run with Ceph test
test-ceph-simple: $(SIMPLE_TARGET)
	@echo "Starting Ceph trace with simple tracer (10 seconds)..."
	sudo $(SIMPLE_TARGET) -d 10 -j -o ceph_simple_trace.json

test-ceph-multi: $(MULTI_TARGET)
	@echo "Starting Ceph trace with multi-layer tracer (10 seconds)..."
	sudo $(MULTI_TARGET) -s ceph -c -d 10 -j -o ceph_multi_trace.json

# Run with PostgreSQL test
test-postgres-simple: $(SIMPLE_TARGET)
	@echo "Starting PostgreSQL trace with simple tracer (10 seconds)..."
	sudo $(SIMPLE_TARGET) -d 10 -j -o postgres_simple_trace.json

test-postgres-multi: $(MULTI_TARGET)
	@echo "Starting PostgreSQL trace with multi-layer tracer (10 seconds)..."
	sudo $(MULTI_TARGET) -s postgres -c -d 10 -j -o postgres_multi_trace.json

# ========== DEVELOPMENT TARGETS ==========

# Development target - build with debug info
debug: BPF_CFLAGS += -DDEBUG
debug: USER_CFLAGS += -DDEBUG -g3 -O0
debug: clean $(ALL_TARGETS)
	@echo "Debug build complete with full symbols"

# Check BPF programs can be loaded
check-simple: $(SIMPLE_BPF_OBJ)
	@echo "Verifying simple BPF program can be loaded..."
	sudo $(BPFTOOL_CMD) prog load $< /sys/fs/bpf/simple_io_test type kprobe
	@echo "Simple BPF program verification successful"
	sudo $(BPFTOOL_CMD) prog show pinned /sys/fs/bpf/simple_io_test
	sudo rm -f /sys/fs/bpf/simple_io_test

check-multi: $(MULTI_BPF_OBJ)
	@echo "Verifying multi-layer BPF program can be loaded..."
	sudo $(BPFTOOL_CMD) prog load $< /sys/fs/bpf/multi_io_test type kprobe
	@echo "Multi-layer BPF program verification successful"
	sudo $(BPFTOOL_CMD) prog show pinned /sys/fs/bpf/multi_io_test
	sudo rm -f /sys/fs/bpf/multi_io_test

check: check-simple check-multi
	@echo "All BPF program checks complete ✓"

# Check system requirements
check-system:
	@echo "Checking system requirements..."
	@echo "Kernel version: $(shell uname -r)"
	@echo "Architecture: $(ARCH)"
	@echo -n "BTF support: "
	@if [ -f /sys/kernel/btf/vmlinux ]; then echo "✓ Available"; else echo "✗ Missing"; fi
	@echo -n "BPF filesystem: "
	@if [ -d /sys/fs/bpf ]; then echo "✓ Available"; else echo "✗ Missing"; fi
	@echo -n "clang: "
	@if command -v clang >/dev/null 2>&1; then echo "✓ $(shell clang --version | head -n1)"; else echo "✗ Missing"; fi
	@echo -n "bpftool: "
	@if command -v $(BPFTOOL_CMD) >/dev/null 2>&1; then echo "✓ Available"; else echo "✗ Missing"; fi
	@echo -n "libbpf: "
	@if pkg-config --exists libbpf; then echo "✓ $(shell pkg-config --modversion libbpf)"; else echo "✗ Missing"; fi

# Compare simple vs multi-layer output
compare: $(ALL_TARGETS)
	@echo "Running comparison test..."
	@echo "Starting both tracers for 10 seconds..."
	@mkdir -p comparison
	sudo $(SIMPLE_TARGET) -j -o comparison/simple.json -d 10 &
	sudo $(MULTI_TARGET) -j -o comparison/multi.json -d 10 &
	@wait
	@echo "Traces saved to comparison/ directory"
	@echo "You can now analyze the differences between simple and multi-layer tracing"

# Development helpers
lint: $(SIMPLE_BPF_SRC) $(SIMPLE_USER_SRC) $(MULTI_BPF_SRC) $(MULTI_USER_SRC)
	@echo "Linting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format --dry-run --Werror $^; \
		echo "Code format check passed"; \
	else \
		echo "clang-format not available, skipping"; \
	fi

format: $(SIMPLE_BPF_SRC) $(SIMPLE_USER_SRC) $(MULTI_BPF_SRC) $(MULTI_USER_SRC)
	@echo "Formatting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $^; \
		echo "Code formatted"; \
	else \
		echo "clang-format not available, skipping"; \
	fi

# Show detailed help
help:
	@echo "eBPF I/O Amplification Tracer Build System"
	@echo "=========================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build both simple and multi-layer tracers (default)"
	@echo "  simple        - Build only the simple I/O tracer"
	@echo "  multi         - Build only the multi-layer tracer"
	@echo "  clean         - Remove all build files"
	@echo "  setup         - Install system dependencies"
	@echo "  install       - Install both tracers to /usr/local/bin"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test          - Quick test of both tracers"
	@echo "  test-simple   - Test simple tracer (5 seconds)"
	@echo "  test-multi    - Test multi-layer tracer (5 seconds)"
	@echo "  test-correlate- Test request correlation in multi-layer tracer"
	@echo "  test-100byte  - Test 100-byte write amplification"
	@echo "  compare       - Run both tracers simultaneously for comparison"
	@echo ""
	@echo "Storage System Tests:"
	@echo "  test-minio-simple    - Test MinIO with simple tracer"
	@echo "  test-minio-multi     - Test MinIO with multi-layer tracer"
	@echo "  test-ceph-simple     - Test Ceph with simple tracer"
	@echo "  test-ceph-multi      - Test Ceph with multi-layer tracer"
	@echo "  test-postgres-simple - Test PostgreSQL with simple tracer"
	@echo "  test-postgres-multi  - Test PostgreSQL with multi-layer tracer"
	@echo ""
	@echo "Verification Targets:"
	@echo "  check         - Verify both BPF programs can load"
	@echo "  check-simple  - Verify simple BPF program"
	@echo "  check-multi   - Verify multi-layer BPF program"
	@echo "  check-system  - Check system requirements"
	@echo ""
	@echo "Development Targets:"
	@echo "  debug         - Build with debug symbols"
	@echo "  lint          - Check code formatting"
	@echo "  format        - Format code"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make setup                # First time setup"
	@echo "  make all                  # Build both tracers"
	@echo "  make simple               # Build only simple tracer"
	@echo "  make multi                # Build only multi-layer tracer"
	@echo "  sudo make test-100byte    # Test write amplification"
	@echo "  sudo make test-correlate  # Test with request correlation"
	@echo "  sudo make compare         # Compare both tracers"
	@echo ""
	@echo "Manual Usage:"
	@echo "  Simple tracer:"
	@echo "    sudo ./build/simple_io_tracer -v -d 30"
	@echo "    sudo ./build/simple_io_tracer -j -o trace.json -d 60"
	@echo ""
	@echo "  Multi-layer tracer:"
	@echo "    sudo ./build/multilayer_io_tracer -v -c -d 30"
	@echo "    sudo ./build/multilayer_io_tracer -s minio -c -j -o trace.json"
	@echo ""
	@echo "Requirements:"
	@echo "  - Linux kernel >= 5.4 with BTF support"
	@echo "  - Root privileges for eBPF loading"
	@echo "  - clang, libbpf, bpftool"

# Install libbpf from source if not available
install-libbpf:
	@echo "Building libbpf from source..."
	@cd /tmp && \
	git clone https://github.com/libbpf/libbpf.git || (cd libbpf && git pull) && \
	cd libbpf/src && \
	make && \
	sudo make install && \
	sudo ldconfig
	@echo "libbpf installed from source"

# Show build status
status: check-system
	@echo ""
	@echo "Build Status:"
	@echo "============="
	@if [ -f $(SIMPLE_TARGET) ]; then \
		echo "✓ Simple tracer built: $(SIMPLE_TARGET)"; \
		ls -lh $(SIMPLE_TARGET) | awk '{print "  Size:", $$5}'; \
	else \
		echo "✗ Simple tracer not built - run 'make simple'"; \
	fi
	@if [ -f $(MULTI_TARGET) ]; then \
		echo "✓ Multi-layer tracer built: $(MULTI_TARGET)"; \
		ls -lh $(MULTI_TARGET) | awk '{print "  Size:", $$5}'; \
	else \
		echo "✗ Multi-layer tracer not built - run 'make multi'"; \
	fi
	@echo ""
	@if [ -f $(SIMPLE_BPF_SKEL) ]; then \
		echo "✓ Simple BPF skeleton generated"; \
	else \
		echo "✗ Simple BPF skeleton not generated"; \
	fi
	@if [ -f $(MULTI_BPF_SKEL) ]; then \
		echo "✓ Multi-layer BPF skeleton generated"; \
	else \
		echo "✗ Multi-layer BPF skeleton not generated"; \
	fi

# Print build variables (for debugging)
vars:
	@echo "Build Variables:"
	@echo "==============="
	@echo "CLANG:           $(CLANG)"
	@echo "BPFTOOL:         $(BPFTOOL_CMD)"
	@echo "ARCH:            $(ARCH)"
	@echo "BUILD_DIR:       $(BUILD_DIR)"
	@echo ""
	@echo "Simple Tracer:"
	@echo "  BPF_SRC:       $(SIMPLE_BPF_SRC)"
	@echo "  BPF_OBJ:       $(SIMPLE_BPF_OBJ)"
	@echo "  BPF_SKEL:      $(SIMPLE_BPF_SKEL)"
	@echo "  USER_SRC:      $(SIMPLE_USER_SRC)"
	@echo "  TARGET:        $(SIMPLE_TARGET)"
	@echo ""
	@echo "Multi-layer Tracer:"
	@echo "  BPF_SRC:       $(MULTI_BPF_SRC)"
	@echo "  BPF_OBJ:       $(MULTI_BPF_OBJ)"
	@echo "  BPF_SKEL:      $(MULTI_BPF_SKEL)"
	@echo "  USER_SRC:      $(MULTI_USER_SRC)"
	@echo "  TARGET:        $(MULTI_TARGET)"
	@echo ""
	@echo "Flags:"
	@echo "  BPF_CFLAGS:    $(BPF_CFLAGS)"
	@echo "  USER_CFLAGS:   $(USER_CFLAGS)"
	@echo "  USER_LDFLAGS:  $(USER_LDFLAGS)"

# Create distribution package
dist: clean
	@echo "Creating distribution package..."
	@mkdir -p dist
	@tar czf dist/ebpf-io-tracers-$(shell date +%Y%m%d).tar.gz \
		--exclude=dist \
		--exclude=build \
		--exclude='*.tar.gz' \
		--exclude='.git*' \
		$(SIMPLE_BPF_SRC) $(SIMPLE_USER_SRC) \
		$(MULTI_BPF_SRC) $(MULTI_USER_SRC) \
		Makefile README.md
	@echo "Distribution package created in dist/"

.PHONY: all simple multi clean install test setup check help debug \
        test-simple test-multi test-correlate test-100byte \
        test-minio-simple test-minio-multi test-ceph-simple test-ceph-multi \
        test-postgres-simple test-postgres-multi \
        check-simple check-multi check-system \
        compare lint format status vars dist install-libbpf

