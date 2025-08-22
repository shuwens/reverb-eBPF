# Makefile for eBPF I/O Amplification Tracer

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

# Files
BPF_SRC := simple_io_tracer.bpf.c
BPF_OBJ := $(BUILD_DIR)/simple_io_tracer.bpf.o
BPF_SKEL := $(BUILD_DIR)/simple_io_tracer.skel.h

USER_SRC := simple_io_tracer.c
USER_OBJ := $(BUILD_DIR)/simple_io_tracer.o
TARGET := $(BUILD_DIR)/simple_io_tracer

# VMLinux header (for better BPF type definitions)
VMLINUX_H := $(BUILD_DIR)/vmlinux.h

.PHONY: all clean install test setup check help debug

all: $(TARGET)

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

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) | $(BUILD_DIR)
	@echo "Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "BPF program compiled successfully"

# Generate BPF skeleton
$(BPF_SKEL): $(BPF_OBJ) $(BPFTOOL_CMD) | $(BUILD_DIR)
	@echo "Generating BPF skeleton..."
	$(BPFTOOL_CMD) gen skeleton $< > $@
	@echo "BPF skeleton generated"

# Compile userspace program
$(USER_OBJ): $(USER_SRC) $(BPF_SKEL) | $(BUILD_DIR)
	@echo "Compiling userspace program..."
	$(CC) $(USER_CFLAGS) -c $< -o $@

# Link final executable
$(TARGET): $(USER_OBJ)
	@echo "Linking executable..."
	$(CC) $< -o $@ $(USER_LDFLAGS)
	@echo "Build complete! Executable: $(TARGET)"

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

# Install the tracer
install: $(TARGET)
	@echo "Installing tracer..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/io_tracer
	@echo "io_tracer installed to /usr/local/bin/"

# Test the tracer (requires root)
test: $(TARGET)
	@echo "Testing the eBPF I/O tracer..."
	@echo "This will trace for 5 seconds. Run some I/O operations in another terminal."
	sudo $(TARGET) -d 5 -v

# Full test suite
test-full: $(TARGET)
	@echo "Running comprehensive test suite..."
	sudo bash test_framework.sh

# Run with MinIO test
test-minio: $(TARGET)
	@echo "Starting MinIO trace (10 seconds)..."
	@echo "Make sure MinIO is running and perform some S3 operations"
	sudo $(TARGET) -d 10 -j -o minio_trace.json

# Run with Ceph test
test-ceph: $(TARGET)
	@echo "Starting Ceph trace (10 seconds)..."
	@echo "Make sure Ceph cluster is running and perform some operations"
	sudo $(TARGET) -d 10 -j -o ceph_trace.json

# Run with etcd test
test-etcd: $(TARGET)
	@echo "Starting etcd trace (10 seconds)..."
	@echo "Make sure etcd is running and perform some key-value operations"
	sudo $(TARGET) -d 10 -j -o etcd_trace.json

# Run with PostgreSQL test
test-postgres: $(TARGET)
	@echo "Starting PostgreSQL trace (10 seconds)..."
	@echo "Make sure PostgreSQL is running and perform some database operations"
	sudo $(TARGET) -d 10 -j -o postgres_trace.json

# Development target - build with debug info
debug: BPF_CFLAGS += -DDEBUG
debug: USER_CFLAGS += -DDEBUG -g3 -O0
debug: clean $(TARGET)
	@echo "Debug build complete with full symbols"

# Check BPF program can be loaded
check: $(BPF_OBJ)
	@echo "Verifying BPF program can be loaded..."
	sudo $(BPFTOOL) prog load $< /sys/fs/bpf/io_tracer_test type kprobe
	@echo "BPF program verification successful"
	sudo $(BPFTOOL) prog show pinned /sys/fs/bpf/io_tracer_test
	sudo rm -f /sys/fs/bpf/io_tracer_test
	@echo "BPF program check complete ✓"

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
	@if command -v bpftool >/dev/null 2>&1; then echo "✓ Available"; else echo "✗ Missing"; fi
	@echo -n "libbpf: "
	@if pkg-config --exists libbpf; then echo "✓ $(shell pkg-config --modversion libbpf)"; else echo "✗ Missing"; fi

# Create sample analysis
analyze-sample: $(TARGET)
	@echo "Creating sample trace data and analysis..."
	@mkdir -p samples
	@echo "Generating sample I/O activity..."
	@for i in {1..5}; do echo "sample data $$i" > /tmp/sample_$$i; cat /tmp/sample_$$i > /dev/null; done &
	sudo timeout 10s $(TARGET) -j -o samples/sample_trace.json || true
	@if [ -f samples/sample_trace.json ] && [ -s samples/sample_trace.json ]; then \
		echo "Sample trace created: samples/sample_trace.json"; \
		if [ -f analyze_io.py ]; then \
			echo "Running analysis..."; \
			python3 analyze_io.py samples/sample_trace.json -v -o samples/plots/ -e samples/results.csv; \
			echo "Analysis complete - check samples/ directory"; \
		else \
			echo "Analysis script not found - create analyze_io.py from the framework"; \
		fi; \
	else \
		echo "No sample data captured - try running some I/O intensive applications"; \
	fi
	@rm -f /tmp/sample_*

# Development helpers
lint: $(BPF_SRC) $(USER_SRC)
	@echo "Linting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format --dry-run --Werror $(BPF_SRC) $(USER_SRC); \
		echo "Code format check passed"; \
	else \
		echo "clang-format not available, skipping"; \
	fi

format: $(BPF_SRC) $(USER_SRC)
	@echo "Formatting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(BPF_SRC) $(USER_SRC); \
		echo "Code formatted"; \
	else \
		echo "clang-format not available, skipping"; \
	fi

# Show detailed help
help:
	@echo "eBPF I/O Amplification Tracer Build System"
	@echo "=========================================="
	@echo ""
	@echo "Primary Targets:"
	@echo "  all           - Build the tracer (default)"
	@echo "  clean         - Remove build files"
	@echo "  setup         - Install system dependencies"
	@echo "  install       - Install tracer to /usr/local/bin"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test          - Quick 5-second test"
	@echo "  test-full     - Run comprehensive test suite"
	@echo "  test-minio    - Test with MinIO"
	@echo "  test-ceph     - Test with Ceph"
	@echo "  test-etcd     - Test with etcd"
	@echo "  test-postgres - Test with PostgreSQL"
	@echo ""
	@echo "Verification Targets:"
	@echo "  check         - Verify BPF program can load"
	@echo "  check-system  - Check system requirements"
	@echo ""
	@echo "Development Targets:"
	@echo "  debug         - Build with debug symbols"
	@echo "  lint          - Check code formatting"
	@echo "  format        - Format code"
	@echo "  analyze-sample- Create sample trace and analysis"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make setup           # First time setup"
	@echo "  make all             # Build tracer"
	@echo "  make check-system    # Verify requirements"
	@echo "  sudo make test       # Quick test"
	@echo "  sudo make test-full  # Full test suite"
	@echo ""
	@echo "Manual Usage:"
	@echo "  sudo ./build/io_tracer -v -d 30                    # Real-time tracing"
	@echo "  sudo ./build/io_tracer -j -o trace.json -d 60      # JSON output"
	@echo "  python3 analyze_io.py trace.json -v -o plots/      # Analysis"
	@echo ""
	@echo "Requirements:"
	@echo "  - Linux kernel >= 5.4 with BTF support"
	@echo "  - Root privileges for eBPF loading"
	@echo "  - clang, libbpf, bpftool"
	@echo ""
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

# Alternative setup for older Ubuntu versions
setup-manual:
	@echo "Manual setup for older Ubuntu versions..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libelf-dev \
		zlib1g-dev \
		pkg-config \
		make \
		gcc \
		git \
		linux-headers-$(shell uname -r)
	@echo "Installing bpftool manually..."
	@if ! command -v bpftool >/dev/null 2>&1; then \
		cd /tmp && \
		git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
		cd bpftool/src && \
		make && \
		sudo make install; \
	fi
	$(MAKE) install-libbpf
	@echo "Manual setup complete"

# Show status
status: check-system
	@echo ""
	@echo "Build Status:"
	@echo "============="
	@if [ -f $(TARGET) ]; then \
		echo "✓ Tracer built: $(TARGET)"; \
		ls -la $(TARGET); \
	else \
		echo "✗ Tracer not built - run 'make all'"; \
	fi
	@if [ -f $(BPF_SKEL) ]; then \
		echo "✓ BPF skeleton generated"; \
	else \
		echo "✗ BPF skeleton not generated"; \
	fi

# Print build variables (for debugging)
vars:
	@echo "Build Variables:"
	@echo "==============="
	@echo "CLANG:      $(CLANG)"
	@echo "BPFTOOL:    $(BPFTOOL)"
	@echo "ARCH:       $(ARCH)"
	@echo "BUILD_DIR:  $(BUILD_DIR)"
	@echo "BPF_SRC:    $(BPF_SRC)"
	@echo "BPF_OBJ:    $(BPF_OBJ)"
	@echo "BPF_SKEL:   $(BPF_SKEL)"
	@echo "USER_SRC:   $(USER_SRC)"
	@echo "TARGET:     $(TARGET)"
	@echo "BPF_CFLAGS: $(BPF_CFLAGS)"
	@echo "USER_CFLAGS:$(USER_CFLAGS)"
	@echo "USER_LDFLAGS:$(USER_LDFLAGS)"

# Create distribution package
dist: clean
	@echo "Creating distribution package..."
	@mkdir -p dist
	@tar czf dist/ebpf-io-tracer-$(shell date +%Y%m%d).tar.gz \
		--exclude=dist \
		--exclude=build \
		--exclude='*.tar.gz' \
		--exclude='.git*' \
		.
	@echo "Distribution package created in dist/"


