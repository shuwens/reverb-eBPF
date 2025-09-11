# Makefile for eBPF I/O Amplification Tracers with MinIO Support
# Supports both simple and multi-layer tracer compilation

# Tool versions and paths - Updated for Ubuntu compatibility
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= $(shell which bpftool 2>/dev/null || echo "/usr/lib/linux-tools/$(shell uname -r)/bpftool")
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

# Find libbpf headers - check multiple locations
LIBBPF_INCLUDE := $(shell \
    if [ -d "/usr/include/bpf" ]; then echo "/usr/include"; \
    elif [ -d "/usr/local/include/bpf" ]; then echo "/usr/local/include"; \
    elif [ -d "/usr/include/libbpf" ]; then echo "/usr/include/libbpf"; \
    elif pkg-config --exists libbpf 2>/dev/null; then pkg-config --cflags-only-I libbpf | sed 's/-I//'; \
    else echo "/usr/include"; fi)

# Compiler flags - Updated for compatibility
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(BUILD_DIR) -I$(LIBBPF_INCLUDE) -I/usr/include -I/usr/local/include
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-address-of-packed-member
BPF_CFLAGS += -D__BPF_TRACING__

USER_CFLAGS := -g -O2 -Wall -I$(BUILD_DIR)
USER_LDFLAGS := -lelf -lz

# Try to use pkg-config for libbpf if available
ifeq ($(shell pkg-config --exists libbpf && echo yes),yes)
    USER_CFLAGS += $(shell pkg-config --cflags libbpf)
    USER_LDFLAGS += $(shell pkg-config --libs libbpf)
else
    USER_CFLAGS += -I/usr/local/include -I/usr/include
    USER_LDFLAGS += -L/usr/local/lib -L/usr/lib -lbpf
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

# BPF headers for standalone compilation
BPF_HEADERS := $(BUILD_DIR)/bpf_headers_installed

# All targets
ALL_TARGETS := $(SIMPLE_TARGET) $(MULTI_TARGET)

.PHONY: all simple multi clean install test setup check help debug deps

# Default: build both tracers
all: deps simple multi

# Build only simple tracer
simple: deps $(SIMPLE_TARGET)
	@echo "Simple I/O tracer built successfully!"

# Build only multi-layer tracer
multi: deps $(MULTI_TARGET)
	@echo "Multi-layer I/O tracer built successfully!"

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Install BPF headers if missing
$(BPF_HEADERS): | $(BUILD_DIR)
	@echo "Checking BPF headers..."
	@if [ ! -f "$(LIBBPF_INCLUDE)/bpf/bpf_core_read.h" ]; then \
		echo "Installing BPF headers locally..."; \
		mkdir -p $(BUILD_DIR)/bpf; \
		if [ -d "/usr/src/linux-headers-$(shell uname -r)/tools/lib/bpf" ]; then \
			cp -r /usr/src/linux-headers-$(shell uname -r)/tools/lib/bpf/*.h $(BUILD_DIR)/bpf/ 2>/dev/null || true; \
		fi; \
		if [ ! -f "$(BUILD_DIR)/bpf/bpf_core_read.h" ]; then \
			echo "Downloading BPF headers from libbpf..."; \
			curl -sL https://raw.githubusercontent.com/libbpf/libbpf/master/src/bpf_core_read.h -o $(BUILD_DIR)/bpf/bpf_core_read.h; \
			curl -sL https://raw.githubusercontent.com/libbpf/libbpf/master/src/bpf_helpers.h -o $(BUILD_DIR)/bpf/bpf_helpers.h; \
			curl -sL https://raw.githubusercontent.com/libbpf/libbpf/master/src/bpf_tracing.h -o $(BUILD_DIR)/bpf/bpf_tracing.h; \
			curl -sL https://raw.githubusercontent.com/libbpf/libbpf/master/src/bpf_helper_defs.h -o $(BUILD_DIR)/bpf/bpf_helper_defs.h; \
		fi; \
		touch $(BPF_HEADERS); \
	else \
		echo "BPF headers found at $(LIBBPF_INCLUDE)/bpf"; \
		touch $(BPF_HEADERS); \
	fi

# Generate vmlinux.h for BPF type definitions
$(VMLINUX_H): | $(BUILD_DIR)
	@echo "Generating vmlinux.h..."
	@if [ -x "$(BPFTOOL_CMD)" ] && [ -f "/sys/kernel/btf/vmlinux" ]; then \
		$(BPFTOOL_CMD) btf dump file /sys/kernel/btf/vmlinux format c > $@ 2>/dev/null || \
		(echo "Using minimal vmlinux.h..."; \
		 echo '#ifndef __VMLINUX_H__' > $@; \
		 echo '#define __VMLINUX_H__' >> $@; \
		 echo '#include <linux/types.h>' >> $@; \
		 echo 'typedef __u32 u32;' >> $@; \
		 echo 'typedef __u64 u64;' >> $@; \
		 echo 'typedef __u8 u8;' >> $@; \
		 echo 'typedef __s32 s32;' >> $@; \
		 echo 'typedef __u16 u16;' >> $@; \
		 echo 'typedef unsigned long long sector_t;' >> $@; \
		 echo 'typedef unsigned int dev_t;' >> $@; \
		 echo 'typedef long long loff_t;' >> $@; \
		 echo 'struct pt_regs {};' >> $@; \
		 echo 'struct file {};' >> $@; \
		 echo 'struct inode { unsigned long i_ino; };' >> $@; \
		 echo 'struct bio { struct { unsigned int bi_size; sector_t bi_sector; } bi_iter; struct block_device *bi_bdev; };' >> $@; \
		 echo 'struct block_device { dev_t bd_dev; };' >> $@; \
		 echo 'struct trace_event_raw_sys_enter { unsigned long args[6]; };' >> $@; \
		 echo '#define PT_REGS_PARM1(x) ((x)->di)' >> $@; \
		 echo '#define PT_REGS_PARM2(x) ((x)->si)' >> $@; \
		 echo '#define PT_REGS_PARM3(x) ((x)->dx)' >> $@; \
		 echo '#endif' >> $@); \
	else \
		echo "Creating minimal vmlinux.h (no BTF support)..."; \
		echo '#ifndef __VMLINUX_H__' > $@; \
		echo '#define __VMLINUX_H__' >> $@; \
		echo '#include <linux/types.h>' >> $@; \
		echo 'typedef __u32 u32;' >> $@; \
		echo 'typedef __u64 u64;' >> $@; \
		echo 'typedef __u8 u8;' >> $@; \
		echo 'typedef __s32 s32;' >> $@; \
		echo 'typedef __u16 u16;' >> $@; \
		echo 'typedef unsigned long long sector_t;' >> $@; \
		echo 'typedef unsigned int dev_t;' >> $@; \
		echo 'typedef long long loff_t;' >> $@; \
		echo 'struct pt_regs {};' >> $@; \
		echo 'struct file {};' >> $@; \
		echo 'struct inode { unsigned long i_ino; };' >> $@; \
		echo 'struct bio { struct { unsigned int bi_size; sector_t bi_sector; } bi_iter; struct block_device *bi_bdev; };' >> $@; \
		echo 'struct block_device { dev_t bd_dev; };' >> $@; \
		echo 'struct trace_event_raw_sys_enter { unsigned long args[6]; };' >> $@; \
		echo '#define PT_REGS_PARM1(x) ((x)->di)' >> $@; \
		echo '#define PT_REGS_PARM2(x) ((x)->si)' >> $@; \
		echo '#define PT_REGS_PARM3(x) ((x)->dx)' >> $@; \
		echo '#endif' >> $@; \
	fi

# Build dependencies
deps: $(VMLINUX_H) $(BPF_HEADERS)

# ========== SIMPLE TRACER BUILD RULES ==========

# Compile Simple BPF program
$(SIMPLE_BPF_OBJ): $(SIMPLE_BPF_SRC) $(VMLINUX_H) $(BPF_HEADERS) | $(BUILD_DIR)
	@echo "[SIMPLE] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[SIMPLE] BPF program compiled successfully"

# Generate Simple BPF skeleton
$(SIMPLE_BPF_SKEL): $(SIMPLE_BPF_OBJ) | $(BUILD_DIR)
	@echo "[SIMPLE] Generating BPF skeleton..."
	@if [ -x "$(BPFTOOL_CMD)" ]; then \
		$(BPFTOOL_CMD) gen skeleton $< > $@; \
	else \
		echo "Error: bpftool not found. Please install linux-tools-common"; \
		exit 1; \
	fi
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
$(MULTI_BPF_OBJ): $(MULTI_BPF_SRC) $(VMLINUX_H) $(BPF_HEADERS) | $(BUILD_DIR)
	@echo "[MULTI] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[MULTI] BPF program compiled successfully"

# Generate Multi-layer BPF skeleton
$(MULTI_BPF_SKEL): $(MULTI_BPF_OBJ) | $(BUILD_DIR)
	@echo "[MULTI] Generating BPF skeleton..."
	@if [ -x "$(BPFTOOL_CMD)" ]; then \
		$(BPFTOOL_CMD) gen skeleton $< > $@; \
	else \
		echo "Error: bpftool not found. Please install linux-tools-common"; \
		exit 1; \
	fi
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
		curl \
		linux-headers-$(shell uname -r)
	@echo "Installing BPF tools..."
	sudo apt-get install -y linux-tools-common linux-tools-$(shell uname -r) || \
		sudo apt-get install -y linux-tools-generic
	@echo "Installing libbpf..."
	sudo apt-get install -y libbpf-dev || \
		(echo "libbpf-dev not available, will use downloaded headers")
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
	sudo cp $(SIMPLE_TARGET) /usr/local/bin/simple_io_tracer 2>/dev/null || true
	sudo cp $(MULTI_TARGET) /usr/local/bin/multilayer_io_tracer
	sudo chmod +x /usr/local/bin/multilayer_io_tracer
	@if [ -f $(SIMPLE_TARGET) ]; then \
		sudo chmod +x /usr/local/bin/simple_io_tracer; \
		echo "  - simple_io_tracer: Basic I/O amplification tracking"; \
	fi
	@echo "  - multilayer_io_tracer: Complete storage stack analysis with MinIO support"

# ========== TEST TARGETS ==========

# Test multi-layer tracer (requires root)
test-multi: $(MULTI_TARGET)
	@echo "Testing multi-layer I/O tracer..."
	@echo "This will trace all storage layers for 5 seconds."
	sudo $(MULTI_TARGET) -d 5 -v

# Test MinIO auto-detection
test-minio-auto: $(MULTI_TARGET)
	@echo "Testing MinIO auto-detection..."
	@echo "Make sure MinIO is running!"
	sudo $(MULTI_TARGET) -A -v -d 10

# Test MinIO with specific PID
test-minio-pid: $(MULTI_TARGET)
	@echo "Testing MinIO with specific PID..."
	@if pgrep -x minio > /dev/null; then \
		sudo $(MULTI_TARGET) -p $$(pgrep -x minio | head -1) -c -E -T -v -d 10; \
	else \
		echo "MinIO is not running. Please start MinIO first."; \
	fi

# Test MinIO with all features
test-minio-full: $(MULTI_TARGET)
	@echo "Testing MinIO with full features..."
	sudo $(MULTI_TARGET) -M -E -T -c -v -d 15 -o minio_full_trace.log

# Check system requirements
check-system:
	@echo "Checking system requirements..."
	@echo "Kernel version: $(shell uname -r)"
	@echo "Architecture: $(ARCH)"
	@echo -n "BTF support: "
	@if [ -f /sys/kernel/btf/vmlinux ]; then echo "✓ Available"; else echo "✗ Missing (will use fallback)"; fi
	@echo -n "BPF filesystem: "
	@if [ -d /sys/fs/bpf ]; then echo "✓ Available"; else echo "✗ Missing"; fi
	@echo -n "clang: "
	@if command -v clang >/dev/null 2>&1; then echo "✓ $(shell clang --version | head -n1)"; else echo "✗ Missing"; fi
	@echo -n "bpftool: "
	@if [ -x "$(BPFTOOL_CMD)" ]; then echo "✓ Available at $(BPFTOOL_CMD)"; else echo "✗ Missing"; fi
	@echo -n "libbpf: "
	@if pkg-config --exists libbpf 2>/dev/null; then echo "✓ $(shell pkg-config --modversion libbpf)"; else echo "✗ Using downloaded headers"; fi
	@echo -n "BPF headers: "
	@if [ -f "$(LIBBPF_INCLUDE)/bpf/bpf_core_read.h" ] || [ -f "$(BUILD_DIR)/bpf/bpf_core_read.h" ]; then echo "✓ Available"; else echo "✗ Will be downloaded"; fi

# Show detailed help
help:
	@echo "eBPF I/O Amplification Tracer with MinIO Support"
	@echo "================================================"
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build both tracers (default)"
	@echo "  multi         - Build only the multi-layer tracer"
	@echo "  clean         - Remove all build files"
	@echo "  setup         - Install system dependencies"
	@echo "  install       - Install tracers to /usr/local/bin"
	@echo ""
	@echo "MinIO Testing:"
	@echo "  test-minio-auto  - Test with MinIO auto-detection"
	@echo "  test-minio-pid   - Test with specific MinIO PID"
	@echo "  test-minio-full  - Test all MinIO features"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make setup                # First time setup"
	@echo "  make multi                # Build multi-layer tracer"
	@echo "  sudo make test-minio-auto # Test MinIO tracing"
	@echo ""
	@echo "Manual MinIO Usage:"
	@echo "  # Auto-detect all MinIO processes:"
	@echo "  sudo ./build/multilayer_io_tracer -A -v"
	@echo ""
	@echo "  # Trace specific MinIO PID:"
	@echo "  sudo ./build/multilayer_io_tracer -p \$$(pgrep minio) -c -E -T"
	@echo ""
	@echo "  # Full MinIO analysis:"
	@echo "  sudo ./build/multilayer_io_tracer -M -E -T -c -o analysis.log"

.PHONY: all simple multi clean install test setup check help debug deps \
        test-multi test-minio-auto test-minio-pid test-minio-full check-system


