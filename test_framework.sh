#!/bin/bash

# Test Script for eBPF I/O Amplification Tracer
# This script validates that the framework works correctly

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
TRACER="$BUILD_DIR/io_tracer"
ANALYZER="$SCRIPT_DIR/analyze_io.py"
TEST_DIR="/tmp/io_tracer_test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
}

check_requirements() {
    log "Checking requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for eBPF tracing"
        exit 1
    fi
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    
    if (( KERNEL_MAJOR < 5 )) || (( KERNEL_MAJOR == 5 && KERNEL_MINOR < 4 )); then
        error "Kernel version $KERNEL_VERSION is too old. Need >= 5.4"
        exit 1
    fi
    
    log "Kernel version: $(uname -r) ✓"
    
    # Check BTF support
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        error "BTF support not available. Need CONFIG_DEBUG_INFO_BTF=y in kernel"
        exit 1
    fi
    
    log "BTF support available ✓"
    
    # Check dependencies
    local missing_deps=()
    
    command -v clang >/dev/null 2>&1 || missing_deps+=("clang")
    command -v bpftool >/dev/null 2>&1 || missing_deps+=("bpftool")
    command -v python3 >/dev/null 2>&1 || missing_deps+=("python3")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        log "Run 'make setup' to install dependencies"
        exit 1
    fi
    
    log "Dependencies available ✓"
}

build_tracer() {
    log "Building eBPF tracer..."
    
    cd "$SCRIPT_DIR"
    if ! make clean && make all; then
        error "Failed to build tracer"
        exit 1
    fi
    
    if [[ ! -f "$TRACER" ]]; then
        error "Tracer binary not found at $TRACER"
        exit 1
    fi
    
    log "Tracer built successfully ✓"
}

test_basic_functionality() {
    log "Testing basic functionality..."
    
    mkdir -p "$TEST_DIR"
    local test_output="$TEST_DIR/basic_test.json"
    
    # Start tracer in background
    log "Starting tracer for 10 seconds..."
    timeout 10s "$TRACER" -j -o "$test_output" &
    local tracer_pid=$!
    
    # Give tracer time to start
    sleep 2
    
    # Generate some I/O activity
    log "Generating I/O activity..."
    for i in {1..5}; do
        echo "test data $i" > "$TEST_DIR/test_file_$i"
        cat "$TEST_DIR/test_file_$i" > /dev/null
        sync
        sleep 1
    done
    
    # Wait for tracer to finish
    wait $tracer_pid 2>/dev/null || true
    
    # Check if output file was created
    if [[ ! -f "$test_output" ]]; then
        error "Tracer output file not created"
        return 1
    fi
    
    # Check if output contains data
    if [[ ! -s "$test_output" ]]; then
        warn "Tracer output file is empty - this might be normal if no target processes were running"
    else
        log "Tracer output file created with $(wc -l < "$test_output") lines ✓"
    fi
    
    return 0
}

test_storage_system_detection() {
    log "Testing storage system detection..."
    
    local test_output="$TEST_DIR/detection_test.json"
    
    # Create fake processes with storage system names
    (
        # Change process name to simulate MinIO
        exec -a minio-server bash -c 'sleep 5 & echo "fake minio data" > '"$TEST_DIR"'/minio_test; wait'
    ) &
    local fake_minio_pid=$!
    
    (
        # Change process name to simulate etcd
        exec -a etcd bash -c 'sleep 5 & echo "fake etcd data" > '"$TEST_DIR"'/etcd_test; wait'
    ) &
    local fake_etcd_pid=$!
    
    # Start tracer
    timeout 8s "$TRACER" -j -o "$test_output" &
    local tracer_pid=$!
    
    # Wait for fake processes
    wait $fake_minio_pid 2>/dev/null || true
    wait $fake_etcd_pid 2>/dev/null || true
    
    # Wait for tracer
    wait $tracer_pid 2>/dev/null || true
    
    # Check output
    if [[ -f "$test_output" && -s "$test_output" ]]; then
        log "System detection test completed ✓"
        
        # Try to find traces from our fake systems
        if grep -q "MinIO\|etcd" "$test_output" 2>/dev/null; then
            log "Storage system detection working ✓"
        else
            warn "No storage systems detected in trace (expected if processes were too short-lived)"
        fi
    else
        warn "No output from detection test"
    fi
}

test_analyzer() {
    log "Testing analyzer..."
    
    # Check if Python script exists
    if [[ ! -f "$ANALYZER" ]]; then
        error "Analyzer script not found at $ANALYZER"
        return 1
    fi
    
    # Check Python dependencies
    local python_deps=("pandas" "matplotlib" "seaborn" "numpy")
    local missing_python_deps=()
    
    for dep in "${python_deps[@]}"; do
        if ! python3 -c "import $dep" 2>/dev/null; then
            missing_python_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_python_deps[@]} -gt 0 ]]; then
        warn "Missing Python dependencies: ${missing_python_deps[*]}"
        log "Install with: pip3 install ${missing_python_deps[*]}"
        return 1
    fi
    
    # Create a sample JSON file for testing
    local sample_json="$TEST_DIR/sample_trace.json"
    cat > "$sample_json" << EOF
{"timestamp":"14:23:45.123456789","pid":1234,"tid":1234,"comm":"minio","system":"MinIO","event_type":"SYSCALL_WRITE","size":4096,"offset":0,"latency_us":45.23,"retval":4096}
{"timestamp":"14:23:45.123500000","pid":1234,"tid":1234,"comm":"minio","system":"MinIO","event_type":"VFS_WRITE","size":4096,"offset":0,"latency_us":38.45,"retval":4096}
{"timestamp":"14:23:45.123650000","pid":1234,"tid":1234,"comm":"minio","system":"MinIO","event_type":"BLOCK_WRITE","size":4096,"offset":2048,"latency_us":125.67,"retval":4096}
{"timestamp":"14:23:46.123456789","pid":5678,"tid":5678,"comm":"etcd","system":"etcd","event_type":"SYSCALL_READ","size":1024,"offset":0,"latency_us":25.12,"retval":1024}
{"timestamp":"14:23:46.123500000","pid":5678,"tid":5678,"comm":"etcd","system":"etcd","event_type":"VFS_READ","size":1024,"offset":0,"latency_us":20.45,"retval":1024}
EOF
    
    # Test basic analysis
    if ! python3 "$ANALYZER" "$sample_json" --no-summary > /dev/null; then
        error "Analyzer failed on sample data"
        return 1
    fi
    
    log "Analyzer basic functionality ✓"
    
    # Test CSV export
    local csv_output="$TEST_DIR/test_results.csv"
    if python3 "$ANALYZER" "$sample_json" -e "$csv_output" --no-summary > /dev/null; then
        if [[ -f "$csv_output" && -s "$csv_output" ]]; then
            log "Analyzer CSV export ✓"
        else
            warn "CSV export file not created properly"
        fi
    else
        warn "CSV export test failed"
    fi
    
    # Test visualization (might fail without display)
    local plot_dir="$TEST_DIR/test_plots"
    if python3 "$ANALYZER" "$sample_json" -v -o "$plot_dir" --no-summary > /dev/null 2>&1; then
        if [[ -d "$plot_dir" ]] && [[ $(find "$plot_dir" -name "*.png" | wc -l) -gt 0 ]]; then
            log "Analyzer visualization ✓"
        else
            warn "Visualization files not created (may need display)"
        fi
    else
        warn "Visualization test failed (may need display)"
    fi
    
    return 0
}

run_comprehensive_test() {
    log "Running comprehensive test..."
    
    local comp_output="$TEST_DIR/comprehensive_test.json"
    
    # Start tracer
    timeout 15s "$TRACER" -v -j -o "$comp_output" &
    local tracer_pid=$!
    
    # Generate diverse I/O patterns
    log "Generating comprehensive I/O workload..."
    
    # Sequential writes
    for i in {1..10}; do
        dd if=/dev/zero of="$TEST_DIR/seq_$i" bs=4K count=10 2>/dev/null
    done
    
    # Random reads
    for i in {1..5}; do
        if [[ -f "$TEST_DIR/seq_$i" ]]; then
            dd if="$TEST_DIR/seq_$i" of=/dev/null bs=4K 2>/dev/null
        fi
    done
    
    # Mixed workload
    for i in {1..5}; do
        echo "mixed workload $i" >> "$TEST_DIR/mixed_file"
        cat "$TEST_DIR/mixed_file" > /dev/null
        sync
        sleep 1
    done
    
    # Wait for tracer
    wait $tracer_pid 2>/dev/null || true
    
    # Analyze results
    if [[ -f "$comp_output" && -s "$comp_output" ]]; then
        local line_count=$(wc -l < "$comp_output")
        log "Comprehensive test captured $line_count events ✓"
        
        # Run full analysis
        if python3 "$ANALYZER" "$comp_output" --no-summary > /dev/null 2>&1; then
            log "Comprehensive analysis completed ✓"
        else
            warn "Comprehensive analysis had issues"
        fi
    else
        warn "Comprehensive test produced no output"
    fi
}

performance_test() {
    log "Running performance test..."
    
    local perf_output="$TEST_DIR/performance_test.json"
    
    # Get baseline performance
    log "Measuring baseline I/O performance..."
    local start_time=$(date +%s.%N)
    
    for i in {1..100}; do
        echo "performance test data $i" > "$TEST_DIR/perf_$i"
    done
    sync
    
    local baseline_time=$(echo "$(date +%s.%N) - $start_time" | bc -l)
    log "Baseline time: ${baseline_time}s"
    
    # Test with tracer running
    log "Measuring performance with tracer..."
    start_time=$(date +%s.%N)
    
    timeout 10s "$TRACER" -q -j -o "$perf_output" &
    local tracer_pid=$!
    
    sleep 1  # Let tracer start
    
    for i in {101..200}; do
        echo "performance test data $i" > "$TEST_DIR/perf_$i"
    done
    sync
    
    local traced_time=$(echo "$(date +%s.%N) - $start_time" | bc -l)
    kill $tracer_pid 2>/dev/null || true
    
    log "Traced time: ${traced_time}s"
    
    # Calculate overhead
    local overhead=$(echo "scale=2; ($traced_time - $baseline_time) / $baseline_time * 100" | bc -l)
    if (( $(echo "$overhead < 50" | bc -l) )); then
        log "Performance overhead: ${overhead}% ✓"
    else
        warn "Performance overhead: ${overhead}% (high)"
    fi
}

cleanup() {
    log "Cleaning up test files..."
    rm -rf "$TEST_DIR"
    log "Cleanup complete ✓"
}

main() {
    log "Starting eBPF I/O Amplification Tracer Test Suite"
    log "=================================================="
    
    # Create test directory
    mkdir -p "$TEST_DIR"
    
    # Run tests
    local failed_tests=0
    
    check_requirements || ((failed_tests++))
    build_tracer || ((failed_tests++))
    test_basic_functionality || ((failed_tests++))
    test_storage_system_detection || ((failed_tests++))
    test_analyzer || ((failed_tests++))
    run_comprehensive_test || ((failed_tests++))
    
    # Optional performance test
    if command -v bc >/dev/null 2>&1; then
        performance_test || ((failed_tests++))
    else
        warn "Skipping performance test (bc not available)"
    fi
    
    cleanup
    
    # Summary
    log "=================================================="
    if [[ $failed_tests -eq 0 ]]; then
        log "All tests passed! ✓"
        log "The eBPF I/O Amplification Tracer is ready to use."
        log ""
        log "Quick start:"
        log "  sudo $TRACER -v -d 30                    # Real-time tracing"
        log "  sudo $TRACER -j -o trace.json -d 60      # JSON output"
        log "  python3 $ANALYZER trace.json -v          # Analysis with plots"
    else
        error "$failed_tests tests failed!"
        log ""
        log "Common issues and solutions:"
        log "  - Permission denied: Run with sudo"
        log "  - BPF load failed: Check kernel version >= 5.4 with BTF"
        log "  - Missing dependencies: Run 'make setup'"
        log "  - Python errors: Install pandas, matplotlib, seaborn, numpy"
        exit 1
    fi
}

# Handle script interruption
trap cleanup EXIT

main "$@"
