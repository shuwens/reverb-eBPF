#!/bin/bash

# Debug version of I/O Analysis Script
# Helps identify why eBPF tracer is returning zeros
# File: debug_io_tracer.sh

set -e

# Configuration
BUCKET="public"
PROFILE="minio"
TEST_SIZE=10240  # 10KB for testing
TEST_NAME="10KB"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Results directory
RESULTS_DIR="debug_io_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR

echo "=========================================================================="
echo "I/O Tracer Debug Session"
echo "=========================================================================="

# Get MinIO PIDs
MINIO_PIDS=$(pgrep -f "minio server" | tr '\n' ',' | sed 's/,$//')
echo "MinIO PIDs: $MINIO_PIDS"
echo ""

# Test 1: Check if tracer works WITHOUT PID filtering
echo -e "${YELLOW}Test 1: Running tracer WITHOUT PID filtering${NC}"
echo "----------------------------------------"

# Create test file
dd if=/dev/zero of=/tmp/test.dat bs=$TEST_SIZE count=1 2>/dev/null

# Start tracer without PID filter
echo "Starting unfiltered tracer..."
sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 10 > $RESULTS_DIR/unfiltered.log 2>&1 &
TRACER_PID=$!

sleep 2

# Perform write
echo "Performing S3 write..."
aws s3 cp /tmp/test.dat s3://${BUCKET}/debug_test --profile $PROFILE >/dev/null 2>&1

sleep 2

# Stop tracer
sudo kill -INT $TRACER_PID 2>/dev/null || true
sleep 1

# Analyze unfiltered results
echo "Unfiltered results:"
echo "  Total lines captured: $(wc -l < $RESULTS_DIR/unfiltered.log)"
echo "  APPLICATION events: $(grep -c "APPLICATION" $RESULTS_DIR/unfiltered.log 2>/dev/null || echo 0)"
echo "  OS events: $(grep -c "OS" $RESULTS_DIR/unfiltered.log 2>/dev/null || echo 0)"
echo "  DEVICE events: $(grep -c "DEVICE" $RESULTS_DIR/unfiltered.log 2>/dev/null || echo 0)"
echo ""

# Test 2: Check tracer with PID filtering (if supported)
echo -e "${YELLOW}Test 2: Testing PID filtering methods${NC}"
echo "----------------------------------------"

# Method A: Using -p flag
echo "Method A: Using -p flag with PIDs..."
sudo timeout 5 ./build/multilayer_io_tracer -M -c -E -T -v -p $MINIO_PIDS 2>&1 | head -20 > $RESULTS_DIR/pid_test.log
if grep -q "invalid option" $RESULTS_DIR/pid_test.log 2>/dev/null; then
    echo -e "  ${RED}✗ -p flag not supported${NC}"
else
    echo -e "  ${GREEN}✓ -p flag accepted${NC}"
fi

# Method B: Check for filter expression support
echo "Method B: Testing filter expression..."
sudo timeout 2 ./build/multilayer_io_tracer -h 2>&1 | grep -E "filter|pid|process" > $RESULTS_DIR/help.txt || true
if [ -s $RESULTS_DIR/help.txt ]; then
    echo -e "  ${GREEN}Filter options found:${NC}"
    cat $RESULTS_DIR/help.txt
else
    echo -e "  ${YELLOW}No built-in filter options found${NC}"
fi

echo ""

# Test 3: Alternative - Use tracer without filter and post-process
echo -e "${YELLOW}Test 3: Post-processing approach${NC}"
echo "----------------------------------------"

# Start tracer without filter but capture everything
echo "Starting comprehensive trace..."
sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 12 > $RESULTS_DIR/full_trace.log 2>&1 &
TRACER_PID=$!

sleep 2

# Mark start time
START_MARKER=$(date +%s.%N)

# Perform operation
echo "Performing S3 operation..."
aws s3 cp /tmp/test.dat s3://${BUCKET}/debug_test2 --profile $PROFILE >/dev/null 2>&1

# Mark end time
END_MARKER=$(date +%s.%N)

sleep 3

# Stop tracer
sudo kill -INT $TRACER_PID 2>/dev/null || true
sleep 1

# Analyze captured data
echo "Full trace analysis:"
python3 - << EOF
import re

trace_file = "$RESULTS_DIR/full_trace.log"
start_time = $START_MARKER
end_time = $END_MARKER

stats = {
    'app': {'count': 0, 'bytes': 0},
    'os': {'count': 0, 'bytes': 0},
    'device': {'count': 0, 'bytes': 0}
}

print(f"  Analyzing window: {start_time:.2f} to {end_time:.2f}")

try:
    with open(trace_file, 'r') as f:
        for line in f:
            if 'TIME' in line or '===' in line:
                continue
                
            # Try to extract timestamp if present
            # Adjust parsing based on your tracer output format
            
            parts = line.split()
            if len(parts) < 5:
                continue
                
            try:
                layer = parts[1] if len(parts) > 1 else ""
                event = parts[2] if len(parts) > 2 else ""
                size_val = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                
                if 'APPLICATION' in layer:
                    stats['app']['count'] += 1
                    stats['app']['bytes'] += size_val
                elif 'OS' in layer:
                    stats['os']['count'] += 1
                    stats['os']['bytes'] += size_val
                elif 'DEVICE' in layer:
                    stats['device']['count'] += 1
                    stats['device']['bytes'] += size_val
            except:
                pass
                
    print(f"  Application: {stats['app']['count']} ops, {stats['app']['bytes']:,} bytes")
    print(f"  OS Layer: {stats['os']['count']} ops, {stats['os']['bytes']:,} bytes")
    print(f"  Device Layer: {stats['device']['count']} ops, {stats['device']['bytes']:,} bytes")
    
except Exception as e:
    print(f"  Error analyzing trace: {e}")
EOF

echo ""

# Test 4: Check if we need different tracer invocation
echo -e "${YELLOW}Test 4: Alternative tracer invocations${NC}"
echo "----------------------------------------"

# Check if tracer needs to be run differently
echo "Checking tracer binary..."
file ./build/multilayer_io_tracer 2>/dev/null || echo "  Binary not found at expected path"
ldd ./build/multilayer_io_tracer 2>/dev/null | head -5 || echo "  Cannot check dependencies"

# Try running with minimal flags
echo ""
echo "Testing minimal invocation..."
sudo timeout 5 ./build/multilayer_io_tracer -d 5 > $RESULTS_DIR/minimal.log 2>&1 &
MINIMAL_PID=$!
sleep 1
aws s3 ls --profile $PROFILE >/dev/null 2>&1
sleep 2
sudo kill $MINIMAL_PID 2>/dev/null || true

echo "  Minimal trace lines: $(wc -l < $RESULTS_DIR/minimal.log 2>/dev/null || echo 0)"

echo ""

# Test 5: Use strace as primary measurement with eBPF validation
echo -e "${YELLOW}Test 5: Strace-based measurement (reliable fallback)${NC}"
echo "----------------------------------------"

# Get fresh PIDs
MINIO_PID=$(pgrep -f "minio server" | head -1)

# Comprehensive strace
echo "Running strace on MinIO PID $MINIO_PID..."
sudo strace -f -p $MINIO_PID \
    -e trace=read,write,pread64,pwrite64,openat,fsync,fdatasync \
    -o $RESULTS_DIR/strace_measure.log \
    -T -s 0 2>/dev/null &
STRACE_PID=$!

sleep 2

# Perform operation
echo "Performing measured S3 write..."
aws s3 cp /tmp/test.dat s3://${BUCKET}/strace_test --profile $PROFILE >/dev/null 2>&1

sleep 2

# Stop strace
sudo kill $STRACE_PID 2>/dev/null || true

# Analyze strace
echo "Strace syscall analysis:"
echo "  Write syscalls: $(grep -c "write(" $RESULTS_DIR/strace_measure.log 2>/dev/null || echo 0)"
echo "  Read syscalls: $(grep -c "read(" $RESULTS_DIR/strace_measure.log 2>/dev/null || echo 0)"
echo "  Total bytes written: $(grep "write(" $RESULTS_DIR/strace_measure.log | grep -oE "= [0-9]+" | awk '{sum+=$2} END {print sum}')"
echo ""

# Test 6: Check system configuration
echo -e "${YELLOW}Test 6: System configuration check${NC}"
echo "----------------------------------------"

# Check if BPF is enabled
echo "BPF/eBPF support:"
if [ -d /sys/kernel/debug/tracing ]; then
    echo -e "  ${GREEN}✓ Tracing infrastructure present${NC}"
else
    echo -e "  ${RED}✗ Tracing infrastructure not found${NC}"
fi

if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    BPF_DISABLED=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    if [ "$BPF_DISABLED" = "0" ]; then
        echo -e "  ${GREEN}✓ Unprivileged BPF enabled${NC}"
    else
        echo -e "  ${YELLOW}⚠ Unprivileged BPF disabled (running as root should work)${NC}"
    fi
fi

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "  Kernel version: $KERNEL_VERSION"

echo ""

# Summary and recommendations
echo "=========================================================================="
echo -e "${CYAN}DIAGNOSIS SUMMARY${NC}"
echo "=========================================================================="

# Determine the issue
if [ $(grep -c "DEVICE" $RESULTS_DIR/unfiltered.log 2>/dev/null || echo 0) -gt 0 ]; then
    echo -e "${GREEN}✓ eBPF tracer is working (capturing device events)${NC}"
    echo ""
    echo "Issue: PID filtering is not working correctly"
    echo ""
    echo "RECOMMENDED SOLUTIONS:"
    echo "1. Use tracer WITHOUT PID filtering and post-process the output:"
    echo "   sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 15 > trace.log"
    echo "   Then filter MinIO operations by timestamp correlation"
    echo ""
    echo "2. Modify the tracer source to add PID filtering in eBPF programs"
    echo ""
    echo "3. Use process name filtering if available:"
    echo "   Look for options like -n 'minio' or --comm 'minio'"
else
    echo -e "${RED}✗ eBPF tracer is NOT capturing device events${NC}"
    echo ""
    echo "Possible causes:"
    echo "1. Tracer not compiled correctly"
    echo "2. Missing kernel headers or eBPF support"
    echo "3. Incorrect invocation flags"
    echo ""
    echo "RECOMMENDED SOLUTIONS:"
    echo "1. Rebuild the tracer:"
    echo "   cd build && make clean && make"
    echo ""
    echo "2. Check tracer dependencies:"
    echo "   sudo apt-get install linux-headers-\$(uname -r)"
    echo "   sudo apt-get install libbpf-dev"
    echo ""
    echo "3. Use strace as primary measurement tool:"
    echo "   More reliable but less comprehensive than eBPF"
fi

echo ""
echo "Detailed logs saved in: $RESULTS_DIR/"
echo ""

# Create working solution script
cat > $RESULTS_DIR/working_solution.sh << 'SOLUTION_EOF'
#!/bin/bash

# Working solution for I/O measurement
# Based on diagnostic results

# For eBPF (if working): Run without PID filter, correlate by time
run_ebpf_measurement() {
    local operation=$1
    local size=$2
    
    # Start trace
    sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 15 > trace.log 2>&1 &
    TRACER_PID=$!
    
    sleep 2
    
    # Mark operation start
    START_TIME=$(date +%s.%N)
    
    # Run S3 operation
    if [ "$operation" = "write" ]; then
        aws s3 cp test.dat s3://bucket/test --profile minio
    else
        aws s3 cp s3://bucket/test downloaded.dat --profile minio
    fi
    
    # Mark operation end
    END_TIME=$(date +%s.%N)
    
    sleep 3
    sudo kill -INT $TRACER_PID
    
    # Extract relevant window from trace
    # Process trace.log focusing on START_TIME to END_TIME window
}

# For strace: Direct PID attachment
run_strace_measurement() {
    local operation=$1
    local size=$2
    local minio_pid=$(pgrep -f "minio server" | head -1)
    
    # Attach strace
    sudo strace -f -p $minio_pid \
        -e trace=read,write,pread64,pwrite64 \
        -o strace.log -T 2>/dev/null &
    STRACE_PID=$!
    
    sleep 1
    
    # Run S3 operation
    if [ "$operation" = "write" ]; then
        aws s3 cp test.dat s3://bucket/test --profile minio
    else
        aws s3 cp s3://bucket/test downloaded.dat --profile minio
    fi
    
    sleep 1
    sudo kill $STRACE_PID
    
    # Analyze strace.log for I/O bytes
}

# Choose based on what works
if grep -q "DEVICE" trace.log 2>/dev/null; then
    echo "Using eBPF tracer (without PID filter)"
    run_ebpf_measurement "$@"
else
    echo "Using strace fallback"
    run_strace_measurement "$@"
fi
SOLUTION_EOF

chmod +x $RESULTS_DIR/working_solution.sh

echo "Working solution script created: $RESULTS_DIR/working_solution.sh"
echo "=========================================================================="

# Cleanup
rm -f /tmp/test.dat
aws s3 rm s3://${BUCKET}/debug_test --profile $PROFILE 2>/dev/null || true
aws s3 rm s3://${BUCKET}/debug_test2 --profile $PROFILE 2>/dev/null || true
aws s3 rm s3://${BUCKET}/strace_test --profile $PROFILE 2>/dev/null || true
