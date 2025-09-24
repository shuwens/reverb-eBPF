#!/bin/bash

# Fixed strace capture for MinIO I/O analysis
# This script properly captures syscalls during MinIO operations

set -e

# Configuration
BUCKET="public"
PROFILE="minio"
SIZES=(1 10 100 1024 10240 102400 1048576 10485760)
NAMES=("1B" "10B" "100B" "1KB" "10KB" "100KB" "1MB" "10MB")
STRACE_DURATION=20  # Capture for full duration

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create results directory
RESULTS_DIR="strace_capture_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR/{write,read}

echo "=========================================================================="
echo "Fixed strace Capture for MinIO"
echo "Results directory: $RESULTS_DIR"
echo "=========================================================================="

# Find ALL MinIO processes
MINIO_PIDS=$(pgrep -f "minio server" | tr '\n' ',' | sed 's/,$//')
if [ -z "$MINIO_PIDS" ]; then
    echo -e "${RED}Error: MinIO server not found${NC}"
    exit 1
fi
echo "MinIO PIDs: $MINIO_PIDS"

# Function to run test with proper strace
run_test_with_strace() {
    local size=$1
    local name=$2
    local operation=$3
    
    echo -e "${BLUE}Testing $operation for $name ($size bytes)...${NC}"
    
    # Prepare test file for write
    if [ "$operation" = "write" ]; then
        if [ "$size" -eq 1 ]; then
            echo -n "A" > /tmp/test_${name}.dat
        else
            dd if=/dev/zero of=/tmp/test_${name}.dat bs=$size count=1 2>/dev/null
        fi
    fi
    
    # Start strace on ALL MinIO processes with comprehensive capture
    local strace_file="$RESULTS_DIR/$operation/${name}_${operation}.strace"
    echo "  Starting comprehensive strace..."
    
    # Use -p for each PID and capture ALL syscalls
    sudo strace -f \
        $(echo $MINIO_PIDS | tr ',' '\n' | sed 's/^/-p /') \
        -o $strace_file \
        -T -tt -s 512 \
        2>/dev/null &
    STRACE_PID=$!
    
    # Give strace time to attach
    sleep 2
    
    # Perform the operation
    echo "  Performing $operation..."
    if [ "$operation" = "write" ]; then
        aws s3 cp /tmp/test_${name}.dat s3://${BUCKET}/strace_test_${name} \
            --profile $PROFILE 2>&1 | grep -v "upload" || true
    else
        aws s3 cp s3://${BUCKET}/strace_test_${name} /tmp/downloaded_${name}.dat \
            --profile $PROFILE 2>&1 | grep -v "download" || true
    fi
    
    # Let I/O complete
    sleep 2
    
    # Stop strace
    echo "  Stopping strace..."
    sudo kill -TERM $STRACE_PID 2>/dev/null || true
    sleep 1
    
    # Check if we captured data
    local line_count=$(wc -l < $strace_file)
    echo "  Captured $line_count syscalls"
    
    # Quick analysis
    echo "  Quick analysis:"
    echo "    Open/openat calls: $(grep -c "open" $strace_file 2>/dev/null || echo 0)"
    echo "    Read calls: $(grep -c "read(" $strace_file 2>/dev/null || echo 0)"
    echo "    Write calls: $(grep -c "write(" $strace_file 2>/dev/null || echo 0)"
    echo "    xl.meta accesses: $(grep -c "xl.meta" $strace_file 2>/dev/null || echo 0)"
    echo "    part. files: $(grep -c "/part\." $strace_file 2>/dev/null || echo 0)"
    
    # Show sample of xl.meta access if found
    if grep -q "xl.meta" $strace_file 2>/dev/null; then
        echo -e "  ${GREEN}Found xl.meta access:${NC}"
        grep "xl.meta" $strace_file | head -1
    fi
    
    # Cleanup
    rm -f /tmp/test_${name}.dat /tmp/downloaded_${name}.dat
    
    echo -e "  ${GREEN}✓ Complete${NC}"
    echo ""
}

# Alternative: Use systemtap or tcpdump approach
test_with_tcpdump() {
    local name=$1
    echo -e "${YELLOW}Alternative: Capturing network traffic for $name...${NC}"
    
    # Capture network traffic to MinIO port
    sudo timeout 10 tcpdump -i lo -w $RESULTS_DIR/${name}_network.pcap port 9000 &
    TCPDUMP_PID=$!
    
    sleep 1
    
    # Run operation
    dd if=/dev/zero of=/tmp/test.dat bs=1024 count=1 2>/dev/null
    aws s3 cp /tmp/test.dat s3://${BUCKET}/tcpdump_test_${name} --profile $PROFILE 2>&1 | head -2
    
    sleep 1
    sudo kill $TCPDUMP_PID 2>/dev/null || true
    
    # Analyze
    echo "  Network bytes: $(sudo tcpdump -r $RESULTS_DIR/${name}_network.pcap 2>/dev/null | wc -l) packets"
}

# Main execution
echo ""
echo "Testing strace capture methods..."
echo "=================================="

# Test 1: Basic strace test
echo -e "${YELLOW}Test 1: Verifying strace can attach to MinIO${NC}"
sudo timeout 2 strace -p $(echo $MINIO_PIDS | cut -d',' -f1) -o /tmp/test_strace.out 2>&1 &
sleep 1
sudo kill $! 2>/dev/null || true
if [ -s /tmp/test_strace.out ]; then
    echo -e "${GREEN}✓ strace can attach to MinIO${NC}"
    echo "  Sample output: $(head -1 /tmp/test_strace.out)"
else
    echo -e "${RED}✗ strace cannot attach - may need different approach${NC}"
fi
sudo rm -f /tmp/test_strace.out

# Test 2: Try different strace modes
echo ""
echo -e "${YELLOW}Test 2: Testing different strace modes${NC}"

# Mode A: Follow children aggressively
echo "  Mode A: Following all children..."
sudo timeout 5 strace -f -ff -p $(echo $MINIO_PIDS | cut -d',' -f1) \
    -o $RESULTS_DIR/test_mode_a 2>/dev/null &
STRACE_PID=$!
sleep 1
aws s3 ls --profile $PROFILE 2>&1 | head -2
sleep 1
sudo kill $STRACE_PID 2>/dev/null || true
echo "    Captured files: $(ls -1 $RESULTS_DIR/test_mode_a* 2>/dev/null | wc -l)"

# Mode B: System-wide trace filtering for MinIO
echo "  Mode B: System-wide trace with filter..."
sudo timeout 5 strace -e trace=open,openat,read,write,pread64,pwrite64 \
    -e trace=%file -o $RESULTS_DIR/test_mode_b.strace \
    bash -c "aws s3 ls --profile $PROFILE" 2>/dev/null || true
echo "    Captured: $(wc -l < $RESULTS_DIR/test_mode_b.strace 2>/dev/null || echo 0) lines"

echo ""
echo "Running actual tests..."
echo "======================"

# Run write tests
for i in ${!SIZES[@]}; do
    run_test_with_strace ${SIZES[$i]} ${NAMES[$i]} "write"
done

# Run read tests
for i in ${!SIZES[@]}; do
    run_test_with_strace ${SIZES[$i]} ${NAMES[$i]} "read"
done

# Summary
echo ""
echo "=========================================================================="
echo -e "${GREEN}Capture Complete!${NC}"
echo "=========================================================================="
echo "Results in: $RESULTS_DIR/"
echo ""
echo "File size summary:"
du -sh $RESULTS_DIR/*/*.strace 2>/dev/null | head -10

echo ""
echo "xl.meta access summary:"
for file in $RESULTS_DIR/*/*.strace; do
    count=$(grep -c "xl.meta" $file 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        echo "  $(basename $file): $count xl.meta operations"
    fi
done

echo ""
echo "To examine details:"
echo "  grep xl.meta $RESULTS_DIR/write/1KB_write.strace"
echo "  grep 'write(' $RESULTS_DIR/write/1KB_write.strace | head"
echo "=========================================================================="

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up temporary files..."
    sudo rm -f /tmp/test_*.dat /tmp/downloaded_*.dat /tmp/test_strace.out
    # Clean up S3 test objects
    for name in ${NAMES[@]}; do
        aws s3 rm s3://${BUCKET}/strace_test_${name} --profile $PROFILE 2>/dev/null || true
        aws s3 rm s3://${BUCKET}/tcpdump_test_${name} --profile $PROFILE 2>/dev/null || true
    done
    echo "Cleanup complete"
}

# Run cleanup on exit
trap cleanup EXIT
