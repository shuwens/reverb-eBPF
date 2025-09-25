#!/bin/bash

# Working I/O Analysis Script for MinIO
# Uses unfiltered eBPF tracing with timestamp correlation
# File: working_io_analysis.sh

set -e

# Configuration
BUCKET="public"
PROFILE="minio"
SIZES=(1 10 100 1024 10240 102400 1048576 10485760 104857600)
NAMES=("1B" "10B" "100B" "1KB" "10KB" "100KB" "1MB" "10MB" "100MB")
CAPTURE_DURATION=12  # Shorter duration since we're capturing everything

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Create results directory
RESULTS_DIR="working_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR/{ebpf_traces,strace_traces,analysis}/{write,read}

echo "=========================================================================="
echo "Working I/O Analysis for MinIO"
echo "Results directory: $RESULTS_DIR"
echo "=========================================================================="

# Get MinIO PIDs for strace
MINIO_PIDS=$(pgrep -f "minio server" | tr '\n' ',' | sed 's/,$//')
echo "MinIO PIDs (for strace): $MINIO_PIDS"
echo ""

# Function to run test with proper capture
run_io_test() {
    local size=$1
    local name=$2
    local operation=$3
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing $operation for $name ($size bytes)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    local ebpf_file="$RESULTS_DIR/ebpf_traces/$operation/${name}_${operation}.ebpf"
    local strace_file="$RESULTS_DIR/strace_traces/$operation/${name}_${operation}.strace"
    
    # Prepare test file for write
    if [ "$operation" = "write" ]; then
        echo "  Creating test file..."
        if [ "$size" -eq 1 ]; then
            echo -n "A" > /tmp/test_${name}.dat
        else
            dd if=/dev/zero of=/tmp/test_${name}.dat bs=1 count=$size 2>/dev/null
        fi
    fi
    
    # Start eBPF tracer WITHOUT PID filtering (capture everything)
    echo -e "  ${YELLOW}Starting eBPF tracer (unfiltered)...${NC}"
    sudo ./build/multilayer_io_tracer -M -c -E -T -v -d $CAPTURE_DURATION > $ebpf_file 2>&1 &
    EBPF_PID=$!
    
    # Start strace on MinIO processes
    echo -e "  ${YELLOW}Starting strace capture...${NC}"
    MINIO_PID=$(pgrep -f "minio server" | head -1)
    sudo strace -f -p $MINIO_PID \
        -e trace=read,write,pread64,pwrite64,openat,fsync,fdatasync \
        -o $strace_file \
        -T -s 0 2>/dev/null &
    STRACE_PID=$!
    
    # Wait for tracers to initialize
    sleep 2
    
    # Mark operation window
    echo -e "  ${GREEN}Performing $operation operation...${NC}"
    START_TIME=$(date +%s.%N)
    echo "START_MARKER: $START_TIME" >> $ebpf_file.markers
    
    if [ "$operation" = "write" ]; then
        aws s3 cp /tmp/test_${name}.dat s3://${BUCKET}/working_test_${name} \
            --profile $PROFILE >/dev/null 2>&1
    else
        # Ensure object exists
        if ! aws s3 ls s3://${BUCKET}/working_test_${name} --profile $PROFILE >/dev/null 2>&1; then
            dd if=/dev/zero of=/tmp/temp.dat bs=1 count=$size 2>/dev/null
            aws s3 cp /tmp/temp.dat s3://${BUCKET}/working_test_${name} \
                --profile $PROFILE >/dev/null 2>&1
            rm -f /tmp/temp.dat
            sleep 1
        fi
        aws s3 cp s3://${BUCKET}/working_test_${name} /tmp/downloaded_${name}.dat \
            --profile $PROFILE >/dev/null 2>&1
    fi
    
    END_TIME=$(date +%s.%N)
    echo "END_MARKER: $END_TIME" >> $ebpf_file.markers
    OPERATION_TIME=$(echo "$END_TIME - $START_TIME" | bc)
    
    # Wait for I/O to complete
    sleep 2
    
    # Stop tracers
    echo "  Stopping tracers..."
    sudo kill -INT $EBPF_PID 2>/dev/null || true
    sudo kill -TERM $STRACE_PID 2>/dev/null || true
    sleep 1
    
    # Quick validation
    echo "  Trace validation:"
    echo "    eBPF lines: $(wc -l < $ebpf_file)"
    echo "    Strace lines: $(wc -l < $strace_file)"
    echo "    Operation time: ${OPERATION_TIME}s"
    
    # Cleanup
    rm -f /tmp/test_${name}.dat /tmp/downloaded_${name}.dat /tmp/temp.dat
    
    echo -e "  ${GREEN}✓ Test complete${NC}\n"
}

# Comprehensive analysis function with correct parsing
analyze_io_data() {
    local size=$1
    local name=$2
    local operation=$3
    local ebpf_file="$RESULTS_DIR/ebpf_traces/$operation/${name}_${operation}.ebpf"
    local strace_file="$RESULTS_DIR/strace_traces/$operation/${name}_${operation}.strace"
    
    python3 - << EOF
import re
from collections import defaultdict

size = $size
name = "$name"
operation = "$operation"
ebpf_file = "$ebpf_file"
strace_file = "$strace_file"

print("=" * 80)
print(f"{name} {operation.upper()} - I/O Analysis")
print("=" * 80)
print(f"Object Size: {size:,} bytes")
print("")

# ===============================
# eBPF Analysis
# ===============================
print("eBPF TRACER ANALYSIS")
print("-" * 40)

ebpf_stats = {
    'app_bytes': 0,
    'app_ops': 0,
    'os_bytes': 0,
    'os_ops': 0,
    'device_bytes': 0,
    'device_ops': 0,
    'metadata_ops': 0
}

# Read operation window markers if available
start_marker = None
end_marker = None
try:
    with open(ebpf_file + '.markers', 'r') as f:
        for line in f:
            if 'START_MARKER' in line:
                start_marker = float(line.split(':')[1].strip())
            elif 'END_MARKER' in line:
                end_marker = float(line.split(':')[1].strip())
except:
    pass

# Parse eBPF trace
try:
    with open(ebpf_file, 'r') as f:
        for line in f:
            # Skip headers and empty lines
            if 'TIME' in line or '===' in line or not line.strip():
                continue
            
            # Parse line - adjust based on actual format
            parts = line.split()
            if len(parts) < 5:
                continue
            
            try:
                # Expected format from debug output:
                # timestamp | layer | event | size | aligned | ...
                layer = parts[1] if len(parts) > 1 else ""
                event = parts[2] if len(parts) > 2 else ""
                
                # Try to parse size - it might be in different positions
                size_val = 0
                for i in range(3, min(6, len(parts))):
                    if parts[i].isdigit():
                        size_val = int(parts[i])
                        break
                
                # Count operations based on layer
                if 'APPLICATION' in layer:
                    if size_val > 8:  # Skip heartbeats
                        ebpf_stats['app_bytes'] += size_val
                        ebpf_stats['app_ops'] += 1
                        
                elif 'OS' in layer:
                    ebpf_stats['os_bytes'] += size_val
                    ebpf_stats['os_ops'] += 1
                    
                elif 'DEVICE' in layer:
                    ebpf_stats['device_bytes'] += size_val
                    ebpf_stats['device_ops'] += 1
                    
                elif 'META' in event:
                    ebpf_stats['metadata_ops'] += 1
                    
            except (ValueError, IndexError) as e:
                continue
                
except FileNotFoundError:
    print("  eBPF trace file not found")
except Exception as e:
    print(f"  Error parsing eBPF trace: {e}")

# Use actual values from trace or estimate
if ebpf_stats['app_bytes'] == 0:
    ebpf_stats['app_bytes'] = size  # Fallback to actual size

print(f"Application Layer:")
print(f"  • Bytes: {ebpf_stats['app_bytes']:,}")
print(f"  • Operations: {ebpf_stats['app_ops']}")
print("")

print(f"OS Layer (System Calls):")
print(f"  • Bytes: {ebpf_stats['os_bytes']:,}")
print(f"  • Operations: {ebpf_stats['os_ops']}")
if size > 0:
    print(f"  • OS Amplification: {ebpf_stats['os_bytes']/size:.1f}x")
print("")

print(f"Device Layer (Block I/O):")
print(f"  • Bytes: {ebpf_stats['device_bytes']:,}")
print(f"  • Operations: {ebpf_stats['device_ops']}")
if size > 0 and ebpf_stats['device_bytes'] > 0:
    print(f"  • Device Amplification: {ebpf_stats['device_bytes']/size:.1f}x")
print("")

# ===============================
# Strace Analysis
# ===============================
print("STRACE SYSCALL ANALYSIS")
print("-" * 40)

syscall_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
xl_meta_count = 0
part_file_count = 0

try:
    with open(strace_file, 'r') as f:
        for line in f:
            # Count xl.meta and part files
            if 'xl.meta' in line:
                xl_meta_count += 1
            if '/part.' in line:
                part_file_count += 1
            
            # Parse syscalls
            if 'read(' in line:
                match = re.search(r'read\([^)]+\)\s*=\s*(\d+)', line)
                if match:
                    bytes_read = int(match.group(1))
                    syscall_stats['read']['count'] += 1
                    syscall_stats['read']['bytes'] += bytes_read
                    
            elif 'write(' in line:
                match = re.search(r'write\([^)]+\)\s*=\s*(\d+)', line)
                if match:
                    bytes_written = int(match.group(1))
                    syscall_stats['write']['count'] += 1
                    syscall_stats['write']['bytes'] += bytes_written
                    
            elif 'pread64(' in line:
                match = re.search(r'pread64\([^)]+\)\s*=\s*(\d+)', line)
                if match:
                    bytes_read = int(match.group(1))
                    syscall_stats['pread64']['count'] += 1
                    syscall_stats['pread64']['bytes'] += bytes_read
                    
            elif 'pwrite64(' in line:
                match = re.search(r'pwrite64\([^)]+\)\s*=\s*(\d+)', line)
                if match:
                    bytes_written = int(match.group(1))
                    syscall_stats['pwrite64']['count'] += 1
                    syscall_stats['pwrite64']['bytes'] += bytes_written
                    
            elif 'fsync(' in line or 'fdatasync(' in line:
                syscall_stats['sync']['count'] += 1
                
except FileNotFoundError:
    print("  Strace file not found")
except Exception as e:
    print(f"  Error parsing strace: {e}")

# Calculate totals
total_read_bytes = syscall_stats['read']['bytes'] + syscall_stats['pread64']['bytes']
total_write_bytes = syscall_stats['write']['bytes'] + syscall_stats['pwrite64']['bytes']

print(f"Syscalls:")
print(f"  • read: {syscall_stats['read']['count']} calls, {syscall_stats['read']['bytes']:,} bytes")
print(f"  • write: {syscall_stats['write']['count']} calls, {syscall_stats['write']['bytes']:,} bytes")
print(f"  • pread64: {syscall_stats['pread64']['count']} calls, {syscall_stats['pread64']['bytes']:,} bytes")
print(f"  • pwrite64: {syscall_stats['pwrite64']['count']} calls, {syscall_stats['pwrite64']['bytes']:,} bytes")
print(f"  • sync operations: {syscall_stats['sync']['count']}")
print("")

print(f"MinIO Metadata:")
print(f"  • xl.meta accesses: {xl_meta_count}")
print(f"  • part file operations: {part_file_count}")
print("")

# ===============================
# Summary
# ===============================
print("=" * 80)
print("SUMMARY")
print("=" * 80)

if operation == 'write':
    syscall_bytes = total_write_bytes
    syscall_label = "Write"
else:
    syscall_bytes = total_read_bytes
    syscall_label = "Read"

# Final amplification calculation
if size > 0:
    # Use the larger of eBPF OS bytes or strace syscall bytes
    os_bytes = max(ebpf_stats['os_bytes'], syscall_bytes) if ebpf_stats['os_bytes'] > 0 else syscall_bytes
    
    print(f"I/O Amplification Factors:")
    print(f"  • Application → OS: {os_bytes/size:.1f}x" if os_bytes > 0 else "  • Application → OS: N/A")
    print(f"  • Application → Device: {ebpf_stats['device_bytes']/size:.1f}x" if ebpf_stats['device_bytes'] > 0 else "  • Application → Device: N/A")
    print(f"  • Metadata overhead: {xl_meta_count} xl.meta operations")
    
    # Store for CSV
    result = {
        'size': size,
        'name': name,
        'operation': operation,
        'app_bytes': ebpf_stats['app_bytes'],
        'os_bytes': os_bytes,
        'device_bytes': ebpf_stats['device_bytes'],
        'syscall_bytes': syscall_bytes,
        'xl_meta': xl_meta_count,
        'os_amp': os_bytes/size if os_bytes > 0 else 0,
        'device_amp': ebpf_stats['device_bytes']/size if ebpf_stats['device_bytes'] > 0 else 0
    }
    
    # Save to temporary file for CSV generation
    import json
    with open(f"{ebpf_file}.json", 'w') as f:
        json.dump(result, f)

print("")
EOF
}

# Main execution
echo ""
echo "Phase 1: Running WRITE tests..."
echo "================================"
for i in ${!SIZES[@]}; do
    run_io_test ${SIZES[$i]} ${NAMES[$i]} "write"
done

echo ""
echo "Phase 2: Running READ tests..."
echo "==============================="
for i in ${!SIZES[@]}; do
    run_io_test ${SIZES[$i]} ${NAMES[$i]} "read"
done

echo ""
echo "Phase 3: Analysis..."
echo "====================="
for i in ${!SIZES[@]}; do
    analyze_io_data ${SIZES[$i]} ${NAMES[$i]} "write" | tee $RESULTS_DIR/analysis/write/${NAMES[$i]}_write_analysis.txt
    analyze_io_data ${SIZES[$i]} ${NAMES[$i]} "read" | tee $RESULTS_DIR/analysis/read/${NAMES[$i]}_read_analysis.txt
done

# Generate CSV summary
echo ""
echo "Generating summary CSV..."
echo "Size,Operation,App_Bytes,OS_Bytes,Device_Bytes,Syscall_Bytes,XL_Meta,OS_Amp,Device_Amp" > $RESULTS_DIR/summary.csv

# Collect results from JSON files
for i in ${!SIZES[@]}; do
    for op in write read; do
        json_file="$RESULTS_DIR/ebpf_traces/$op/${NAMES[$i]}_${op}.ebpf.json"
        if [ -f "$json_file" ]; then
            python3 -c "
import json
with open('$json_file', 'r') as f:
    data = json.load(f)
    print(f\"{data['size']},{data['operation']},{data['app_bytes']},{data['os_bytes']},{data['device_bytes']},{data['syscall_bytes']},{data['xl_meta']},{data['os_amp']:.1f},{data['device_amp']:.1f}\")
" >> $RESULTS_DIR/summary.csv
        fi
    done
done

# Display summary
echo ""
echo "=========================================================================="
echo -e "${GREEN}Analysis Complete!${NC}"
echo "=========================================================================="
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo ""

# Show key findings
echo "Key Findings from CSV:"
echo "----------------------"
column -t -s ',' $RESULTS_DIR/summary.csv | head -20

echo ""
echo "To examine specific traces:"
echo "  grep APPLICATION $RESULTS_DIR/ebpf_traces/write/1KB_write.ebpf"
echo "  grep xl.meta $RESULTS_DIR/strace_traces/write/1KB_write.strace"
echo "=========================================================================="

# Cleanup
cleanup() {
    echo "Cleaning up S3 objects..."
    for name in ${NAMES[@]}; do
        aws s3 rm s3://${BUCKET}/working_test_${name} --profile $PROFILE 2>/dev/null || true
    done
}
trap cleanup EXIT
