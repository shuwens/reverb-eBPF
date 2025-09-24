#!/bin/bash

# Comprehensive Syscall and I/O Analysis for MinIO
# Captures detailed syscall metrics, byte-level amplification, and I/O patterns
# File: comprehensive_syscall_analysis.sh

set -e

# Configuration
BUCKET="public"
PROFILE="minio"
SIZES=(1 10 100 1024 10240 102400 1048576 10485760 104857600)
NAMES=("1B" "10B" "100B" "1KB" "10KB" "100KB" "1MB" "10MB" "100MB")
CAPTURE_DURATION=20

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Create results directory
RESULTS_DIR="syscall_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR/{write,read}/{strace,ebpf,analysis}

echo "=========================================================================="
echo -e "${CYAN}Comprehensive Syscall and I/O Analysis${NC}"
echo "Results directory: $RESULTS_DIR"
echo "=========================================================================="

# Log file for debugging
LOG_FILE="$RESULTS_DIR/debug.log"

# Find MinIO processes
get_minio_pids() {
    pgrep -f "minio server" | tr '\n' ' '
}

MINIO_PIDS=$(get_minio_pids)
if [ -z "$MINIO_PIDS" ]; then
    echo -e "${RED}Error: MinIO server not found${NC}"
    exit 1
fi
echo "MinIO PIDs: $MINIO_PIDS"

# Function to capture syscalls with strace
capture_syscalls() {
    local operation=$1
    local name=$2
    local size=$3
    local strace_file="$RESULTS_DIR/$operation/strace/${name}_${operation}.strace"
    
    echo "  Starting syscall capture..." | tee -a $LOG_FILE
    
    # Build strace command for all PIDs
    local strace_cmd="sudo strace -f"
    for pid in $MINIO_PIDS; do
        strace_cmd="$strace_cmd -p $pid"
    done
    
    # Run strace with comprehensive options
    $strace_cmd \
        -e trace=all \
        -o $strace_file \
        -T -tt -s 1024 \
        2>>$LOG_FILE &
    
    local strace_pid=$!
    echo "    strace PID: $strace_pid" | tee -a $LOG_FILE
    
    # Wait for attach
    sleep 2
    
    # Return PID for later cleanup
    echo $strace_pid
}

# Function to analyze captured syscalls
analyze_syscalls() {
    local strace_file=$1
    local analysis_file=$2
    local size=$3
    local name=$4
    local operation=$5
    
    python3 - "$strace_file" "$analysis_file" "$size" "$name" "$operation" << 'PYTHON_SCRIPT'
import sys
import re
from collections import defaultdict
import json

strace_file = sys.argv[1]
analysis_file = sys.argv[2]
test_size = int(sys.argv[3])
test_name = sys.argv[4]
operation = sys.argv[5]

# Initialize metrics
metrics = {
    'syscall_counts': defaultdict(int),
    'syscall_bytes': defaultdict(int),
    'file_operations': defaultdict(lambda: {'reads': 0, 'writes': 0, 'opens': 0}),
    'fd_map': {},
    'total_read_bytes': 0,
    'total_write_bytes': 0,
    'xl_meta_ops': 0,
    'part_file_ops': 0,
    'fsync_ops': 0,
    'network_bytes': 0,
    'syscall_timeline': []
}

# Parse strace output
try:
    with open(strace_file, 'r') as f:
        for line in f:
            # Skip incomplete lines
            if '<unfinished' in line or 'resumed>' in line:
                continue
                
            # Extract timestamp
            timestamp_match = re.match(r'(\d+:\d+:\d+\.\d+)', line)
            if timestamp_match:
                timestamp = timestamp_match.group(1)
            else:
                timestamp = None
                
            # Track file opens
            if 'open(' in line or 'openat(' in line:
                fd_match = re.search(r'= (\d+)', line)
                path_match = re.search(r'"([^"]+)"', line)
                if fd_match and path_match and int(fd_match.group(1)) >= 0:
                    fd = fd_match.group(1)
                    path = path_match.group(1)
                    metrics['fd_map'][fd] = path
                    metrics['file_operations'][path]['opens'] += 1
                    
                    if 'xl.meta' in path:
                        metrics['xl_meta_ops'] += 1
                    if '/part.' in path or 'part-' in path:
                        metrics['part_file_ops'] += 1
                        
            # Track read operations
            for read_call in ['read', 'pread', 'pread64', 'readv']:
                if f'{read_call}(' in line:
                    metrics['syscall_counts'][read_call] += 1
                    
                    # Extract bytes
                    bytes_match = re.search(r'= (\d+)', line)
                    if bytes_match:
                        byte_count = int(bytes_match.group(1))
                        if byte_count > 0:
                            metrics['syscall_bytes'][read_call] += byte_count
                            metrics['total_read_bytes'] += byte_count
                            
                            # Track file if known
                            fd_match = re.search(f'{read_call}\((\d+)', line)
                            if fd_match:
                                fd = fd_match.group(1)
                                if fd in metrics['fd_map']:
                                    path = metrics['fd_map'][fd]
                                    metrics['file_operations'][path]['reads'] += byte_count
                                    
                            # Add to timeline
                            if timestamp:
                                metrics['syscall_timeline'].append({
                                    'time': timestamp,
                                    'call': read_call,
                                    'bytes': byte_count,
                                    'type': 'read'
                                })
                    break
                    
            # Track write operations
            for write_call in ['write', 'pwrite', 'pwrite64', 'writev']:
                if f'{write_call}(' in line:
                    metrics['syscall_counts'][write_call] += 1
                    
                    # Extract bytes
                    bytes_match = re.search(r'= (\d+)', line)
                    if bytes_match:
                        byte_count = int(bytes_match.group(1))
                        if byte_count > 0:
                            metrics['syscall_bytes'][write_call] += byte_count
                            metrics['total_write_bytes'] += byte_count
                            
                            # Track file if known
                            fd_match = re.search(f'{write_call}\((\d+)', line)
                            if fd_match:
                                fd = fd_match.group(1)
                                if fd in metrics['fd_map']:
                                    path = metrics['fd_map'][fd]
                                    metrics['file_operations'][path]['writes'] += byte_count
                                    
                            # Add to timeline
                            if timestamp:
                                metrics['syscall_timeline'].append({
                                    'time': timestamp,
                                    'call': write_call,
                                    'bytes': byte_count,
                                    'type': 'write'
                                })
                    break
                    
            # Track fsync operations
            if 'fsync(' in line or 'fdatasync(' in line:
                metrics['fsync_ops'] += 1
                metrics['syscall_counts']['fsync'] += 1
                
            # Track network operations
            if 'sendto(' in line or 'recvfrom(' in line:
                bytes_match = re.search(r'= (\d+)', line)
                if bytes_match:
                    byte_count = int(bytes_match.group(1))
                    if byte_count > 0:
                        metrics['network_bytes'] += byte_count
                        
except Exception as e:
    print(f"Error parsing strace: {e}", file=sys.stderr)

# Calculate amplification factors
if operation == 'write':
    syscall_amp = metrics['total_write_bytes'] / test_size if test_size > 0 else 0
    primary_metric = metrics['total_write_bytes']
else:
    syscall_amp = metrics['total_read_bytes'] / test_size if test_size > 0 else 0
    primary_metric = metrics['total_read_bytes']

# Find MinIO data files
data_files = []
xl_meta_files = []
part_files = []

for path in metrics['file_operations'].keys():
    if '/data/' in path or '/mnt/' in path:
        if 'xl.meta' in path:
            xl_meta_files.append(path)
        elif 'part.' in path or 'part-' in path:
            part_files.append(path)
        else:
            data_files.append(path)

# Write comprehensive analysis
with open(analysis_file, 'w') as f:
    f.write("=" * 80 + "\n")
    f.write(f"COMPREHENSIVE SYSCALL ANALYSIS: {test_name} {operation.upper()}\n")
    f.write("=" * 80 + "\n\n")
    
    # Basic metrics
    f.write("TEST PARAMETERS:\n")
    f.write(f"  Object size: {test_size:,} bytes\n")
    f.write(f"  Operation: {operation}\n\n")
    
    # I/O Summary
    f.write("I/O SUMMARY:\n")
    f.write("-" * 40 + "\n")
    f.write(f"  Total read syscalls:  {metrics['total_read_bytes']:,} bytes\n")
    f.write(f"  Total write syscalls: {metrics['total_write_bytes']:,} bytes\n")
    f.write(f"  Network I/O:          {metrics['network_bytes']:,} bytes\n")
    f.write(f"  Primary amplification: {syscall_amp:.2f}x\n\n")
    
    # Syscall breakdown
    f.write("SYSCALL BREAKDOWN:\n")
    f.write("-" * 40 + "\n")
    for syscall, count in sorted(metrics['syscall_counts'].items()):
        bytes_val = metrics['syscall_bytes'].get(syscall, 0)
        f.write(f"  {syscall:12} {count:6} calls, {bytes_val:12,} bytes\n")
    f.write(f"\n  Total fsync operations: {metrics['fsync_ops']}\n\n")
    
    # MinIO-specific patterns
    f.write("MINIO PATTERNS:\n")
    f.write("-" * 40 + "\n")
    f.write(f"  xl.meta operations:     {metrics['xl_meta_ops']}\n")
    f.write(f"  Part file operations:   {metrics['part_file_ops']}\n")
    f.write(f"  Unique xl.meta files:   {len(xl_meta_files)}\n")
    f.write(f"  Unique part files:      {len(part_files)}\n\n")
    
    # File access patterns
    if xl_meta_files or part_files:
        f.write("FILE ACCESS DETAILS:\n")
        f.write("-" * 40 + "\n")
        
        if xl_meta_files:
            f.write("  xl.meta files:\n")
            for path in xl_meta_files[:5]:
                ops = metrics['file_operations'][path]
                f.write(f"    {path[-50:]}\n")
                f.write(f"      Reads: {ops['reads']:,} bytes, Writes: {ops['writes']:,} bytes\n")
                
        if part_files:
            f.write("\n  Part files:\n")
            for path in part_files[:5]:
                ops = metrics['file_operations'][path]
                f.write(f"    {path[-50:]}\n")
                f.write(f"      Reads: {ops['reads']:,} bytes, Writes: {ops['writes']:,} bytes\n")
    
    # I/O Timeline sample
    if metrics['syscall_timeline']:
        f.write("\nI/O TIMELINE (first 20 operations):\n")
        f.write("-" * 40 + "\n")
        for entry in metrics['syscall_timeline'][:20]:
            f.write(f"  {entry['time']} {entry['call']:8} {entry['bytes']:8,} bytes ({entry['type']})\n")
    
    # Amplification summary
    f.write("\n" + "=" * 80 + "\n")
    f.write("AMPLIFICATION SUMMARY:\n")
    f.write("-" * 40 + "\n")
    f.write(f"  Object size:           {test_size:,} bytes\n")
    f.write(f"  Syscall I/O:           {primary_metric:,} bytes\n")
    f.write(f"  Syscall amplification: {syscall_amp:.2f}x\n")
    
    if metrics['xl_meta_ops'] > 0:
        metadata_overhead = metrics['xl_meta_ops'] * 4096  # Assume 4KB per metadata op
        f.write(f"  Estimated metadata overhead: {metadata_overhead:,} bytes\n")
        total_amp = (primary_metric + metadata_overhead) / test_size if test_size > 0 else 0
        f.write(f"  Total amplification (with metadata): {total_amp:.2f}x\n")

# Also output JSON for further processing
json_file = analysis_file.replace('.txt', '.json')
with open(json_file, 'w') as f:
    json.dump({
        'test_name': test_name,
        'test_size': test_size,
        'operation': operation,
        'total_read_bytes': metrics['total_read_bytes'],
        'total_write_bytes': metrics['total_write_bytes'],
        'syscall_amplification': syscall_amp,
        'xl_meta_ops': metrics['xl_meta_ops'],
        'part_file_ops': metrics['part_file_ops'],
        'fsync_ops': metrics['fsync_ops']
    }, f, indent=2)

print(f"Analysis complete: {analysis_file}")
PYTHON_SCRIPT
}

# Function to run a complete test
run_complete_test() {
    local size=$1
    local name=$2
    local operation=$3
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Testing $operation for $name ($size bytes)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Prepare test file for write
    if [ "$operation" = "write" ]; then
        echo "  Creating test file..."
        if [ "$size" -eq 1 ]; then
            echo -n "A" > /tmp/test_${name}.dat
        else
            dd if=/dev/zero of=/tmp/test_${name}.dat bs=1024 count=$((size/1024 + 1)) 2>/dev/null
            truncate -s $size /tmp/test_${name}.dat
        fi
    fi
    
    # Start eBPF tracer if available
    local ebpf_file="$RESULTS_DIR/$operation/ebpf/${name}_${operation}.ebpf"
    if [ -x "./build/minio_tracer" ]; then
        echo "  Starting eBPF tracer..."
        sudo ./build/minio_tracer -v -d $CAPTURE_DURATION > $ebpf_file 2>&1 &
        EBPF_PID=$!
    fi
    
    # Start syscall capture
    STRACE_PID=$(capture_syscalls $operation $name $size)
    
    # Perform operation
    echo -e "  ${CYAN}Performing $operation operation...${NC}"
    START_TIME=$(date +%s.%N)
    
    if [ "$operation" = "write" ]; then
        aws s3 cp /tmp/test_${name}.dat s3://${BUCKET}/syscall_test_${name} \
            --profile $PROFILE >/dev/null 2>&1
    else
        # Ensure object exists
        if ! aws s3 ls s3://${BUCKET}/syscall_test_${name} --profile $PROFILE >/dev/null 2>&1; then
            dd if=/dev/zero of=/tmp/temp.dat bs=$size count=1 2>/dev/null
            aws s3 cp /tmp/temp.dat s3://${BUCKET}/syscall_test_${name} \
                --profile $PROFILE >/dev/null 2>&1
            rm -f /tmp/temp.dat
            sleep 1
        fi
        
        aws s3 cp s3://${BUCKET}/syscall_test_${name} /tmp/downloaded_${name}.dat \
            --profile $PROFILE >/dev/null 2>&1
    fi
    
    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    echo "  Operation completed in ${DURATION}s"
    
    # Let I/O complete
    sleep 3
    
    # Stop tracers
    echo "  Stopping tracers..."
    if [ -n "$STRACE_PID" ]; then
        sudo kill -TERM $STRACE_PID 2>/dev/null || true
    fi
    if [ -n "$EBPF_PID" ]; then
        sudo kill -INT $EBPF_PID 2>/dev/null || true
    fi
    sleep 1
    
    # Check strace capture
    local strace_file="$RESULTS_DIR/$operation/strace/${name}_${operation}.strace"
    local line_count=$(wc -l < $strace_file 2>/dev/null || echo 0)
    echo "  Captured $line_count syscalls"
    
    # Analyze syscalls
    echo "  Analyzing syscalls..."
    local analysis_file="$RESULTS_DIR/$operation/analysis/${name}_${operation}_analysis.txt"
    analyze_syscalls "$strace_file" "$analysis_file" "$size" "$name" "$operation"
    
    # Show key metrics
    if [ -f "$analysis_file" ]; then
        echo -e "  ${GREEN}Key Metrics:${NC}"
        grep "Primary amplification:" "$analysis_file" | head -1
        grep "xl.meta operations:" "$analysis_file" | head -1
        grep "Part file operations:" "$analysis_file" | head -1
    fi
    
    # Parse eBPF results if available
    if [ -f "$ebpf_file" ]; then
        echo -e "  ${GREEN}eBPF Metrics:${NC}"
        grep "TOTAL AMPLIFICATION:" "$ebpf_file" 2>/dev/null | head -1 || echo "    No amplification data"
        grep "Device layer:" "$ebpf_file" 2>/dev/null | head -1 || echo "    No device data"
    fi
    
    # Cleanup
    sudo rm -f /tmp/test_${name}.dat /tmp/downloaded_${name}.dat
    
    echo -e "  ${GREEN}✓ Test complete${NC}"
}

# Function to generate summary report
generate_summary() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}GENERATING SUMMARY REPORT${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Create CSV summary
    local csv_file="$RESULTS_DIR/amplification_summary.csv"
    echo "Size,Write_Syscall_Bytes,Write_Amplification,Read_Syscall_Bytes,Read_Amplification,xl.meta_Ops,Part_Files" > $csv_file
    
    for i in ${!SIZES[@]}; do
        name=${NAMES[$i]}
        size=${SIZES[$i]}
        
        # Parse JSON files for metrics
        write_json="$RESULTS_DIR/write/analysis/${name}_write_analysis.json"
        read_json="$RESULTS_DIR/read/analysis/${name}_read_analysis.json"
        
        if [ -f "$write_json" ] && [ -f "$read_json" ]; then
            write_bytes=$(python3 -c "import json; print(json.load(open('$write_json'))['total_write_bytes'])")
            write_amp=$(python3 -c "import json; print(json.load(open('$write_json'))['syscall_amplification'])")
            read_bytes=$(python3 -c "import json; print(json.load(open('$read_json'))['total_read_bytes'])")
            read_amp=$(python3 -c "import json; print(json.load(open('$read_json'))['syscall_amplification'])")
            xl_meta=$(python3 -c "import json; print(json.load(open('$write_json'))['xl_meta_ops'])")
            part_files=$(python3 -c "import json; print(json.load(open('$write_json'))['part_file_ops'])")
            
            echo "$name,$write_bytes,$write_amp,$read_bytes,$read_amp,$xl_meta,$part_files" >> $csv_file
        fi
    done
    
    echo ""
    echo "Amplification Summary:"
    column -t -s',' $csv_file
    
    # Create detailed summary report
    local summary_file="$RESULTS_DIR/detailed_summary.txt"
    {
        echo "=========================================================================="
        echo "COMPREHENSIVE SYSCALL AND I/O ANALYSIS SUMMARY"
        echo "=========================================================================="
        echo ""
        echo "Test Date: $(date)"
        echo "Results Directory: $RESULTS_DIR"
        echo ""
        
        for i in ${!SIZES[@]}; do
            name=${NAMES[$i]}
            size=${SIZES[$i]}
            
            echo "──────────────────────────────────────────────────────────────────────"
            echo "$name ($size bytes)"
            echo "──────────────────────────────────────────────────────────────────────"
            
            # Include both write and read analysis
            for op in write read; do
                analysis="$RESULTS_DIR/$op/analysis/${name}_${op}_analysis.txt"
                if [ -f "$analysis" ]; then
                    echo ""
                    echo "${op^^} Operation:"
                    grep -A3 "I/O SUMMARY:" "$analysis" | tail -4
                    grep "xl.meta operations:" "$analysis"
                    grep "Part file operations:" "$analysis"
                fi
            done
            echo ""
        done
    } > $summary_file
    
    echo ""
    echo "Detailed summary saved to: $summary_file"
}

# Main execution
echo ""
echo "Starting comprehensive analysis..."

# Run all write tests
echo ""
echo -e "${CYAN}PHASE 1: WRITE OPERATIONS${NC}"
for i in ${!SIZES[@]}; do
    run_complete_test ${SIZES[$i]} ${NAMES[$i]} "write"
done

# Run all read tests
echo ""
echo -e "${CYAN}PHASE 2: READ OPERATIONS${NC}"
for i in ${!SIZES[@]}; do
    run_complete_test ${SIZES[$i]} ${NAMES[$i]} "read"
done

# Generate summary
generate_summary

# Cleanup S3 objects
echo ""
echo "Cleaning up S3 test objects..."
for name in ${NAMES[@]}; do
    aws s3 rm s3://${BUCKET}/syscall_test_${name} --profile $PROFILE 2>/dev/null || true
done

# Final output
echo ""
echo "=========================================================================="
echo -e "${GREEN}COMPREHENSIVE ANALYSIS COMPLETE!${NC}"
echo "=========================================================================="
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo ""
echo "Key files:"
echo "  • Syscall traces: $RESULTS_DIR/{write,read}/strace/"
echo "  • Analysis reports: $RESULTS_DIR/{write,read}/analysis/"
echo "  • Summary CSV: $RESULTS_DIR/amplification_summary.csv"
echo "  • Detailed report: $RESULTS_DIR/detailed_summary.txt"
echo ""
echo "To examine specific results:"
echo "  less $RESULTS_DIR/write/strace/1KB_write.strace"
echo "  cat $RESULTS_DIR/write/analysis/1KB_write_analysis.txt"
echo "  python3 -m json.tool $RESULTS_DIR/write/analysis/1KB_write_analysis.json"
echo "=========================================================================="

# Cleanup trap
trap 'sudo rm -f /tmp/test_*.dat /tmp/downloaded_*.dat' EXIT
