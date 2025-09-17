#!/bin/bash

# Diagnostic script for MinIO tracer
# File: diagnose_minio_tracer.sh

echo "======================================================================="
echo "MinIO Tracer Diagnostic"
echo "======================================================================="

# Check if MinIO is running
echo "1. Checking if MinIO is running..."
if pgrep -x "minio" > /dev/null; then
    echo "   ✓ MinIO process found"
    echo "   MinIO PIDs:"
    pgrep -x "minio" | while read pid; do
        echo "     - PID $pid: $(ps -p $pid -o comm= -o args=)"
    done
else
    echo "   ✗ MinIO is not running!"
    echo "   Please start MinIO first."
fi

echo ""
echo "2. Checking BPF capabilities..."
if [ -f /sys/kernel/debug/tracing/trace ]; then
    echo "   ✓ Tracing subsystem available"
else
    echo "   ✗ Tracing subsystem not available"
fi

if [ -d /sys/fs/bpf ]; then
    echo "   ✓ BPF filesystem mounted"
else
    echo "   ✗ BPF filesystem not mounted"
fi

echo ""
echo "3. Checking for existing BPF programs..."
sudo bpftool prog list | grep -E "minio|multilayer" | head -5

echo ""
echo "4. Testing BPF attachment points..."

# Check if tracepoints exist
echo "   Checking syscall tracepoints..."
if [ -d /sys/kernel/debug/tracing/events/syscalls/sys_enter_write ]; then
    echo "   ✓ sys_enter_write tracepoint exists"
else
    echo "   ✗ sys_enter_write tracepoint missing"
fi

if [ -d /sys/kernel/debug/tracing/events/syscalls/sys_enter_read ]; then
    echo "   ✓ sys_enter_read tracepoint exists"
else
    echo "   ✗ sys_enter_read tracepoint missing"
fi

# Check if kprobes work
echo ""
echo "   Checking kprobe availability..."
if grep -q "kprobe" /proc/kallsyms 2>/dev/null; then
    echo "   ✓ Kprobes available"
else
    echo "   ✗ Kprobes not available"
fi

echo ""
echo "5. Testing original multilayer tracer..."
if [ -f "./build/multilayer_io_tracer" ]; then
    echo "   Starting original tracer for 3 seconds..."
    timeout 3 sudo ./build/multilayer_io_tracer -M -v 2>&1 | head -20
    echo "   Original tracer test complete"
else
    echo "   Original tracer not found"
fi

echo ""
echo "6. Testing new MinIO tracer..."
if [ -f "./build/minio_tracer" ]; then
    echo "   Starting MinIO tracer for 3 seconds..."
    timeout 3 sudo ./build/minio_tracer -v 2>&1 | head -20
    echo "   MinIO tracer test complete"
else
    echo "   MinIO tracer not found"
fi

echo ""
echo "7. Checking for trace output..."
echo "   Running a quick MinIO operation test..."

# Create test file
echo "test" > /tmp/trace_test.dat

# Start tracer in background
if [ -f "./build/minio_tracer" ]; then
    sudo ./build/minio_tracer -v > /tmp/tracer_output.log 2>&1 &
    TRACER_PID=$!
elif [ -f "./build/multilayer_io_tracer" ]; then
    sudo ./build/multilayer_io_tracer -M -v > /tmp/tracer_output.log 2>&1 &
    TRACER_PID=$!
else
    echo "   No tracer available!"
    exit 1
fi

sleep 2

# Do a MinIO operation
echo "   Performing MinIO S3 operation..."
aws s3 cp /tmp/trace_test.dat s3://public/diagnostic_test.dat --profile minio 2>/dev/null

sleep 2

# Stop tracer
sudo kill -INT $TRACER_PID 2>/dev/null
sleep 1
sudo kill -KILL $TRACER_PID 2>/dev/null

# Check output
echo ""
echo "   Tracer output analysis:"
echo "   - Total lines: $(wc -l < /tmp/tracer_output.log)"
echo "   - MinIO mentions: $(grep -c -i minio /tmp/tracer_output.log)"
echo "   - PUT operations: $(grep -c "PUT\|WRITE" /tmp/tracer_output.log)"
echo "   - Application layer events: $(grep -c "APPLICATION" /tmp/tracer_output.log)"

echo ""
echo "   First 10 lines of output:"
head -10 /tmp/tracer_output.log

# Cleanup
rm -f /tmp/trace_test.dat /tmp/tracer_output.log

echo ""
echo "======================================================================="
echo "Diagnostic Complete"
echo "======================================================================="
echo ""
echo "Recommendations:"
echo "----------------"

if ! pgrep -x "minio" > /dev/null; then
    echo "• Start MinIO server first"
fi

if [ ! -f "./build/minio_tracer" ]; then
    echo "• Build the MinIO tracer: make minio"
fi

echo "• Ensure you're running with sudo"
echo "• Check that MinIO process name is exactly 'minio'"
echo ""
echo "If the tracer isn't capturing events, try:"
echo "1. Using the original tracer: sudo ./build/multilayer_io_tracer -M -v"
echo "2. Checking dmesg for BPF errors: sudo dmesg | tail -20"
echo "3. Verifying MinIO process name: ps aux | grep minio"
