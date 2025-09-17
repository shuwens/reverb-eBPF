#!/bin/bash

# Script to fix the infinite loop issue and test safely
# File: fix_and_test.sh

echo "======================================================================="
echo "Fixing MinIO Tracer Issues"
echo "======================================================================="

# Step 1: Kill any stuck tracer processes
echo "1. Killing stuck tracer processes..."
sudo pkill -f "minio_tracer"
sudo pkill -f "multilayer_io_tracer"
sleep 2

# Check if any are still running
if pgrep -f "minio_tracer" > /dev/null; then
    echo "   Force killing remaining processes..."
    sudo pkill -9 -f "minio_tracer"
fi

echo "   All tracer processes stopped."

# Step 2: Use the working original tracer instead
echo ""
echo "2. Using the original working tracer with MinIO flags..."
echo ""

BUCKET="public"
PROFILE="minio"

# Create a test file
echo "Test data" > test_file.dat

echo "Starting the working tracer (original multilayer_io_tracer)..."
echo "This tracer has been proven to work from your test_with_journal_tracking.sh"
echo ""

# Use the original tracer with MinIO-specific flags
# -M: MinIO mode
# -c: correlation mode  
# -E: trace erasure
# -T: trace metadata
sudo ./build/multilayer_io_tracer -M -c -E -T 2>&1 | head -1000 > tracer_output.log &
TRACER_PID=$!

# Give tracer time to initialize
sleep 2

# Check if tracer is running
if ! kill -0 $TRACER_PID 2>/dev/null; then
    echo "Error: Tracer failed to start"
    exit 1
fi

echo "Tracer started successfully (PID: $TRACER_PID)"
echo ""

# Step 3: Perform MinIO operations
echo "3. Performing MinIO operations..."
echo ""

echo "Uploading file to MinIO..."
aws s3 cp test_file.dat s3://${BUCKET}/test_safe/test.dat --profile $PROFILE

echo "Waiting for I/O to settle..."
sleep 2

echo "Downloading file from MinIO..."
aws s3 cp s3://${BUCKET}/test_safe/test.dat downloaded.dat --profile $PROFILE

echo "Operations complete."
sleep 2

# Step 4: Stop tracer gracefully
echo ""
echo "4. Stopping tracer..."
sudo kill -INT $TRACER_PID 2>/dev/null

# Wait up to 5 seconds for graceful shutdown
WAIT_COUNT=0
while kill -0 $TRACER_PID 2>/dev/null && [ $WAIT_COUNT -lt 10 ]; do
    sleep 0.5
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if kill -0 $TRACER_PID 2>/dev/null; then
    echo "   Force stopping tracer..."
    sudo kill -TERM $TRACER_PID 2>/dev/null
    sleep 1
    sudo kill -KILL $TRACER_PID 2>/dev/null
fi

echo "   Tracer stopped."

# Step 5: Analyze results
echo ""
echo "5. Analyzing trace results..."
echo "======================================================================="

echo "Summary of captured events:"
echo "   Total lines: $(wc -l < tracer_output.log)"
echo "   MinIO events: $(grep -c "MINIO" tracer_output.log || echo 0)"
echo "   PUT operations: $(grep -c "PUT" tracer_output.log || echo 0)"
echo "   GET operations: $(grep -c "GET" tracer_output.log || echo 0)"
echo "   VFS operations: $(grep -c "VFS" tracer_output.log || echo 0)"
echo "   Device I/O: $(grep -c "DEV_BIO" tracer_output.log || echo 0)"

echo ""
echo "Sample of MinIO operations:"
grep "MINIO" tracer_output.log | head -10

echo ""
echo "Sample of correlation IDs:"
grep "REQ:" tracer_output.log | head -5

# Cleanup
rm -f test_file.dat downloaded.dat

echo ""
echo "======================================================================="
echo "Test Complete!"
echo "Full trace log saved to: tracer_output.log"
echo ""
echo "To view the full log:"
echo "  less tracer_output.log"
echo ""
echo "To see amplification analysis:"
echo "  grep 'AMPLIFICATION' tracer_output.log"
echo "======================================================================="
