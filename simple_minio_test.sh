#!/bin/bash

# Simple test script for MinIO tracer debugging
# File: simple_minio_test.sh

BUCKET="public"
PROFILE="minio"

echo "======================================================================="
echo "Simple MinIO Tracer Test"
echo "======================================================================="

# Check if we're using the old or new tracer
if [ -f "./build/minio_tracer" ]; then
    TRACER="./build/minio_tracer"
    echo "Using new MinIO-specific tracer"
elif [ -f "./build/multilayer_io_tracer" ]; then
    TRACER="./build/multilayer_io_tracer"
    echo "Using original multilayer tracer"
    # Add MinIO-specific flags for the old tracer
    TRACER_FLAGS="-M -c -E -T"
else
    echo "Error: No tracer found. Please build first."
    exit 1
fi

echo ""
echo "Starting tracer in background..."

if [ "$TRACER" = "./build/minio_tracer" ]; then
    # New MinIO tracer
    sudo $TRACER -v 2>&1 | tee minio_test.log &
else
    # Old tracer with MinIO flags
    sudo $TRACER $TRACER_FLAGS -v 2>&1 | tee minio_test.log &
fi

TRACER_PID=$!

# Check if tracer started successfully
sleep 2
if ! kill -0 $TRACER_PID 2>/dev/null; then
    echo "Error: Tracer failed to start. Check the log."
    exit 1
fi

echo "Tracer started with PID: $TRACER_PID"
echo ""

# Create a small test file
echo "Creating test file..."
echo "Hello MinIO" > test_simple.dat
ls -la test_simple.dat

echo ""
echo "Uploading to MinIO (this will trigger PUT operation)..."
aws s3 cp test_simple.dat s3://${BUCKET}/simple_test/test.dat --profile $PROFILE

echo ""
echo "Waiting for I/O to settle..."
sleep 2

echo ""
echo "Downloading from MinIO (this will trigger GET operation)..."
aws s3 cp s3://${BUCKET}/simple_test/test.dat downloaded.dat --profile $PROFILE

echo ""
echo "Verifying download..."
cat downloaded.dat

echo ""
echo "Waiting for final I/O..."
sleep 2

echo ""
echo "Stopping tracer..."
sudo kill -INT $TRACER_PID 2>/dev/null

# Give it time to print summary
sleep 2

# Force kill if still running
if kill -0 $TRACER_PID 2>/dev/null; then
    echo "Force stopping tracer..."
    sudo kill -TERM $TRACER_PID 2>/dev/null
    sleep 1
    sudo kill -KILL $TRACER_PID 2>/dev/null
fi

echo ""
echo "======================================================================="
echo "Test Complete!"
echo "======================================================================="
echo ""
echo "Checking for MinIO operations in log..."
echo "PUT operations:"
grep -c "MINIO_OBJECT_PUT\|MINIO_PUT" minio_test.log || echo "No PUT operations found"
echo "GET operations:"
grep -c "MINIO_OBJECT_GET\|MINIO_GET" minio_test.log || echo "No GET operations found"
echo ""
echo "First 10 MinIO-related lines:"
grep -i minio minio_test.log | head -10

echo ""
echo "Log saved to: minio_test.log"
echo "Cleaning up test files..."
rm -f test_simple.dat downloaded.dat

echo "Done!"
