#!/bin/bash

SIZES=(1 10 100 1000 10485760)
NAMES=("1B" "10B" "100B" "1KB" "10MB")
BUCKET="public"
PROFILE="minio"

echo "======================================================================="
echo "MinIO I/O Test with Journal Tracking"
echo "======================================================================="

for i in ${!SIZES[@]}; do
    SIZE=${SIZES[$i]}
    NAME=${NAMES[$i]}
    LOGFILE="minio_${NAME}_journal.log"
    
    echo ""
    echo "Testing $NAME object..."
    echo "-----------------------"
    
    # Start tracer with enhanced output
    echo "Starting tracer with journal tracking..."
    sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 20 2>&1 | tee $LOGFILE &
    TRACER_PID=$!
    
    # Monitor journal activity in parallel
    sudo bash -c "while kill -0 $TRACER_PID 2>/dev/null; do 
        cat /proc/diskstats | grep -E 'nvme1n1|nvme3n1' >> diskstats_${NAME}.log
        sleep 0.5
    done" &
    DISK_PID=$!
    
    # Wait for tracer initialization
    sleep 3
    
    # Create test file
    if [ "$SIZE" = "1" ]; then
        echo -n "A" > test_${NAME}.dat
    elif [ "$SIZE" = "10" ]; then
        echo -n "0123456789" > test_${NAME}.dat
    elif [ "$SIZE" = "100" ]; then
        dd if=/dev/zero of=test_${NAME}.dat bs=1 count=100 2>/dev/null
    elif [ "$SIZE" = "1000" ]; then
        dd if=/dev/zero of=test_${NAME}.dat bs=1 count=1000 2>/dev/null
    else
        dd if=/dev/zero of=test_${NAME}.dat bs=1M count=10 2>/dev/null
    fi
    
    # Upload with sync to force journal flush
    aws s3 cp test_${NAME}.dat s3://${BUCKET}/journal_test_${NAME}/test.dat --profile $PROFILE
    sync  # Force filesystem sync
    
    # Wait for I/O to complete
    sleep 5
    
    # Stop tracers
    sudo kill $TRACER_PID 2>/dev/null
    sudo kill $DISK_PID 2>/dev/null
    wait $TRACER_PID 2>/dev/null
    
    # Clean up
    rm -f test_${NAME}.dat
    
    echo "Test complete for $NAME"
done

echo ""
echo "======================================================================="
echo "Analyzing results..."
echo "======================================================================="
