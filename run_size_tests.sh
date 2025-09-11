#!/bin/bash

SIZES=(1 10 100 1000 10485760)
NAMES=("1B" "10B" "100B" "1KB" "10MB")

echo "====================================="
echo "MinIO I/O Breakdown Test Suite"
echo "====================================="

for i in ${!SIZES[@]}; do
    SIZE=${SIZES[$i]}
    NAME=${NAMES[$i]}
    LOGFILE="minio_${NAME}_analysis.log"
    
    echo ""
    echo "Testing $NAME object..."
    echo "------------------------"
    
    # Start tracer for 15 seconds
    echo "Starting tracer..."
    sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 15 -o $LOGFILE 2>&1 > /dev/null &
    TRACER_PID=$!
    
    # Wait for tracer to initialize
    sleep 2
    
    # Run single test
    ./test_single_object.sh $SIZE test_${NAME}.dat
    
    # Wait for tracer to complete
    wait $TRACER_PID
    
    echo "Trace complete. Log saved to $LOGFILE"
    
    # Extract key metrics
    echo "Quick summary:"
    grep "TOTAL AMPLIFICATION" $LOGFILE | tail -1
    echo ""
    
    # Small delay between tests
    sleep 3
done

echo "====================================="
echo "All tests complete!"
echo "====================================="
echo ""
echo "Log files created:"
for NAME in "${NAMES[@]}"; do
    echo "  - minio_${NAME}_analysis.log"
done
