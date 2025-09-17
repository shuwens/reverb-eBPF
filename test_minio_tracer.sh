#!/bin/bash

# Test script for MinIO tracer with both GET and PUT operations
# File: test_minio_tracer.sh

SIZES=(1 10 100 1000 10485760)
NAMES=("1B" "10B" "100B" "1KB" "10MB")
BUCKET="public"
PROFILE="minio"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================="
echo "MinIO I/O Test with Request Correlation Tracking"
echo "======================================================================="

# Check if the tracer exists
if [ ! -f "./build/minio_tracer" ]; then
    echo -e "${RED}Error: minio_tracer not found. Please run 'make minio' first.${NC}"
    exit 1
fi

# Function to test PUT operation
test_put_operation() {
    local SIZE=$1
    local NAME=$2
    local LOGFILE="minio_${NAME}_put.log"
    
    echo -e "${GREEN}Testing PUT operation for $NAME object...${NC}"
    echo "-----------------------"
    
    # Start MinIO tracer
    echo "Starting MinIO tracer..."
    sudo ./build/minio_tracer -v -d 20 -o $LOGFILE &
    TRACER_PID=$!
    
    # Wait for tracer initialization
    sleep 2
    
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
    
    # Upload to MinIO
    echo -e "${YELLOW}Uploading test_${NAME}.dat to MinIO...${NC}"
    aws s3 cp test_${NAME}.dat s3://${BUCKET}/tracer_test_${NAME}/test.dat --profile $PROFILE
    
    # Force filesystem sync
    sync
    
    # Wait for I/O to complete
    sleep 2
    
    # Stop tracer gracefully
    echo "Stopping tracer..."
    sudo kill -INT $TRACER_PID 2>/dev/null
    
    # Wait for tracer to finish with timeout
    WAIT_COUNT=0
    while kill -0 $TRACER_PID 2>/dev/null; do
        sleep 0.5
        WAIT_COUNT=$((WAIT_COUNT + 1))
        if [ $WAIT_COUNT -gt 10 ]; then
            echo "Force stopping tracer..."
            sudo kill -TERM $TRACER_PID 2>/dev/null
            sleep 1
            sudo kill -KILL $TRACER_PID 2>/dev/null
            break
        fi
    done
    
    # Clean up local file
    rm -f test_${NAME}.dat
    
    echo -e "${GREEN}PUT test complete for $NAME${NC}"
    echo ""
}

# Function to test GET operation
test_get_operation() {
    local NAME=$1
    local LOGFILE="minio_${NAME}_get.log"
    
    echo -e "${GREEN}Testing GET operation for $NAME object...${NC}"
    echo "-----------------------"
    
    # Start MinIO tracer
    echo "Starting MinIO tracer..."
    sudo ./build/minio_tracer -v -d 20 -o $LOGFILE &
    TRACER_PID=$!
    
    # Wait for tracer initialization
    sleep 2
    
    # Download from MinIO
    echo -e "${YELLOW}Downloading test.dat from MinIO...${NC}"
    aws s3 cp s3://${BUCKET}/tracer_test_${NAME}/test.dat downloaded_${NAME}.dat --profile $PROFILE
    
    # Wait for I/O to complete
    sleep 3
    
    # Stop tracer
    sudo kill -INT $TRACER_PID 2>/dev/null
    wait $TRACER_PID 2>/dev/null
    
    # Clean up downloaded file
    rm -f downloaded_${NAME}.dat
    
    echo -e "${GREEN}GET test complete for $NAME${NC}"
    echo ""
}

# Function to test both PUT and GET with correlation
test_put_get_correlation() {
    local SIZE=$1
    local NAME=$2
    local LOGFILE="minio_${NAME}_correlation.log"
    
    echo -e "${GREEN}Testing PUT+GET correlation for $NAME object...${NC}"
    echo "-----------------------"
    
    # Start MinIO tracer with correlation enabled
    echo "Starting MinIO tracer with correlation..."
    sudo ./build/minio_tracer -v -c -d 30 -o $LOGFILE &
    TRACER_PID=$!
    
    # Wait for tracer initialization
    sleep 2
    
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
    
    # Perform PUT operation
    echo -e "${YELLOW}[PUT] Uploading test_${NAME}.dat...${NC}"
    aws s3 cp test_${NAME}.dat s3://${BUCKET}/correlation_test_${NAME}/test.dat --profile $PROFILE
    
    # Small delay
    sleep 2
    
    # Perform GET operation
    echo -e "${YELLOW}[GET] Downloading test.dat...${NC}"
    aws s3 cp s3://${BUCKET}/correlation_test_${NAME}/test.dat downloaded_${NAME}.dat --profile $PROFILE
    
    # Wait for I/O to complete
    sleep 5
    
    # Stop tracer
    sudo kill -INT $TRACER_PID 2>/dev/null
    wait $TRACER_PID 2>/dev/null
    
    # Clean up
    rm -f test_${NAME}.dat downloaded_${NAME}.dat
    
    echo -e "${GREEN}Correlation test complete for $NAME${NC}"
    echo ""
}

# Function to analyze results
analyze_results() {
    echo ""
    echo "======================================================================="
    echo "Analyzing Results"
    echo "======================================================================="
    
    for NAME in "${NAMES[@]}"; do
        echo ""
        echo "Analysis for $NAME:"
        echo "-------------------"
        
        # Analyze PUT operations
        if [ -f "minio_${NAME}_put.log" ]; then
            echo "PUT Operation:"
            grep "TOTAL AMPLIFICATION" "minio_${NAME}_put.log" | tail -1
            grep "Total PUT operations" "minio_${NAME}_put.log" | tail -1
            echo ""
        fi
        
        # Analyze GET operations
        if [ -f "minio_${NAME}_get.log" ]; then
            echo "GET Operation:"
            grep "TOTAL AMPLIFICATION" "minio_${NAME}_get.log" | tail -1
            grep "Total GET operations" "minio_${NAME}_get.log" | tail -1
            echo ""
        fi
        
        # Analyze correlation
        if [ -f "minio_${NAME}_correlation.log" ]; then
            echo "Correlation Analysis:"
            grep "REQUEST FLOWS" "minio_${NAME}_correlation.log" -A 20 | head -10
        fi
    done
}

# Main execution
echo "Select test mode:"
echo "1) PUT operations only"
echo "2) GET operations only"
echo "3) PUT+GET with correlation"
echo "4) All tests"
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        for i in ${!SIZES[@]}; do
            test_put_operation ${SIZES[$i]} ${NAMES[$i]}
        done
        ;;
    2)
        # First ensure objects exist
        echo "Ensuring test objects exist in MinIO..."
        for i in ${!SIZES[@]}; do
            SIZE=${SIZES[$i]}
            NAME=${NAMES[$i]}
            
            # Create and upload if not exists
            if ! aws s3 ls s3://${BUCKET}/tracer_test_${NAME}/test.dat --profile $PROFILE 2>/dev/null; then
                echo "Creating $NAME test object..."
                if [ "$SIZE" = "1" ]; then
                    echo -n "A" > temp_${NAME}.dat
                elif [ "$SIZE" = "10" ]; then
                    echo -n "0123456789" > temp_${NAME}.dat
                elif [ "$SIZE" = "100" ]; then
                    dd if=/dev/zero of=temp_${NAME}.dat bs=1 count=100 2>/dev/null
                elif [ "$SIZE" = "1000" ]; then
                    dd if=/dev/zero of=temp_${NAME}.dat bs=1 count=1000 2>/dev/null
                else
                    dd if=/dev/zero of=temp_${NAME}.dat bs=1M count=10 2>/dev/null
                fi
                aws s3 cp temp_${NAME}.dat s3://${BUCKET}/tracer_test_${NAME}/test.dat --profile $PROFILE
                rm -f temp_${NAME}.dat
            fi
        done
        
        # Now run GET tests
        for i in ${!SIZES[@]}; do
            test_get_operation ${NAMES[$i]}
        done
        ;;
    3)
        for i in ${!SIZES[@]}; do
            test_put_get_correlation ${SIZES[$i]} ${NAMES[$i]}
        done
        ;;
    4)
        # Run all tests
        echo "Running all tests..."
        for i in ${!SIZES[@]}; do
            test_put_operation ${SIZES[$i]} ${NAMES[$i]}
            test_get_operation ${NAMES[$i]}
            test_put_get_correlation ${SIZES[$i]} ${NAMES[$i]}
        done
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Analyze all results
analyze_results

echo ""
echo "======================================================================="
echo "Test Complete!"
echo "Log files generated:"
ls -lh minio_*.log 2>/dev/null
echo "======================================================================="

