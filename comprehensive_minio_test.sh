#!/bin/bash

# Comprehensive MinIO I/O Test Script with Multiple Object Sizes
# File: comprehensive_minio_test.sh

# Test configuration
SIZES=(1 10 100 1024 10240 102400 1048576 10485760 104857600)
NAMES=("1B" "10B" "100B" "1KB" "10KB" "100KB" "1MB" "10MB" "100MB")
BUCKET="public"
PROFILE="minio"
TRACER_DURATION=30  # Increased for larger files

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Results directory
RESULTS_DIR="minio_test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR

echo "======================================================================="
echo "Comprehensive MinIO I/O Analysis Test"
echo "Testing sizes: ${NAMES[@]}"
echo "Results will be saved to: $RESULTS_DIR"
echo "======================================================================="

# Function to analyze a single log file
analyze_log() {
    local logfile=$1
    local name=$2
    local size=$3
    
    echo "Analyzing $name..."
    
    # Count different types of operations
    local total_lines=$(wc -l < $logfile)
    local app_puts=$(grep -c "APPLICATION.*MINIO_OBJECT_PUT" $logfile || echo 0)
    local app_gets=$(grep -c "APPLICATION.*MINIO_OBJECT_GET" $logfile || echo 0)
    local metadata_ops=$(grep -c "MINIO_XL_META" $logfile || echo 0)
    local fs_syncs=$(grep -c "FS_SYNC" $logfile || echo 0)
    local bio_submits=$(grep -c "DEV_BIO_SUBMIT" $logfile || echo 0)
    local bio_completes=$(grep -c "DEV_BIO_COMPLETE" $logfile || echo 0)
    
    # Calculate I/O sizes
    local data_io=$(grep "MINIO_OBJECT_PUT\|MINIO_OBJECT_GET" $logfile | \
                    awk '{sum+=$4} END {print sum}' || echo 0)
    local os_io=$(grep "OS_VFS" $logfile | \
                  awk '{sum+=$5} END {print sum}' || echo 0)
    local device_io=$(grep "DEV_BIO_SUBMIT" $logfile | \
                      awk '{sum+=$4} END {print sum}' || echo 0)
    
    # Calculate amplification
    local amplification=0
    if [ "$size" -gt 0 ] && [ "$device_io" -gt 0 ]; then
        amplification=$(echo "scale=2; $device_io / $size" | bc)
    fi
    
    # Extract latency information
    local avg_latency=$(grep "DEV_BIO_COMPLETE" $logfile | \
                        awk '{sum+=$6; count++} END {if(count>0) print sum/count; else print 0}')
    
    # Save analysis results
    cat > "$RESULTS_DIR/${name}_analysis.txt" << EOF
================================================================================
Analysis for $name ($size bytes)
================================================================================

I/O OPERATIONS COUNT:
---------------------
Application PUT operations:  $app_puts
Application GET operations:  $app_gets
Metadata operations:         $metadata_ops
Filesystem syncs:           $fs_syncs
Device BIO submits:         $bio_submits
Device BIO completes:       $bio_completes

I/O SIZES:
----------
Original size:              $size bytes
Application layer I/O:      $data_io bytes
OS layer I/O:              $os_io bytes
Device layer I/O:          $device_io bytes
Amplification:             ${amplification}x

LATENCY:
--------
Average device latency:     ${avg_latency}μs

I/O CATEGORIZATION:
-------------------
EOF
    
    # Calculate data/metadata/journal distribution
    local journal_io=$((fs_syncs * 4096))
    local metadata_io=$((metadata_ops * 4096))
    local pure_data_io=$((device_io - journal_io - metadata_io))
    
    if [ "$device_io" -gt 0 ]; then
        local data_percent=$(echo "scale=1; $pure_data_io * 100 / $device_io" | bc)
        local metadata_percent=$(echo "scale=1; $metadata_io * 100 / $device_io" | bc)
        local journal_percent=$(echo "scale=1; $journal_io * 100 / $device_io" | bc)
        
        cat >> "$RESULTS_DIR/${name}_analysis.txt" << EOF
Data I/O:                  $pure_data_io bytes (${data_percent}%)
Metadata I/O:              $metadata_io bytes (${metadata_percent}%)
Journal I/O:               $journal_io bytes (${journal_percent}%)

SUMMARY:
--------
Total device I/O for ${size}B object: $device_io bytes
Total amplification: ${amplification}x
EOF
    fi
    
    echo "Analysis saved to $RESULTS_DIR/${name}_analysis.txt"
}

# Function to run test for a single size
run_test() {
    local size=$1
    local name=$2
    local logfile="$RESULTS_DIR/${name}_trace.log"
    
    echo ""
    echo -e "${GREEN}Testing $name object ($size bytes)...${NC}"
    echo "======================================="
    
    # Adjust tracer duration for large files
    local duration=$TRACER_DURATION
    if [ "$size" -gt 10485760 ]; then
        duration=60  # 60 seconds for files > 10MB
    fi
    
    # Start the tracer
    echo "Starting tracer (duration: ${duration}s)..."
    sudo ./build/multilayer_io_tracer -M -c -E -T -v -d $duration 2>&1 | \
         tee $logfile > /dev/null &
    TRACER_PID=$!
    
    # Wait for tracer to initialize
    sleep 3
    
    # Create test file
    echo "Creating test file..."
    if [ "$size" -eq 1 ]; then
        echo -n "A" > test_${name}.dat
    elif [ "$size" -lt 100 ]; then
        head -c $size /dev/urandom > test_${name}.dat 2>/dev/null || \
        dd if=/dev/zero of=test_${name}.dat bs=1 count=$size 2>/dev/null
    else
        dd if=/dev/zero of=test_${name}.dat bs=1 count=$size 2>/dev/null
    fi
    
    # Verify file size
    actual_size=$(stat -c%s test_${name}.dat)
    echo "Created file size: $actual_size bytes"
    
    # PUT operation
    echo -e "${YELLOW}Performing PUT operation...${NC}"
    aws s3 cp test_${name}.dat s3://${BUCKET}/comprehensive_test_${name}/test.dat \
        --profile $PROFILE
    
    # Wait for I/O to settle
    sleep 3
    
    # GET operation
    echo -e "${YELLOW}Performing GET operation...${NC}"
    aws s3 cp s3://${BUCKET}/comprehensive_test_${name}/test.dat \
        downloaded_${name}.dat --profile $PROFILE
    
    # Verify download
    if [ -f "downloaded_${name}.dat" ]; then
        downloaded_size=$(stat -c%s downloaded_${name}.dat)
        echo "Downloaded file size: $downloaded_size bytes"
        if [ "$actual_size" -eq "$downloaded_size" ]; then
            echo -e "${GREEN}✓ Size verification passed${NC}"
        else
            echo -e "${RED}✗ Size mismatch!${NC}"
        fi
    fi
    
    # Wait for final I/O
    sleep 3
    
    # Stop tracer gracefully
    echo "Stopping tracer..."
    sudo kill -INT $TRACER_PID 2>/dev/null
    
    # Wait for tracer to finish (with timeout)
    WAIT_COUNT=0
    while kill -0 $TRACER_PID 2>/dev/null && [ $WAIT_COUNT -lt 20 ]; do
        sleep 0.5
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done
    
    if kill -0 $TRACER_PID 2>/dev/null; then
        echo "Force stopping tracer..."
        sudo kill -TERM $TRACER_PID 2>/dev/null
        sleep 1
        sudo kill -KILL $TRACER_PID 2>/dev/null
    fi
    
    # Clean up test files
    rm -f test_${name}.dat downloaded_${name}.dat
    
    # Analyze the log
    analyze_log $logfile $name $size
    
    echo -e "${GREEN}Test complete for $name${NC}"
}

# Main execution
echo ""
echo "Starting comprehensive test suite..."

# Run tests for all sizes
for i in ${!SIZES[@]}; do
    run_test ${SIZES[$i]} ${NAMES[$i]}
    echo ""
    echo "----------------------------------------------------------------------"
done

# Generate summary report
echo ""
echo "======================================================================="
echo -e "${BLUE}Generating Summary Report...${NC}"
echo "======================================================================="

cat > "$RESULTS_DIR/summary_report.txt" << EOF
================================================================================
MinIO I/O Amplification Test Summary
Date: $(date)
================================================================================

Object Size    Amplification    Data %    Metadata %    Journal %    Device I/O
-----------    -------------    ------    ----------    ---------    ----------
EOF

# Collect summary data
for name in "${NAMES[@]}"; do
    if [ -f "$RESULTS_DIR/${name}_analysis.txt" ]; then
        # Extract key metrics from analysis files
        amp=$(grep "Total amplification:" "$RESULTS_DIR/${name}_analysis.txt" | \
              awk '{print $3}')
        device_io=$(grep "Total device I/O" "$RESULTS_DIR/${name}_analysis.txt" | \
                    awk '{print $6}')
        data_pct=$(grep "Data I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                   grep -o '[0-9.]*%' | head -1)
        meta_pct=$(grep "Metadata I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                   grep -o '[0-9.]*%' | head -1)
        journal_pct=$(grep "Journal I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                      grep -o '[0-9.]*%' | head -1)
        
        printf "%-12s   %-13s   %-6s   %-10s   %-9s   %s\n" \
               "$name" "$amp" "$data_pct" "$meta_pct" "$journal_pct" "$device_io" >> \
               "$RESULTS_DIR/summary_report.txt"
    fi
done

# Display summary
cat "$RESULTS_DIR/summary_report.txt"

# Create visualization data (CSV for easy plotting)
echo "Object_Size,Amplification,Data_Percent,Metadata_Percent,Journal_Percent" > \
     "$RESULTS_DIR/amplification_data.csv"

for i in ${!NAMES[@]}; do
    name=${NAMES[$i]}
    size=${SIZES[$i]}
    if [ -f "$RESULTS_DIR/${name}_analysis.txt" ]; then
        amp=$(grep "Total amplification:" "$RESULTS_DIR/${name}_analysis.txt" | \
              awk '{print $3}' | tr -d 'x')
        data_pct=$(grep "Data I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                   grep -o '[0-9.]*' | head -1)
        meta_pct=$(grep "Metadata I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                   grep -o '[0-9.]*' | head -1)
        journal_pct=$(grep "Journal I/O:" "$RESULTS_DIR/${name}_analysis.txt" | \
                      grep -o '[0-9.]*' | head -1)
        
        echo "$size,$amp,$data_pct,$meta_pct,$journal_pct" >> \
             "$RESULTS_DIR/amplification_data.csv"
    fi
done

echo ""
echo "======================================================================="
echo -e "${GREEN}All tests completed!${NC}"
echo "======================================================================="
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo "  - Individual traces: ${RESULTS_DIR}/*_trace.log"
echo "  - Individual analyses: ${RESULTS_DIR}/*_analysis.txt"
echo "  - Summary report: ${RESULTS_DIR}/summary_report.txt"
echo "  - CSV data: ${RESULTS_DIR}/amplification_data.csv"
echo ""
echo "To view the summary report:"
echo "  cat $RESULTS_DIR/summary_report.txt"
echo ""
echo "To plot the data, use the CSV file with your favorite plotting tool."
echo "======================================================================="
