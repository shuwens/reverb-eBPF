#!/bin/bash

echo "================================================================================================"
echo "MinIO I/O Comparison Across Object Sizes"
echo "================================================================================================"
printf "%-10s %12s %12s %12s %12s %10s %10s\n" \
       "Size" "Total_I/O" "Data" "Metadata" "Journal" "Amp" "Meta%"
echo "------------------------------------------------------------------------------------------------"

for size in 1B 10B 100B 1KB 10MB; do
    if [ -f "minio_${size}_analysis.log" ]; then
        # Extract key metrics using grep and awk
        total=$(grep -E "DEVICE.*[0-9]+" minio_${size}_analysis.log | tail -1 | awk '{print $5}')
        amp=$(grep "TOTAL AMPLIFICATION" minio_${size}_analysis.log | tail -1 | awk '{print $3}' | tr -d 'x*')
        meta_count=$(grep -c "XL_META" minio_${size}_analysis.log)
        
        printf "%-10s %12s %12s %12s %12s %10s %10d\n" \
               "$size" "$total" "-" "-" "-" "$amp" "$meta_count"
    fi
done
echo "================================================================================================"
