#!/bin/bash
FILE=${1:-large_file_test.txt}

echo "=== Complete DD Analysis ==="

# Count ALL dd write events (not just first few)
echo "1. Counting DD write operations:"
dd_write_count=$(grep "APPLICATION.*dd.*APP_WRITE" $FILE | wc -l)
echo "   Number of dd write syscalls: $dd_write_count"

# Sum ALL dd writes to get total
echo -e "\n2. Calculating total DD writes:"
dd_total_writes=$(grep "APPLICATION.*dd.*APP_WRITE" $FILE | awk '{sum+=$5} END {print sum+0}')
echo "   Total bytes written by dd: $dd_total_writes"

# Show the distribution of write sizes
echo -e "\n3. Write size distribution:"
grep "APPLICATION.*dd.*APP_WRITE" $FILE | awk '{print $5}' | sort | uniq -c | sort -rn | head -5

# Calculate device I/O
echo -e "\n4. Device layer analysis:"
device_total=$(grep "DEVICE.*BIO_SUBMIT" $FILE | awk '{sum+=$5} END {print sum+0}')
echo "   Total device bytes: $device_total"

# Show device I/O breakdown
echo "   Device I/O by process:"
grep "DEVICE.*BIO_SUBMIT" $FILE | awk '{proc=$NF; size=$5; sum[proc]+=size} END {for(p in sum) printf "     %s: %d bytes\n", p, sum[p]}' | sort -rnk2

# Calculate true amplification
echo -e "\n5. TRUE AMPLIFICATION:"
if [ "$dd_total_writes" -gt 0 ]; then
    amp=$(echo "scale=2; $device_total / $dd_total_writes" | bc -l)
    echo "   Application: $dd_total_writes bytes"
    echo "   Device: $device_total bytes"
    echo "   Amplification: ${amp}x"
    
    # Interpret the result
    if (( $(echo "$amp < 1" | bc -l) )); then
        echo "   → Compression or caching reduced I/O!"
    elif (( $(echo "$amp > 5" | bc -l) )); then
        echo "   → Significant amplification detected!"
    fi
else
    echo "   No dd writes captured!"
fi
