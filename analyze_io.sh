#!/bin/bash
FILE=${1:-complete_test.txt}

echo "=== I/O Amplification Analysis ==="

# Fix 1: Use awk instead of grep for reliable pattern matching
# The issue: grep has problems with multiple spaces/tabs in the output

# Count dd write events using awk
dd_count=$(awk '/APP_WRITE/ && /dd/' $FILE | wc -l)
echo "DD write events: $dd_count"

# Sum dd writes - awk handles spacing better than grep+awk pipeline
dd_bytes=$(awk '/APP_WRITE/ && /dd/ {sum+=$5} END {print sum+0}' $FILE)
echo "Application bytes: $dd_bytes"

# For 1MB writes specifically
mb_writes=$(awk '/APP_WRITE/ && /1048576/ && /dd/' $FILE | wc -l)
echo "1MB write count: $mb_writes"

# Device layer total
dev_bytes=$(awk '/DEVICE.*BIO_SUBMIT/ {sum+=$5} END {print sum+0}' $FILE)
echo "Device bytes: $dev_bytes"

# Calculate amplification
if [ "$dd_bytes" -gt 0 ]; then
    amp=$(echo "scale=3; $dev_bytes / $dd_bytes" | bc -l)
    echo ""
    echo "AMPLIFICATION: ${amp}x"
    echo "  Application: $dd_bytes bytes ($(echo "scale=2; $dd_bytes/1048576" | bc) MB)"
    echo "  Device: $dev_bytes bytes ($(echo "scale=2; $dev_bytes/1048576" | bc) MB)"
fi

# Show sample events for verification
echo ""
echo "Sample events:"
echo "First dd write:"
awk '/APP_WRITE/ && /dd/' $FILE | head -1
echo "First device write:"
awk '/DEVICE.*BIO_SUBMIT/' $FILE | head -1
