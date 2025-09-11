#!/bin/bash

# Quick test to capture journal activity
echo "Tracing ext4/jbd2 journal operations..."

# Use existing tracer and additionally monitor jbd2
sudo ./build/multilayer_io_tracer -M -c -E -T -v -d 30 2>&1 | tee journal_trace.log &
TRACER_PID=$!

# Also trace jbd2 kernel threads
sudo perf trace -e 'jbd2:*' -a -o jbd2_trace.log &
PERF_PID=$!

sleep 2

# Generate I/O that will trigger journal activity
echo "Generating journal activity..."
for i in {1..5}; do
    echo "data $i" > test_journal_$i.txt
    aws s3 cp test_journal_$i.txt s3://public/journal_test/file_$i.txt --profile minio
    sync  # Force journal flush
done

sleep 10

# Check jbd2 kernel thread activity
ps aux | grep -E "jbd2|kworker.*ext4" | grep -v grep

# Stop tracing
sudo kill $TRACER_PID $PERF_PID 2>/dev/null

# Analyze journal activity
echo ""
echo "=== Journal Analysis ==="
echo "FS_SYNC events: $(grep -c FS_SYNC journal_trace.log)"
echo "Small device writes (<=8KB): $(grep DEV_BIO_SUBMIT journal_trace.log | awk '$4<=8192' | wc -l)"
echo "jbd2 events from perf: $(grep -c jbd2 jbd2_trace.log 2>/dev/null || echo 'N/A')"

rm -f test_journal_*.txt
