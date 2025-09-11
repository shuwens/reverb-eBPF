#!/bin/bash

BUCKET="public"
PROFILE="minio"

echo "Starting MinIO I/O amplification tests..."

# Test 1: Small file (100 bytes) - expect high amplification
echo "Test 1: 100-byte file upload"
echo "HelloWorld" > small.txt
aws s3 cp small.txt s3://$BUCKET/small.txt --profile $PROFILE
sleep 2

# Test 2: 4KB file - aligned with page size
echo "Test 2: 4KB file upload"
dd if=/dev/zero of=4k.dat bs=4096 count=1 2>/dev/null
aws s3 cp 4k.dat s3://$BUCKET/4k.dat --profile $PROFILE
sleep 2

# Test 3: Large file with multipart upload (>5MB triggers multipart)
echo "Test 3: 10MB file upload (multipart)"
dd if=/dev/zero of=10m.dat bs=1M count=10 2>/dev/null
aws s3 cp 10m.dat s3://$BUCKET/10m.dat --profile $PROFILE
sleep 2

# Test 4: Multiple small files (metadata intensive)
echo "Test 4: Multiple small files"
for i in {1..10}; do
    echo "File $i" > file_$i.txt
    aws s3 cp file_$i.txt s3://$BUCKET/batch/file_$i.txt --profile $PROFILE
done
sleep 2

# Test 5: Download test
echo "Test 5: Download 4KB file"
aws s3 cp s3://$BUCKET/4k.dat downloaded_4k.dat --profile $PROFILE

# Cleanup
rm -f *.txt *.dat

echo "Tests complete!"
