#!/bin/bash

SIZE=$1
FILENAME=$2
BUCKET="public"
PROFILE="minio"

if [ -z "$SIZE" ] || [ -z "$FILENAME" ]; then
    echo "Usage: ./test_single_object.sh <size> <filename>"
    echo "Example: ./test_single_object.sh 1 test_1b.dat"
    exit 1
fi

echo "Testing ${SIZE}B object: ${FILENAME}"

# Create the file with exact size
if [ "$SIZE" = "1" ]; then
    echo -n "A" > $FILENAME
elif [ "$SIZE" = "10" ]; then
    echo -n "0123456789" > $FILENAME
elif [ "$SIZE" = "100" ]; then
    dd if=/dev/zero of=$FILENAME bs=1 count=100 2>/dev/null
elif [ "$SIZE" = "1000" ]; then
    dd if=/dev/zero of=$FILENAME bs=1 count=1000 2>/dev/null
elif [ "$SIZE" = "10485760" ]; then  # 10MB
    dd if=/dev/zero of=$FILENAME bs=1M count=10 2>/dev/null
else
    dd if=/dev/zero of=$FILENAME bs=1 count=$SIZE 2>/dev/null
fi

# Upload to MinIO
echo "Uploading to s3://${BUCKET}/test_${SIZE}B/${FILENAME}"
aws s3 cp $FILENAME s3://${BUCKET}/test_${SIZE}B/${FILENAME} --profile $PROFILE

# Clean up local file
rm -f $FILENAME

echo "Test complete for ${SIZE}B object"
