#!/bin/bash

BUCKET="public"
PROFILE="minio"
TEST_DIR="metadata_test_$$"

echo "=== MinIO Metadata I/O Analysis Test ==="
echo "Test directory: $TEST_DIR"
echo "----------------------------------------"

mkdir -p $TEST_DIR
cd $TEST_DIR

# Test 1: Single object creation (observe xl.meta creation)
echo "[Test 1] Single object - metadata creation pattern"
echo "data" > single.txt
aws s3 cp single.txt s3://$BUCKET/meta_test/single.txt --profile $PROFILE
sleep 3

# Test 2: Directory listing (metadata reads)
echo "[Test 2] List operation - metadata reads"
aws s3 ls s3://$BUCKET/ --recursive --profile $PROFILE > /dev/null
sleep 3

# Test 3: Object HEAD operation (metadata only, no data)
echo "[Test 3] HEAD operation - pure metadata"
aws s3api head-object --bucket $BUCKET --key meta_test/single.txt --profile $PROFILE > /dev/null
sleep 3

# Test 4: Multiple small objects (metadata amplification)
echo "[Test 4] Batch small objects - metadata storm"
for i in {1..20}; do
    echo "$i" > small_$i.txt
    aws s3 cp small_$i.txt s3://$BUCKET/meta_test/batch/small_$i.txt --profile $PROFILE --quiet
done
sleep 3

# Test 5: Object versioning/update (metadata changes)
echo "[Test 5] Object update - metadata modification"
echo "updated" > single.txt
aws s3 cp single.txt s3://$BUCKET/meta_test/single.txt --profile $PROFILE
sleep 3

# Test 6: GetObjectAttributes (metadata intensive)
echo "[Test 6] Get object attributes"
aws s3api get-object-attributes --bucket $BUCKET --key meta_test/single.txt \
    --object-attributes "ETag" "StorageClass" "ObjectSize" --profile $PROFILE > /dev/null 2>&1
sleep 3

# Test 7: Delete operation (metadata cleanup)
echo "[Test 7] Delete - metadata removal"
aws s3 rm s3://$BUCKET/meta_test/single.txt --profile $PROFILE

cd ..
rm -rf $TEST_DIR

echo "=== Tests Complete ==="
