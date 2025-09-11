#!/bin/bash

BUCKET="public"
PROFILE="minio"
TEST_DIR="io_test_$$"
RESULTS_DIR="results_$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

mkdir -p $TEST_DIR $RESULTS_DIR
cd $TEST_DIR

echo -e "${GREEN}=== MinIO I/O Pattern Analysis ===${NC}"
echo "Testing: Data, Journal, and Metadata Operations"
echo "Test PID: $$"
echo "================================================"

# Function to wait and mark test boundaries
mark_test() {
    echo -e "\n${YELLOW}>>> $1${NC}"
    sleep 2
    echo "MARKER: $1" >> /tmp/test_markers.log
    date '+%Y-%m-%d %H:%M:%S' >> /tmp/test_markers.log
}

# ===========================================
# PART 1: DATA I/O TESTS
# ===========================================
echo -e "\n${GREEN}[PART 1: DATA I/O PATTERNS]${NC}"

mark_test "Test 1.1: Tiny data (10 bytes) - Maximum amplification"
echo "123456789" > tiny.txt
aws s3 cp tiny.txt s3://$BUCKET/data_test/tiny.txt --profile $PROFILE
sleep 3

mark_test "Test 1.2: Sub-page data (2KB) - Below 4KB page"
dd if=/dev/urandom of=2kb.dat bs=2048 count=1 2>/dev/null
aws s3 cp 2kb.dat s3://$BUCKET/data_test/2kb.dat --profile $PROFILE
sleep 3

mark_test "Test 1.3: Page-aligned data (4KB) - Optimal small size"
dd if=/dev/urandom of=4kb.dat bs=4096 count=1 2>/dev/null
aws s3 cp 4kb.dat s3://$BUCKET/data_test/4kb.dat --profile $PROFILE
sleep 3

mark_test "Test 1.4: Large data (10MB) - Multipart & erasure coding"
dd if=/dev/urandom of=10mb.dat bs=1M count=10 2>/dev/null
aws s3 cp 10mb.dat s3://$BUCKET/data_test/10mb.dat --profile $PROFILE
sleep 3

mark_test "Test 1.5: Sequential small writes - Write amplification"
for i in {1..5}; do
    echo "Line $i" >> sequential.txt
    aws s3 cp sequential.txt s3://$BUCKET/data_test/seq_$i.txt --profile $PROFILE --quiet
done
sleep 3

# ===========================================
# PART 2: METADATA I/O TESTS
# ===========================================
echo -e "\n${GREEN}[PART 2: METADATA I/O PATTERNS]${NC}"

mark_test "Test 2.1: Object creation - xl.meta generation"
echo "metadata_test" > meta.txt
aws s3 cp meta.txt s3://$BUCKET/meta_test/object.txt --profile $PROFILE
sleep 3

mark_test "Test 2.2: HEAD request - Pure metadata read"
aws s3api head-object --bucket $BUCKET --key meta_test/object.txt --profile $PROFILE >/dev/null
sleep 2

mark_test "Test 2.3: List operation - Metadata scan"
aws s3 ls s3://$BUCKET/ --recursive --profile $PROFILE >/dev/null
sleep 3

mark_test "Test 2.4: Metadata update - Copy with new metadata"
aws s3api copy-object \
    --bucket $BUCKET \
    --copy-source $BUCKET/meta_test/object.txt \
    --key meta_test/object.txt \
    --metadata-directive REPLACE \
    --metadata type=test,timestamp=$(date +%s) \
    --profile $PROFILE >/dev/null
sleep 3

mark_test "Test 2.5: Batch metadata - Many small objects"
for i in {1..10}; do
    echo "$i" > batch_$i.txt
    aws s3 cp batch_$i.txt s3://$BUCKET/meta_test/batch/file_$i.txt --profile $PROFILE --quiet
done
sleep 3

# ===========================================
# PART 3: JOURNAL I/O TESTS (Filesystem Level)
# ===========================================
echo -e "\n${GREEN}[PART 3: JOURNAL I/O PATTERNS]${NC}"

mark_test "Test 3.1: Sync write - Force journal flush"
echo "sync_test" > sync.txt
aws s3 cp sync.txt s3://$BUCKET/journal_test/sync.txt --profile $PROFILE
sync  # Force filesystem sync
sleep 3

mark_test "Test 3.2: Rapid small writes - Journal pressure"
for i in {1..20}; do
    echo "$i" > rapid_$i.txt
    aws s3 cp rapid_$i.txt s3://$BUCKET/journal_test/rapid_$i.txt --profile $PROFILE --quiet &
done
wait
sleep 3

mark_test "Test 3.3: Large atomic write - Journal transaction"
dd if=/dev/urandom of=atomic.dat bs=1M count=1 2>/dev/null
aws s3 cp atomic.dat s3://$BUCKET/journal_test/atomic.dat --profile $PROFILE
sleep 3

# ===========================================
# PART 4: MIXED WORKLOAD TESTS
# ===========================================
echo -e "\n${GREEN}[PART 4: MIXED I/O PATTERNS]${NC}"

mark_test "Test 4.1: Read after write - Cache behavior"
echo "cache_test" > cache.txt
aws s3 cp cache.txt s3://$BUCKET/mixed_test/cache.txt --profile $PROFILE
aws s3 cp s3://$BUCKET/mixed_test/cache.txt downloaded_cache.txt --profile $PROFILE
sleep 3

mark_test "Test 4.2: Overwrite - Metadata + Data + Journal"
echo "version1" > versioned.txt
aws s3 cp versioned.txt s3://$BUCKET/mixed_test/versioned.txt --profile $PROFILE
echo "version2" > versioned.txt
aws s3 cp versioned.txt s3://$BUCKET/mixed_test/versioned.txt --profile $PROFILE
sleep 3

mark_test "Test 4.3: Delete operation - Metadata cleanup + Journal"
aws s3 rm s3://$BUCKET/mixed_test/versioned.txt --profile $PROFILE
sleep 3

# ===========================================
# PART 5: READ TESTS
# ===========================================
echo -e "\n${GREEN}[PART 5: READ I/O PATTERNS]${NC}"

mark_test "Test 5.1: Small read - Full block read for small file"
aws s3 cp s3://$BUCKET/data_test/tiny.txt read_tiny.txt --profile $PROFILE

mark_test "Test 5.2: Large read - Streaming read pattern"
aws s3 cp s3://$BUCKET/data_test/10mb.dat read_10mb.dat --profile $PROFILE

mark_test "Test 5.3: Partial read - Range request"
aws s3api get-object \
    --bucket $BUCKET \
    --key data_test/10mb.dat \
    --range bytes=0-1023 \
    --profile $PROFILE \
    partial_read.dat >/dev/null

# Cleanup
cd ..
rm -rf $TEST_DIR

echo -e "\n${GREEN}=== Test Complete ===${NC}"
echo "Check trace output for I/O patterns analysis"
