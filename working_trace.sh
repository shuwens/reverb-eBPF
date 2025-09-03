#!/bin/bash
DURATION=${1:-5}
OUTPUT=${2:-trace.txt}

echo "Starting tracer for $DURATION seconds..."

# Start tracer in background
sudo ./build/multilayer_io_tracer -v > $OUTPUT 2>&1 &
TRACER_PID=$!

# Wait for specified duration
sleep $DURATION

# Force kill the tracer
sudo kill -9 $TRACER_PID 2>/dev/null

echo "Tracer stopped. Analyzing..."

# Simple analysis
echo -e "\n=== RESULTS ===" >> $OUTPUT
app=$(grep -c "APPLICATION.*WRITE" $OUTPUT)
os=$(grep -c "OS.*WRITE" $OUTPUT)  
dev=$(grep -c "DEVICE" $OUTPUT)

echo "Events captured:" >> $OUTPUT
echo "  Application: $app" >> $OUTPUT
echo "  OS: $os" >> $OUTPUT
echo "  Device: $dev" >> $OUTPUT

# Calculate bytes
app_bytes=$(grep "APPLICATION.*APP_WRITE" $OUTPUT | grep -v multilayer_io_t | awk '{sum+=$5} END {print int(sum+0)}')
dev_bytes=$(grep "DEVICE.*BIO_SUBMIT" $OUTPUT | awk '{sum+=$5} END {print int(sum+0)}')

if [ "$app_bytes" -gt "0" ] && [ "$dev_bytes" -gt "0" ]; then
    amp=$(echo "scale=2; $dev_bytes / $app_bytes" | bc -l)
    echo "Amplification: ${amp}x ($app_bytes -> $dev_bytes bytes)" >> $OUTPUT
fi

tail -20 $OUTPUT
