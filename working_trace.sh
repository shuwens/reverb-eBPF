#!/bin/bash
DURATION=${1:-5}
OUTPUT=${2:-trace.txt}

echo "Starting tracer for $DURATION seconds..."
sudo ./build/multilayer_io_tracer -v > $OUTPUT 2>&1 &
TRACER_PID=$!
sleep $DURATION
sudo kill -9 $TRACER_PID 2>/dev/null
echo "Tracer stopped."
