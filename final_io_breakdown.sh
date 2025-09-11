#!/bin/bash

echo "========================================================================"
echo "COMPLETE I/O BREAKDOWN: Data, Metadata, and Journal (Estimated)"
echo "========================================================================"
echo ""

for size in 1B 10B 100B 1KB 10MB; do
    logfile="minio_${size}_analysis.log"
    
    if [ -f "$logfile" ]; then
        echo ">>> Object Size: $size"
        echo "--------------------------------------------------------------------"
        
        # Count events
        app_writes=$(grep -c "APPLICATION.*MINIO_OBJECT_PUT" $logfile)
        metadata_ops=$(grep -c "XL_META" $logfile)
        sync_ops=$(grep -c "FS_SYNC" $logfile)
        device_writes=$(grep -c "DEV_BIO_SUBMIT" $logfile)
        
        # Extract bytes
        app_bytes=$(grep "APPLICATION" $logfile | grep -E "[0-9]+" | awk '{sum+=$4} END {print sum}')
        device_bytes=$(grep "DEVICE" $logfile | grep -E "[0-9]+" | awk '{sum+=$4} END {print sum}')
        
        # Count small device writes (likely journal)
        small_writes=$(grep "DEV_BIO_SUBMIT" $logfile | awk '$5<=8192 && $5>0' | wc -l)
        journal_bytes=$((small_writes * 4096))
        
        # Metadata bytes (estimate 1KB per xl.meta operation)
        metadata_bytes=$((metadata_ops * 1024))
        
        # Data bytes (device - journal - metadata)
        data_bytes=$((device_bytes - journal_bytes - metadata_bytes))
        
        echo "  Application I/O:     $(printf %8d $app_bytes) bytes"
        echo "  Device Total I/O:    $(printf %8d $device_bytes) bytes"
        echo ""
        echo "  Breakdown:"
        echo "    Data I/O:          $(printf %8d $data_bytes) bytes"
        echo "    Metadata I/O:      $(printf %8d $metadata_bytes) bytes ($metadata_ops xl.meta ops)"
        echo "    Journal I/O (est): $(printf %8d $journal_bytes) bytes ($small_writes small writes)"
        echo ""
        
        if [ $app_bytes -gt 0 ]; then
            amp=$(echo "scale=2; $device_bytes / $app_bytes" | bc)
            echo "  Amplification: ${amp}x"
        fi
        echo ""
    fi
done

echo "========================================================================"
echo "Note: Journal I/O estimated from small (<8KB) device writes"
echo "      On ext4, journal commits are typically 4-8KB blocks"
echo "========================================================================"
