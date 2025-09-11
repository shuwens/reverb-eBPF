#!/usr/bin/env python3
import sys
import re

def analyze_for_journal(filename):
    """Identify journal I/O using ext4 patterns"""
    
    device_writes = []
    sync_events = []
    write_patterns = {}
    
    with open(filename, 'r') as f:
        for line in f:
            # Track device writes
            if 'DEV_BIO_SUBMIT' in line:
                parts = line.split()
                if len(parts) >= 5:
                    time = parts[0]
                    size = int(parts[3]) if parts[3].isdigit() else 0
                    aligned = int(parts[4]) if parts[4].isdigit() else 0
                    device_writes.append({
                        'time': time,
                        'size': size,
                        'aligned': aligned,
                        'line': line
                    })
            
            # Track sync events
            if 'FS_SYNC' in line:
                parts = line.split()
                if len(parts) >= 1:
                    sync_events.append(parts[0])
    
    # Analyze patterns
    print(f"\nJournal I/O Pattern Analysis for: {filename}")
    print("="*60)
    
    # ext4 journal characteristics:
    # 1. Small writes (4KB-8KB) to device
    # 2. Often sequential small writes
    # 3. Occur after FS_SYNC events
    
    small_writes = [w for w in device_writes if w['aligned'] <= 8192 and w['aligned'] > 0]
    large_writes = [w for w in device_writes if w['aligned'] > 8192]
    
    print(f"Total device writes: {len(device_writes)}")
    print(f"Small writes (≤8KB, potential journal): {len(small_writes)}")
    print(f"Large writes (>8KB, likely data): {len(large_writes)}")
    print(f"FS_SYNC events: {len(sync_events)}")
    
    # Estimate journal I/O
    # In ext4, journal commits typically involve:
    # - Descriptor blocks (4KB)
    # - Data blocks (varies)
    # - Commit blocks (4KB)
    
    estimated_journal_bytes = 0
    
    # Method 1: Count small writes after syncs
    if len(sync_events) > 0:
        estimated_journal_bytes += len(sync_events) * 8192  # Typical journal commit size
        print(f"\nEstimated journal from sync events: {len(sync_events) * 8192:,} bytes")
    
    # Method 2: Identify sequential small writes (journal pattern)
    if len(small_writes) > 1:
        sequential_count = 0
        for i in range(1, len(small_writes)):
            # Check if writes are close in time (sequential)
            if small_writes[i]['aligned'] == small_writes[i-1]['aligned']:
                sequential_count += 1
        
        estimated_journal_bytes += sequential_count * 4096
        print(f"Sequential small writes identified: {sequential_count}")
    
    # Show sample of small writes (likely journal)
    if small_writes:
        print(f"\nSample small writes (likely journal):")
        for w in small_writes[:5]:
            print(f"  {w['time']} - {w['aligned']} bytes")
    
    print(f"\n** Total Estimated Journal I/O: {estimated_journal_bytes:,} bytes")
    
    return {
        'total_writes': len(device_writes),
        'small_writes': len(small_writes),
        'large_writes': len(large_writes),
        'sync_events': len(sync_events),
        'estimated_journal': estimated_journal_bytes
    }

# Analyze all test files
if __name__ == "__main__":
    sizes = ['1B', '10B', '100B', '1KB', '10MB']
    
    print("\n" + "="*80)
    print("Journal I/O Estimation for All Tests")
    print("="*80)
    print(f"{'Size':<8} {'Device Writes':<15} {'Small (<8KB)':<12} {'Syncs':<8} {'Est.Journal':<12}")
    print("-"*80)
    
    for size in sizes:
        filename = f"minio_{size}_analysis.log"
        try:
            stats = analyze_for_journal(filename)
            print(f"{size:<8} {stats['total_writes']:<15} {stats['small_writes']:<12} "
                  f"{stats['sync_events']:<8} {stats['estimated_journal']:>11,}")
        except FileNotFoundError:
            continue
    
    print("="*80)
    print("\nNote: On ext4, journal writes are typically 4-8KB blocks")
    print("These are included in DEV_BIO_SUBMIT but not explicitly marked as journal")
