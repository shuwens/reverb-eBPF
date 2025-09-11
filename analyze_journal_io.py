#!/usr/bin/env python3
import sys
import re

def analyze_journal_patterns(logfile, size_name):
    """Analyze journal I/O patterns in detail"""
    
    stats = {
        'app_io': 0,
        'device_io': 0,
        'sync_events': [],
        'device_writes': [],
        'journal_writes': [],
        'metadata_ops': 0,
        'data_writes': [],
    }
    
    with open(logfile, 'r') as f:
        for line in f:
            # Application I/O
            if 'APPLICATION' in line and 'MINIO_OBJECT' in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3].isdigit():
                    stats['app_io'] += int(parts[3])
            
            # FS_SYNC events (journal triggers)
            if 'FS_SYNC' in line:
                time = line.split()[0] if line else 'unknown'
                stats['sync_events'].append(time)
            
            # Device writes
            if 'DEV_BIO_SUBMIT' in line:
                parts = line.split()
                if len(parts) >= 5:
                    time = parts[0]
                    size = int(parts[3]) if parts[3].isdigit() else 0
                    aligned = int(parts[4]) if parts[4].isdigit() else 0
                    
                    write_info = {
                        'time': time,
                        'size': aligned if aligned > 0 else size,
                        'type': 'journal' if aligned <= 8192 else 'data'
                    }
                    
                    stats['device_writes'].append(write_info)
                    stats['device_io'] += write_info['size']
                    
                    if write_info['type'] == 'journal':
                        stats['journal_writes'].append(write_info)
                    else:
                        stats['data_writes'].append(write_info)
            
            # Metadata operations
            if 'XL_META' in line:
                stats['metadata_ops'] += 1
    
    # Print detailed analysis
    print(f"\n{'='*70}")
    print(f"JOURNAL I/O ANALYSIS: {size_name} Object")
    print(f"{'='*70}")
    
    print(f"\n1. I/O SUMMARY:")
    print(f"   Application I/O:  {stats['app_io']:,} bytes")
    print(f"   Device Total I/O: {stats['device_io']:,} bytes")
    if stats['app_io'] > 0:
        print(f"   Amplification:    {stats['device_io']/stats['app_io']:.2f}x")
    
    print(f"\n2. JOURNAL ACTIVITY:")
    print(f"   FS_SYNC Events:   {len(stats['sync_events'])}")
    print(f"   Journal Writes:   {len(stats['journal_writes'])}")
    journal_bytes = sum(w['size'] for w in stats['journal_writes'])
    print(f"   Journal Bytes:    {journal_bytes:,}")
    
    if stats['sync_events']:
        print(f"\n   Sync Times:")
        for i, sync_time in enumerate(stats['sync_events'][:5], 1):
            print(f"     {i}. {sync_time}")
            # Find journal writes after this sync
            journal_after = [w for w in stats['journal_writes'] 
                           if w['time'] > sync_time][:2]
            for jw in journal_after:
                print(f"        └─> Journal write: {jw['size']} bytes at {jw['time']}")
    
    print(f"\n3. DEVICE WRITE PATTERN:")
    print(f"   Total Writes:     {len(stats['device_writes'])}")
    print(f"   Journal (<= 8KB): {len(stats['journal_writes'])}")
    print(f"   Data (> 8KB):     {len(stats['data_writes'])}")
    
    print(f"\n4. I/O BREAKDOWN:")
    data_bytes = sum(w['size'] for w in stats['data_writes'])
    metadata_bytes = stats['metadata_ops'] * 1024  # Estimate 1KB per xl.meta
    print(f"   Data I/O:         {data_bytes:,} bytes")
    print(f"   Metadata I/O:     {metadata_bytes:,} bytes ({stats['metadata_ops']} ops)")
    print(f"   Journal I/O:      {journal_bytes:,} bytes")
    
    if stats['device_io'] > 0:
        print(f"\n   Percentages:")
        print(f"     Data:     {data_bytes*100/stats['device_io']:.1f}%")
        print(f"     Metadata: {metadata_bytes*100/stats['device_io']:.1f}%")
        print(f"     Journal:  {journal_bytes*100/stats['device_io']:.1f}%")
    
    return stats

# Run analysis for all sizes
if __name__ == "__main__":
    sizes = ['1B', '10B', '100B', '1KB', '10MB']
    all_stats = []
    
    for size in sizes:
        logfile = f"minio_{size}_journal.log"
        try:
            stats = analyze_journal_patterns(logfile, size)
            all_stats.append((size, stats))
        except FileNotFoundError:
            print(f"Log file not found: {logfile}")
            continue
    
    # Summary table
    if all_stats:
        print(f"\n{'='*70}")
        print("JOURNAL I/O SUMMARY TABLE")
        print(f"{'='*70}")
        print(f"{'Size':<8} {'App I/O':<12} {'Device I/O':<12} {'Journal':<12} {'Syncs':<8} {'Amp':<8}")
        print("-"*70)
        
        for size, stats in all_stats:
            journal_bytes = sum(w['size'] for w in stats['journal_writes'])
            amp = stats['device_io']/stats['app_io'] if stats['app_io'] > 0 else 0
            print(f"{size:<8} {stats['app_io']:<11,} {stats['device_io']:<11,} "
                  f"{journal_bytes:<11,} {len(stats['sync_events']):<7} {amp:<7.2f}x")
