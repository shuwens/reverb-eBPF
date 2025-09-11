#!/usr/bin/env python3
import sys
import re
from collections import defaultdict

def analyze_minio_trace(filename):
    """Analyze MinIO trace with proper metadata accounting"""
    
    stats = {
        'by_layer': defaultdict(lambda: {'data': 0, 'metadata': 0, 'journal': 0, 'total': 0}),
        'by_type': {'data': 0, 'metadata': 0, 'journal': 0},
        'metadata_ops': 0,
        'xl_meta_files': set(),
        'events': defaultdict(int),
        'app_bytes': 0,
        'device_bytes': 0
    }
    
    with open(filename, 'r') as f:
        for line in f:
            # Skip empty lines and headers
            if not line.strip() or '===' in line or '---' in line:
                continue
            
            # Parse event lines
            parts = line.split()
            if len(parts) >= 7:
                try:
                    # Format: TIME LAYER EVENT SIZE ALIGNED LAT COMM FLAGS
                    layer = parts[1]
                    event = parts[2]
                    size = int(parts[3]) if parts[3].isdigit() else 0
                    aligned = int(parts[4]) if parts[4].isdigit() else 0
                    
                    # Use aligned size if available and larger
                    actual_size = max(size, aligned)
                    
                    # Categorize the I/O
                    if '[META]' in line or 'XL_META' in event:
                        # Metadata operations - estimate size if 0
                        if actual_size == 0:
                            actual_size = 1024  # Typical xl.meta size
                        stats['by_layer'][layer]['metadata'] += actual_size
                        stats['by_type']['metadata'] += actual_size
                        stats['metadata_ops'] += 1
                        
                    elif '[JRNL]' in line or 'FS_SYNC' in event:
                        # Journal operations
                        if actual_size == 0:
                            actual_size = 4096  # Typical journal block
                        stats['by_layer'][layer]['journal'] += actual_size
                        stats['by_type']['journal'] += actual_size
                        
                    else:
                        # Regular data I/O
                        stats['by_layer'][layer]['data'] += actual_size
                        stats['by_type']['data'] += actual_size
                    
                    stats['by_layer'][layer]['total'] += actual_size
                    stats['events'][event] += 1
                    
                except (ValueError, IndexError):
                    continue
            
            # Capture xl.meta filenames
            if 'File:' in line and 'xl.meta' in line:
                filepath = line.split('File:')[1].strip()
                stats['xl_meta_files'].add(filepath)
            
            # Parse summary section
            if 'Original application I/O:' in line:
                match = re.search(r'(\d+)', line)
                if match:
                    stats['app_bytes'] = int(match.group(1))
            
            if 'Final device layer I/O:' in line:
                match = re.search(r'(\d+)', line)
                if match:
                    stats['device_bytes'] = int(match.group(1))
    
    return stats

def print_detailed_analysis(stats, test_size):
    """Print detailed I/O breakdown"""
    
    print(f"\n{'='*70}")
    print(f"MinIO I/O Analysis: {test_size} Object")
    print(f"{'='*70}")
    
    # Event summary
    print("\n1. EVENT SUMMARY:")
    print("-" * 40)
    for event, count in sorted(stats['events'].items()):
        if count > 0:
            print(f"  {event:<30} {count:>5} events")
    
    # Metadata files
    print(f"\n2. METADATA FILES ACCESSED: {len(stats['xl_meta_files'])}")
    if stats['xl_meta_files']:
        for f in list(stats['xl_meta_files'])[:5]:  # Show first 5
            print(f"  - {f}")
        if len(stats['xl_meta_files']) > 5:
            print(f"  ... and {len(stats['xl_meta_files'])-5} more")
    
    # I/O type breakdown
    print("\n3. I/O TYPE BREAKDOWN:")
    print("-" * 40)
    total = sum(stats['by_type'].values())
    if total > 0:
        for io_type in ['data', 'metadata', 'journal']:
            bytes_val = stats['by_type'][io_type]
            pct = (bytes_val / total * 100) if total > 0 else 0
            print(f"  {io_type.capitalize():<10} {bytes_val:>12,} bytes ({pct:5.1f}%)")
    
    # Per-layer breakdown
    print("\n4. PER-LAYER I/O:")
    print("-" * 40)
    print(f"{'Layer':<15} {'Data':<12} {'Metadata':<12} {'Journal':<12} {'Total':<12}")
    print("-" * 60)
    
    for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
        if layer in stats['by_layer']:
            l = stats['by_layer'][layer]
            print(f"{layer:<15} {l['data']:>11,} {l['metadata']:>11,} {l['journal']:>11,} {l['total']:>11,}")
    
    # Amplification
    print("\n5. AMPLIFICATION:")
    print("-" * 40)
    
    # Calculate from layer totals
    app_total = stats['by_layer']['APPLICATION']['total']
    device_total = stats['by_layer']['DEVICE']['total']
    
    if app_total > 0 and device_total > 0:
        amplification = device_total / app_total
        print(f"  Application I/O: {app_total:>12,} bytes")
        print(f"  Device I/O:      {device_total:>12,} bytes")
        print(f"  Amplification:   {amplification:>12.2f}x")
    
    # Metadata overhead
    if stats['by_type']['data'] > 0:
        metadata_overhead = (stats['by_type']['metadata'] / stats['by_type']['data'] * 100)
        print(f"\n  Metadata Overhead: {metadata_overhead:.1f}% of data")
        print(f"  Metadata Ops:      {stats['metadata_ops']} operations")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_minio_io.py <logfile>")
        sys.exit(1)
    
    logfile = sys.argv[1]
    
    # Extract size from filename (e.g., minio_1KB_analysis.log -> 1KB)
    size = "Unknown"
    if '_' in logfile and '_analysis' in logfile:
        size = logfile.split('_')[1]
    
    stats = analyze_minio_trace(logfile)
    print_detailed_analysis(stats, size)

if __name__ == "__main__":
    main()
