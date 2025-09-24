#!/usr/bin/env python3

"""
Parse and analyze strace results from MinIO I/O experiments
Calculates actual syscall bytes, I/O amplification, and metadata overhead
"""

import sys
import re
import glob
from collections import defaultdict
from pathlib import Path

def parse_strace_file(filepath):
    """Parse a single strace file and extract I/O metrics"""
    
    metrics = {
        'total_read_bytes': 0,
        'total_write_bytes': 0,
        'pread_bytes': 0,
        'pwrite_bytes': 0,
        'read_count': 0,
        'write_count': 0,
        'xl_meta_ops': 0,
        'part_file_ops': 0,
        'open_calls': 0,
        'fsync_calls': 0,
        'files_accessed': set(),
        'xl_meta_files': set(),
        'part_files': set(),
        'syscall_details': defaultdict(lambda: {'count': 0, 'bytes': 0})
    }
    
    fd_to_file = {}
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                # Skip incomplete lines
                if '<unfinished' in line or 'resumed>' in line:
                    continue
                
                # Track file opens to map FDs to files
                if 'openat(' in line or 'open(' in line:
                    fd_match = re.search(r'= (\d+)', line)
                    path_match = re.search(r'"([^"]+)"', line)
                    
                    if fd_match and path_match and int(fd_match.group(1)) >= 0:
                        fd = fd_match.group(1)
                        path = path_match.group(1)
                        fd_to_file[fd] = path
                        metrics['files_accessed'].add(path)
                        metrics['open_calls'] += 1
                        
                        if 'xl.meta' in path:
                            metrics['xl_meta_ops'] += 1
                            metrics['xl_meta_files'].add(path)
                        if '/part.' in path or 'part-' in path:
                            metrics['part_file_ops'] += 1
                            metrics['part_files'].add(path)
                
                # Parse read syscalls
                read_match = re.search(r'\bread\((\d+),.*= (\d+)', line)
                if read_match:
                    fd = read_match.group(1)
                    bytes_read = int(read_match.group(2))
                    if bytes_read > 0:
                        metrics['total_read_bytes'] += bytes_read
                        metrics['read_count'] += 1
                        metrics['syscall_details']['read']['count'] += 1
                        metrics['syscall_details']['read']['bytes'] += bytes_read
                
                # Parse pread64 syscalls
                pread_match = re.search(r'\bpread64\((\d+),.*= (\d+)', line)
                if pread_match:
                    bytes_read = int(pread_match.group(2))
                    if bytes_read > 0:
                        metrics['pread_bytes'] += bytes_read
                        metrics['total_read_bytes'] += bytes_read
                        metrics['syscall_details']['pread64']['count'] += 1
                        metrics['syscall_details']['pread64']['bytes'] += bytes_read
                
                # Parse write syscalls
                write_match = re.search(r'\bwrite\((\d+),.*= (\d+)', line)
                if write_match:
                    bytes_written = int(write_match.group(2))
                    if bytes_written > 0:
                        metrics['total_write_bytes'] += bytes_written
                        metrics['write_count'] += 1
                        metrics['syscall_details']['write']['count'] += 1
                        metrics['syscall_details']['write']['bytes'] += bytes_written
                
                # Parse pwrite64 syscalls
                pwrite_match = re.search(r'\bpwrite64\((\d+),.*= (\d+)', line)
                if pwrite_match:
                    bytes_written = int(pwrite_match.group(2))
                    if bytes_written > 0:
                        metrics['pwrite_bytes'] += bytes_written
                        metrics['total_write_bytes'] += bytes_written
                        metrics['syscall_details']['pwrite64']['count'] += 1
                        metrics['syscall_details']['pwrite64']['bytes'] += bytes_written
                
                # Count fsync operations
                if 'fsync(' in line or 'fdatasync(' in line:
                    metrics['fsync_calls'] += 1
                    
    except Exception as e:
        print(f"Error parsing {filepath}: {e}", file=sys.stderr)
    
    return metrics

def analyze_results(results_dir):
    """Analyze all strace files in the results directory"""
    
    # Test configurations
    sizes = [1, 10, 100, 1024, 10240, 102400, 1048576, 10485760]
    names = ["1B", "10B", "100B", "1KB", "10KB", "100KB", "1MB", "10MB"]
    
    print("=" * 80)
    print("STRACE I/O ANALYSIS RESULTS")
    print("=" * 80)
    print()
    
    # Summary data for CSV
    summary_data = []
    
    for i, (size, name) in enumerate(zip(sizes, names)):
        write_file = f"{results_dir}/write/{name}_write.strace"
        read_file = f"{results_dir}/read/{name}_read.strace"
        
        if not (Path(write_file).exists() and Path(read_file).exists()):
            continue
            
        write_metrics = parse_strace_file(write_file)
        read_metrics = parse_strace_file(read_file)
        
        # Calculate amplifications
        write_amp = write_metrics['total_write_bytes'] / size if size > 0 else 0
        read_amp = read_metrics['total_read_bytes'] / size if size > 0 else 0
        
        # Total I/O amplification (reads + writes)
        write_total_io = write_metrics['total_read_bytes'] + write_metrics['total_write_bytes']
        read_total_io = read_metrics['total_read_bytes'] + read_metrics['total_write_bytes']
        write_total_amp = write_total_io / size if size > 0 else 0
        read_total_amp = read_total_io / size if size > 0 else 0
        
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{name} ({size:,} bytes)")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        print("\nWRITE Operation:")
        print(f"  Syscall writes:     {write_metrics['total_write_bytes']:,} bytes")
        print(f"  Syscall reads:      {write_metrics['total_read_bytes']:,} bytes") 
        print(f"  Total syscall I/O:  {write_total_io:,} bytes")
        print(f"  Write amplification: {write_amp:.2f}x")
        print(f"  Total I/O amplification: {write_total_amp:.2f}x")
        print(f"  xl.meta operations: {write_metrics['xl_meta_ops']}")
        print(f"  Part files:         {write_metrics['part_file_ops']}")
        print(f"  Unique files:       {len(write_metrics['files_accessed'])}")
        
        if write_metrics['syscall_details']:
            print("  Syscall breakdown:")
            for syscall, stats in sorted(write_metrics['syscall_details'].items()):
                if stats['count'] > 0:
                    print(f"    {syscall:10} {stats['count']:4} calls, {stats['bytes']:10,} bytes")
        
        print("\nREAD Operation:")
        print(f"  Syscall reads:      {read_metrics['total_read_bytes']:,} bytes")
        print(f"  Syscall writes:     {read_metrics['total_write_bytes']:,} bytes")
        print(f"  Total syscall I/O:  {read_total_io:,} bytes")
        print(f"  Read amplification: {read_amp:.2f}x")
        print(f"  Total I/O amplification: {read_total_amp:.2f}x")
        print(f"  xl.meta operations: {read_metrics['xl_meta_ops']}")
        print(f"  Part files:         {read_metrics['part_file_ops']}")
        print(f"  Unique files:       {len(read_metrics['files_accessed'])}")
        
        if read_metrics['syscall_details']:
            print("  Syscall breakdown:")
            for syscall, stats in sorted(read_metrics['syscall_details'].items()):
                if stats['count'] > 0:
                    print(f"    {syscall:10} {stats['count']:4} calls, {stats['bytes']:10,} bytes")
        
        print()
        
        # Add to summary
        summary_data.append({
            'size': name,
            'bytes': size,
            'write_bytes': write_metrics['total_write_bytes'],
            'write_amp': write_amp,
            'write_xl_meta': write_metrics['xl_meta_ops'],
            'read_bytes': read_metrics['total_read_bytes'],
            'read_amp': read_amp,
            'read_xl_meta': read_metrics['xl_meta_ops']
        })
    
    # Print summary table
    print("\n" + "=" * 80)
    print("SUMMARY TABLE")
    print("=" * 80)
    print()
    print(f"{'Size':>6} {'Write Bytes':>12} {'Write Amp':>10} {'Read Bytes':>12} {'Read Amp':>10} {'xl.meta W':>10} {'xl.meta R':>10}")
    print("-" * 80)
    
    for data in summary_data:
        print(f"{data['size']:>6} {data['write_bytes']:>12,} {data['write_amp']:>10.2f}x "
              f"{data['read_bytes']:>12,} {data['read_amp']:>10.2f}x "
              f"{data['write_xl_meta']:>10} {data['read_xl_meta']:>10}")
    
    # Key insights
    print("\n" + "=" * 80)
    print("KEY INSIGHTS")
    print("=" * 80)
    print()
    
    # Find patterns
    small_sizes = [d for d in summary_data if d['bytes'] <= 1024]
    large_sizes = [d for d in summary_data if d['bytes'] > 102400]
    
    if small_sizes:
        avg_small_write_amp = sum(d['write_amp'] for d in small_sizes) / len(small_sizes)
        avg_small_read_amp = sum(d['read_amp'] for d in small_sizes) / len(small_sizes)
        print(f"Small objects (≤1KB):")
        print(f"  Average write amplification: {avg_small_write_amp:.2f}x")
        print(f"  Average read amplification:  {avg_small_read_amp:.2f}x")
        print(f"  Typical xl.meta ops: {small_sizes[0]['write_xl_meta']} for write, {small_sizes[0]['read_xl_meta']} for read")
    
    if large_sizes:
        avg_large_write_amp = sum(d['write_amp'] for d in large_sizes) / len(large_sizes)
        avg_large_read_amp = sum(d['read_amp'] for d in large_sizes) / len(large_sizes)
        print(f"\nLarge objects (>100KB):")
        print(f"  Average write amplification: {avg_large_write_amp:.2f}x")
        print(f"  Average read amplification:  {avg_large_read_amp:.2f}x")
        print(f"  Shows part file usage for objects >1MB")
    
    # Metadata overhead analysis
    print(f"\nMetadata Overhead:")
    for data in summary_data:
        if data['write_xl_meta'] > 0:
            # Estimate metadata overhead (assume 4KB per xl.meta operation)
            metadata_overhead = data['write_xl_meta'] * 4096
            metadata_percentage = (metadata_overhead / max(data['write_bytes'], 1)) * 100
            if metadata_percentage > 10:
                print(f"  {data['size']:>6}: ~{metadata_overhead:,} bytes metadata ({metadata_percentage:.1f}% of total I/O)")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    else:
        # Try to find the most recent results
        import glob
        dirs = sorted(glob.glob("strace_capture_*"))
        if dirs:
            results_dir = dirs[-1]
            print(f"Using most recent results: {results_dir}\n")
        else:
            print("Usage: python3 analyze_strace.py <results_directory>")
            sys.exit(1)
    
    analyze_results(results_dir)
