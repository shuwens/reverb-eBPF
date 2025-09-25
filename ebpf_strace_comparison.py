#!/usr/bin/env python3

"""
Complete I/O analysis reading from both eBPF and strace result directories
Shows full I/O path: Application → Syscalls → Filesystem → Device
"""

import sys
import re
from pathlib import Path
from collections import defaultdict

def parse_ebpf_trace(filepath):
    """Parse eBPF trace file for metrics"""
    metrics = {
        'app_bytes': 0,
        'os_bytes': 0,
        'device_bytes': 0,
        'amplification': 0
    }
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
            # Look for aggregate statistics section
            if 'AGGREGATE STATISTICS' in content or 'Application layer:' in content:
                # Extract application bytes
                app_match = re.search(r'Application layer:\s+(\d+)\s+bytes', content)
                if app_match:
                    metrics['app_bytes'] = int(app_match.group(1))
                
                # Extract OS bytes
                os_match = re.search(r'OS layer:\s+(\d+)\s+bytes', content)
                if os_match:
                    metrics['os_bytes'] = int(os_match.group(1))
                
                # Extract device bytes
                device_match = re.search(r'Device layer:\s+(\d+)\s+bytes', content)
                if device_match:
                    metrics['device_bytes'] = int(device_match.group(1))
                
                # Extract amplification
                amp_match = re.search(r'TOTAL AMPLIFICATION:\s+([\d.]+)x', content)
                if amp_match:
                    metrics['amplification'] = float(amp_match.group(1))
    except Exception as e:
        print(f"Error parsing eBPF file {filepath}: {e}", file=sys.stderr)
    
    return metrics

def parse_strace_file(filepath):
    """Parse strace file for syscall metrics"""
    metrics = {
        'syscall_writes': 0,
        'syscall_reads': 0,
        'xl_meta_ops': 0,
        'part_files': 0,
        'write_calls': 0,
        'read_calls': 0,
        'pwrite_calls': 0,
        'pread_calls': 0,
        'files_accessed': set(),
        'fd_to_file': {}
    }
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                # Track file opens
                if 'openat(' in line or 'open(' in line:
                    fd_match = re.search(r'= (\d+)', line)
                    path_match = re.search(r'"([^"]+)"', line)
                    
                    if fd_match and path_match:
                        fd_val = int(fd_match.group(1))
                        if fd_val >= 0:
                            fd = str(fd_val)
                            path = path_match.group(1)
                            metrics['fd_to_file'][fd] = path
                            metrics['files_accessed'].add(path)
                            
                            if 'xl.meta' in path:
                                metrics['xl_meta_ops'] += 1
                            if '/part.' in path or 'part-' in path:
                                metrics['part_files'] += 1
                
                # Parse write syscalls
                if 'write(' in line and '= ' in line:
                    match = re.search(r'write\((\d+),.*?\)\s*=\s*(\d+)', line)
                    if match:
                        bytes_written = int(match.group(2))
                        if bytes_written > 0:
                            metrics['syscall_writes'] += bytes_written
                            metrics['write_calls'] += 1
                
                # Parse pwrite64 syscalls
                if 'pwrite64(' in line and '= ' in line:
                    match = re.search(r'pwrite64\((\d+),.*?\)\s*=\s*(\d+)', line)
                    if match:
                        bytes_written = int(match.group(2))
                        if bytes_written > 0:
                            metrics['syscall_writes'] += bytes_written
                            metrics['pwrite_calls'] += 1
                
                # Parse read syscalls
                if 'read(' in line and '= ' in line and 'bread' not in line:
                    match = re.search(r'read\((\d+),.*?\)\s*=\s*(\d+)', line)
                    if match:
                        bytes_read = int(match.group(2))
                        if bytes_read > 0:
                            metrics['syscall_reads'] += bytes_read
                            metrics['read_calls'] += 1
                
                # Parse pread64 syscalls
                if 'pread64(' in line and '= ' in line:
                    match = re.search(r'pread64\((\d+),.*?\)\s*=\s*(\d+)', line)
                    if match:
                        bytes_read = int(match.group(2))
                        if bytes_read > 0:
                            metrics['syscall_reads'] += bytes_read
                            metrics['pread_calls'] += 1
                            
    except Exception as e:
        print(f"Error parsing strace file {filepath}: {e}", file=sys.stderr)
    
    return metrics

def analyze_directories(ebpf_dir, strace_dir):
    """Analyze both eBPF and strace directories"""
    
    sizes = {
        '1B': 1, '10B': 10, '100B': 100, '1KB': 1024, '10KB': 10240,
        '100KB': 102400, '1MB': 1048576, '10MB': 10485760, '100MB': 104857600
    }
    
    print("=" * 120)
    print("COMPLETE I/O ANALYSIS: eBPF + STRACE")
    print(f"eBPF Directory: {ebpf_dir}")
    print(f"Strace Directory: {strace_dir}")
    print("=" * 120)
    print()
    print("I/O Path: Application Request → MinIO Syscalls → Filesystem Layer → Block Device")
    print()
    
    # Process each size
    for size_name, size_bytes in sizes.items():
        print(f"\n{'='*120}")
        print(f"{size_name} ({size_bytes:,} bytes)")
        print('='*120)
        
        # Find eBPF files
        ebpf_write = None
        ebpf_read = None
        
        # Try different possible paths for eBPF traces
        for subdir in ['write_traces', 'write', 'traces']:
            path = Path(ebpf_dir) / subdir / f'{size_name}_write.log'
            if not path.exists():
                path = Path(ebpf_dir) / subdir / f'{size_name}_write.trace'
            if path.exists():
                ebpf_write = path
                break
        
        for subdir in ['read_traces', 'read', 'traces']:
            path = Path(ebpf_dir) / subdir / f'{size_name}_read.log'
            if not path.exists():
                path = Path(ebpf_dir) / subdir / f'{size_name}_read.trace'
            if path.exists():
                ebpf_read = path
                break
        
        # Find strace files
        strace_write = Path(strace_dir) / 'write' / f'{size_name}_write.strace'
        strace_read = Path(strace_dir) / 'read' / f'{size_name}_read.strace'
        
        # WRITE OPERATION ANALYSIS
        print("\n" + "─"*80)
        print("WRITE OPERATION")
        print("─"*80)
        
        if ebpf_write and ebpf_write.exists() and strace_write.exists():
            ebpf_metrics = parse_ebpf_trace(ebpf_write)
            strace_metrics = parse_strace_file(strace_write)
            
            print(f"\n1. APPLICATION LAYER (eBPF):")
            print(f"   Request size:        {size_bytes:,} bytes")
            print(f"   Application bytes:   {ebpf_metrics['app_bytes']:,} bytes (includes protocol overhead)")
            
            print(f"\n2. SYSCALL LAYER (strace):")
            print(f"   Syscall writes:      {strace_metrics['syscall_writes']:,} bytes")
            print(f"   Syscall reads:       {strace_metrics['syscall_reads']:,} bytes")
            print(f"   Total syscall I/O:   {strace_metrics['syscall_writes'] + strace_metrics['syscall_reads']:,} bytes")
            print(f"   write() calls:       {strace_metrics['write_calls']}")
            print(f"   pwrite64() calls:    {strace_metrics['pwrite_calls']}")
            print(f"   xl.meta operations:  {strace_metrics['xl_meta_ops']}")
            print(f"   Part files:          {strace_metrics['part_files']}")
            
            print(f"\n3. OS LAYER (eBPF):")
            print(f"   OS layer bytes:      {ebpf_metrics['os_bytes']:,} bytes")
            
            print(f"\n4. DEVICE LAYER (eBPF):")
            print(f"   Device I/O:          {ebpf_metrics['device_bytes']:,} bytes")
            print(f"   Block amplification: {ebpf_metrics['device_bytes']/size_bytes:.2f}x")
            
            print(f"\n5. AMPLIFICATION BREAKDOWN:")
            syscall_amp = (strace_metrics['syscall_writes'] + strace_metrics['syscall_reads']) / size_bytes if size_bytes > 0 else 0
            device_amp = ebpf_metrics['device_bytes'] / size_bytes if size_bytes > 0 else 0
            
            print(f"   Syscall amplification: {syscall_amp:.2f}x (what MinIO requests)")
            print(f"   Device amplification:  {device_amp:.2f}x (what hits disk)")
            print(f"   Gap factor:           {device_amp/syscall_amp if syscall_amp > 0 else 0:.2f}x (filesystem overhead)")
            
            # Explain the gap
            if ebpf_metrics['device_bytes'] > (strace_metrics['syscall_writes'] + strace_metrics['syscall_reads']):
                gap = ebpf_metrics['device_bytes'] - (strace_metrics['syscall_writes'] + strace_metrics['syscall_reads'])
                print(f"\n   EXPLANATION:")
                print(f"   - MinIO wrote {strace_metrics['syscall_writes']:,} bytes via syscalls")
                print(f"   - Filesystem wrote {ebpf_metrics['device_bytes']:,} bytes to disk")
                print(f"   - Gap of {gap:,} bytes due to:")
                if size_bytes <= 4096:
                    print(f"     * Minimum block size (4KB)")
                    print(f"     * Metadata blocks for xl.meta files")
                else:
                    print(f"     * Block alignment and filesystem metadata")
        else:
            print(f"   Missing files - eBPF: {ebpf_write}, strace: {strace_write}")
        
        # READ OPERATION ANALYSIS
        print("\n" + "─"*80)
        print("READ OPERATION")
        print("─"*80)
        
        if ebpf_read and ebpf_read.exists() and strace_read.exists():
            ebpf_metrics = parse_ebpf_trace(ebpf_read)
            strace_metrics = parse_strace_file(strace_read)
            
            print(f"\n1. APPLICATION LAYER (eBPF):")
            print(f"   Request size:        {size_bytes:,} bytes")
            print(f"   Application bytes:   {ebpf_metrics['app_bytes']:,} bytes")
            
            print(f"\n2. SYSCALL LAYER (strace):")
            print(f"   Syscall reads:       {strace_metrics['syscall_reads']:,} bytes")
            print(f"   Syscall writes:      {strace_metrics['syscall_writes']:,} bytes")
            print(f"   Total syscall I/O:   {strace_metrics['syscall_reads'] + strace_metrics['syscall_writes']:,} bytes")
            print(f"   read() calls:        {strace_metrics['read_calls']}")
            print(f"   pread64() calls:     {strace_metrics['pread_calls']}")
            print(f"   xl.meta operations:  {strace_metrics['xl_meta_ops']}")
            
            print(f"\n3. OS LAYER (eBPF):")
            print(f"   OS layer bytes:      {ebpf_metrics['os_bytes']:,} bytes")
            
            print(f"\n4. DEVICE LAYER (eBPF):")
            print(f"   Device I/O:          {ebpf_metrics['device_bytes']:,} bytes")
            print(f"   Block amplification: {ebpf_metrics['device_bytes']/size_bytes:.2f}x")
            
            print(f"\n5. AMPLIFICATION BREAKDOWN:")
            syscall_amp = (strace_metrics['syscall_reads'] + strace_metrics['syscall_writes']) / size_bytes if size_bytes > 0 else 0
            device_amp = ebpf_metrics['device_bytes'] / size_bytes if size_bytes > 0 else 0
            
            print(f"   Syscall amplification: {syscall_amp:.2f}x")
            print(f"   Device amplification:  {device_amp:.2f}x")
            print(f"   Gap factor:           {device_amp/syscall_amp if syscall_amp > 0 else 0:.2f}x")
    
    # Summary table
    print("\n" + "=" * 120)
    print("SUMMARY TABLE")
    print("=" * 120)
    print()
    print(f"{'Size':>6} | {'──────── WRITE ────────'} | {'──────── READ ────────'}")
    print(f"{'':>6} | {'Syscalls':>10} {'Device':>10} {'Amp':>8} | {'Syscalls':>10} {'Device':>10} {'Amp':>8}")
    print("-" * 70)
    
    for size_name, size_bytes in sizes.items():
        # Parse files again for summary
        ebpf_write = None
        ebpf_read = None
        for subdir in ['write_traces', 'write', 'traces']:
            path = Path(ebpf_dir) / subdir / f'{size_name}_write.log'
            if not path.exists():
                path = Path(ebpf_dir) / subdir / f'{size_name}_write.trace'
            if path.exists():
                ebpf_write = path
                break
        
        for subdir in ['read_traces', 'read', 'traces']:
            path = Path(ebpf_dir) / subdir / f'{size_name}_read.log'
            if not path.exists():
                path = Path(ebpf_dir) / subdir / f'{size_name}_read.trace'
            if path.exists():
                ebpf_read = path
                break
        
        strace_write = Path(strace_dir) / 'write' / f'{size_name}_write.strace'
        strace_read = Path(strace_dir) / 'read' / f'{size_name}_read.strace'
        
        if ebpf_write and ebpf_write.exists() and strace_write.exists() and \
           ebpf_read and ebpf_read.exists() and strace_read.exists():
            
            w_ebpf = parse_ebpf_trace(ebpf_write)
            w_strace = parse_strace_file(strace_write)
            r_ebpf = parse_ebpf_trace(ebpf_read)
            r_strace = parse_strace_file(strace_read)
            
            w_syscalls = w_strace['syscall_writes'] + w_strace['syscall_reads']
            r_syscalls = r_strace['syscall_reads'] + r_strace['syscall_writes']
            w_amp = w_ebpf['device_bytes'] / size_bytes if size_bytes > 0 else 0
            r_amp = r_ebpf['device_bytes'] / size_bytes if size_bytes > 0 else 0
            
            print(f"{size_name:>6} | {w_syscalls:>10,} {w_ebpf['device_bytes']:>10,} {w_amp:>8.1f}x | "
                  f"{r_syscalls:>10,} {r_ebpf['device_bytes']:>10,} {r_amp:>8.1f}x")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        ebpf_dir = sys.argv[1]
        strace_dir = sys.argv[2]
    else:
        # Try to find directories
        import glob
        ebpf_dirs = sorted(glob.glob("*rw_results_*"))
        strace_dirs = sorted(glob.glob("strace_capture_*"))
        
        if ebpf_dirs and strace_dirs:
            ebpf_dir = ebpf_dirs[-1]
            strace_dir = strace_dirs[-1]
            print(f"Using eBPF dir: {ebpf_dir}")
            print(f"Using strace dir: {strace_dir}")
        else:
            print("Usage: python3 complete_io_analysis.py <ebpf_dir> <strace_dir>")
            print("Example: python3 complete_io_analysis.py separate_rw_results_20250924_143255 strace_capture_20250924_161320")
            sys.exit(1)
    
    analyze_directories(ebpf_dir, strace_dir)


