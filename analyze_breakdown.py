#!/usr/bin/env python3
import sys
import re
import glob

def parse_log(filename):
    """Parse a single log file for I/O breakdown"""
    stats = {
        'size': filename.split('_')[1],
        'layers': {},
        'io_types': {'data': 0, 'metadata': 0, 'journal': 0},
        'amplification': 0,
        'events': []
    }
    
    with open(filename, 'r') as f:
        for line in f:
            # Parse layer statistics
            for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
                if layer in line:
                    # Extract size values
                    match = re.search(r'(\d+)\s+(\d+)', line)
                    if match:
                        size = int(match.group(1))
                        aligned = int(match.group(2))
                        
                        if layer not in stats['layers']:
                            stats['layers'][layer] = {
                                'size': 0, 'aligned': 0, 
                                'metadata': 0, 'journal': 0, 'data': 0
                            }
                        
                        stats['layers'][layer]['size'] += size
                        stats['layers'][layer]['aligned'] += aligned
                        
                        # Categorize I/O type
                        if '[META]' in line or 'XL_META' in line:
                            stats['layers'][layer]['metadata'] += size
                            stats['io_types']['metadata'] += size
                        elif '[JRNL]' in line or 'FS_SYNC' in line:
                            stats['layers'][layer]['journal'] += size
                            stats['io_types']['journal'] += size
                        else:
                            stats['layers'][layer]['data'] += size
                            stats['io_types']['data'] += size
            
            # Extract total amplification
            if 'TOTAL AMPLIFICATION' in line:
                match = re.search(r'(\d+\.?\d*)x', line)
                if match:
                    stats['amplification'] = float(match.group(1))
    
    return stats

def print_detailed_report(stats):
    """Print detailed breakdown for a single test"""
    print(f"\n{'='*60}")
    print(f"I/O BREAKDOWN: {stats['size']} Object")
    print(f"{'='*60}")
    
    print("\nPER-LAYER BREAKDOWN:")
    print(f"{'Layer':<15} {'Size':<10} {'Aligned':<10} {'Data':<10} {'Metadata':<10} {'Journal':<10}")
    print("-" * 75)
    
    for layer in ['APPLICATION', 'STORAGE_SVC', 'OS', 'FILESYSTEM', 'DEVICE']:
        if layer in stats['layers']:
            l = stats['layers'][layer]
            print(f"{layer:<15} {l['size']:<10} {l['aligned']:<10} "
                  f"{l['data']:<10} {l['metadata']:<10} {l['journal']:<10}")
    
    print(f"\nI/O TYPE TOTALS:")
    total = sum(stats['io_types'].values())
    if total > 0:
        print(f"  Data:     {stats['io_types']['data']:8} bytes ({stats['io_types']['data']*100/total:.1f}%)")
        print(f"  Metadata: {stats['io_types']['metadata']:8} bytes ({stats['io_types']['metadata']*100/total:.1f}%)")
        print(f"  Journal:  {stats['io_types']['journal']:8} bytes ({stats['io_types']['journal']*100/total:.1f}%)")
    
    print(f"\nTOTAL AMPLIFICATION: {stats['amplification']:.2f}x")

def compare_all_sizes():
    """Compare all test results"""
    files = sorted(glob.glob("minio_*_analysis.log"))
    all_stats = []
    
    for f in files:
        stats = parse_log(f)
        all_stats.append(stats)
        print_detailed_report(stats)
    
    # Summary comparison
    print(f"\n{'='*60}")
    print("COMPARATIVE SUMMARY")
    print(f"{'='*60}")
    print(f"{'Size':<10} {'Amplification':<15} {'Data%':<10} {'Metadata%':<12} {'Journal%':<10}")
    print("-" * 60)
    
    for stats in all_stats:
        total = sum(stats['io_types'].values())
        if total > 0:
            data_pct = stats['io_types']['data'] * 100 / total
            meta_pct = stats['io_types']['metadata'] * 100 / total
            jrnl_pct = stats['io_types']['journal'] * 100 / total
            print(f"{stats['size']:<10} {stats['amplification']:<15.1f} "
                  f"{data_pct:<10.1f} {meta_pct:<12.1f} {jrnl_pct:<10.1f}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Analyze single file
        stats = parse_log(sys.argv[1])
        print_detailed_report(stats)
    else:
        # Analyze all files
        compare_all_sizes()
