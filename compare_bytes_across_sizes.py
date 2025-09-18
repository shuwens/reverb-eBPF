#!/usr/bin/env python3

# Script to compare actual bytes across different object sizes
# File: compare_bytes_across_sizes.py

import sys
import json
import glob
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

def load_all_analyses(results_dir):
    """Load all JSON analysis files from a results directory"""
    
    sizes = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    data = {}
    
    for size in sizes:
        json_file = Path(results_dir) / f"{size}_trace_bytes_data.json"
        if json_file.exists():
            with open(json_file, 'r') as f:
                data[size] = json.load(f)
        else:
            # Try alternative naming
            json_files = glob.glob(f"{results_dir}/*{size}*bytes_data.json")
            if json_files:
                with open(json_files[0], 'r') as f:
                    data[size] = json.load(f)
    
    return data

def generate_comparison_table(data):
    """Generate a comparison table of actual bytes"""
    
    print("=" * 120)
    print("ACTUAL BYTES COMPARISON ACROSS OBJECT SIZES")
    print("=" * 120)
    print()
    
    # Header
    header = f"{'Size':>8s} | {'App Bytes':>12s} | {'OS Bytes':>12s} | {'Device Bytes':>12s} | {'Amplif':>7s} | {'Journal':>10s} | {'Metadata':>10s}"
    print(header)
    print("-" * 120)
    
    results = []
    
    for size in ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']:
        if size in data:
            d = data[size]
            app_bytes = d['summary']['application_total']
            os_bytes = d['summary']['os_total']
            device_bytes = d['summary']['device_total']
            journal_bytes = d['summary']['filesystem_total']
            metadata_bytes = d['summary']['storage_total']
            amplification = d.get('amplification', 0)
            
            row = f"{size:>8s} | {app_bytes:>12,d} | {os_bytes:>12,d} | {device_bytes:>12,d} | {amplification:>7.1f}x | {journal_bytes:>10,d} | {metadata_bytes:>10,d}"
            print(row)
            
            results.append({
                'size': size,
                'app_bytes': app_bytes,
                'os_bytes': os_bytes,
                'device_bytes': device_bytes,
                'amplification': amplification,
                'journal_bytes': journal_bytes,
                'metadata_bytes': metadata_bytes
            })
    
    print("-" * 120)
    
    # Calculate totals
    if results:
        total_app = sum(r['app_bytes'] for r in results)
        total_os = sum(r['os_bytes'] for r in results)
        total_device = sum(r['device_bytes'] for r in results)
        total_journal = sum(r['journal_bytes'] for r in results)
        total_metadata = sum(r['metadata_bytes'] for r in results)
        
        if total_app > 0:
            avg_amp = total_device / total_app
        else:
            avg_amp = 0
        
        total_row = f"{'TOTAL':>8s} | {total_app:>12,d} | {total_os:>12,d} | {total_device:>12,d} | {avg_amp:>7.1f}x | {total_journal:>10,d} | {total_metadata:>10,d}"
        print(total_row)
    
    return results

def visualize_bytes_flow(data):
    """Create a Sankey-like diagram showing byte flow through layers"""
    
    fig, axes = plt.subplots(3, 3, figsize=(15, 12))
    fig.suptitle('Actual Bytes Flow Through I/O Layers', fontsize=16, fontweight='bold')
    
    sizes = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    
    for idx, size in enumerate(sizes):
        ax = axes[idx // 3, idx % 3]
        
        if size in data:
            d = data[size]
            
            # Extract values
            app = d['summary']['application_total']
            os = d['summary']['os_total']
            device = d['summary']['device_total']
            
            # Create bar chart showing progression
            layers = ['Application', 'OS', 'Device']
            values = [app, os, device]
            colors = ['#3498db', '#e74c3c', '#2ecc71']
            
            bars = ax.bar(layers, values, color=colors, alpha=0.7)
            
            # Add value labels
            for bar, val in zip(bars, values):
                height = bar.get_height()
                if val < 1000:
                    label = f'{val}B'
                elif val < 1000000:
                    label = f'{val/1024:.1f}KB'
                else:
                    label = f'{val/1048576:.1f}MB'
                
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       label, ha='center', va='bottom', fontsize=9)
            
            # Add amplification factor
            amp = d.get('amplification', 0)
            ax.set_title(f'{size} (Amp: {amp:.1f}x)', fontsize=11, fontweight='bold')
            ax.set_ylabel('Bytes', fontsize=9)
            ax.set_yscale('log')
            ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return fig

def generate_detailed_report(data):
    """Generate a detailed report with breakdowns"""
    
    report = []
    report.append("\n" + "=" * 80)
    report.append("DETAILED BYTE-LEVEL ANALYSIS")
    report.append("=" * 80)
    
    for size in ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']:
        if size not in data:
            continue
            
        d = data[size]
        report.append(f"\n{size} Object Analysis:")
        report.append("-" * 40)
        
        # Application layer details
        app_details = d.get('details', {}).get('application', {})
        if app_details:
            report.append(f"Application Layer:")
            report.append(f"  PUT operations: {app_details.get('put_count', 0)} ({app_details.get('put_bytes', 0):,} bytes)")
            report.append(f"  GET operations: {app_details.get('get_count', 0)} ({app_details.get('get_bytes', 0):,} bytes)")
        
        # OS layer details
        os_details = d.get('details', {}).get('os', {})
        if os_details:
            report.append(f"OS Layer:")
            report.append(f"  Write operations: {os_details.get('write_count', 0)} ({os_details.get('write_bytes', 0):,} bytes)")
            report.append(f"  Read operations: {os_details.get('read_count', 0)} ({os_details.get('read_bytes', 0):,} bytes)")
        
        # Device layer details
        device_details = d.get('details', {}).get('device', {})
        if device_details:
            report.append(f"Device Layer:")
            report.append(f"  BIO submits: {device_details.get('submit_count', 0)} ({device_details.get('submit_bytes', 0):,} bytes)")
        
        # Calculate waste
        app_total = d['summary']['application_total']
        device_total = d['summary']['device_total']
        
        if app_total > 0:
            waste = device_total - app_total
            waste_percent = (waste / device_total) * 100
            report.append(f"Waste Analysis:")
            report.append(f"  Useful data: {app_total:,} bytes")
            report.append(f"  Wasted I/O: {waste:,} bytes ({waste_percent:.1f}%)")
    
    return "\n".join(report)

def create_waste_analysis_chart(data):
    """Create a chart showing wasted I/O for each size"""
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    sizes = []
    useful_data = []
    wasted_io = []
    waste_percentages = []
    
    for size in ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']:
        if size in data:
            d = data[size]
            app = d['summary']['application_total']
            device = d['summary']['device_total']
            
            if device > 0:
                waste = device - app
                waste_pct = (waste / device) * 100
                
                sizes.append(size)
                useful_data.append(app)
                wasted_io.append(waste)
                waste_percentages.append(waste_pct)
    
    # Stacked bar chart
    x_pos = range(len(sizes))
    
    p1 = ax1.bar(x_pos, useful_data, label='Useful Data', color='#27ae60', alpha=0.8)
    p2 = ax1.bar(x_pos, wasted_io, bottom=useful_data, label='Wasted I/O', 
                 color='#e74c3c', alpha=0.8)
    
    ax1.set_xlabel('Object Size', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Bytes', fontsize=12, fontweight='bold')
    ax1.set_title('Useful Data vs Wasted I/O', fontsize=14, fontweight='bold')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(sizes, rotation=45)
    ax1.set_yscale('log')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Waste percentage chart
    colors = ['#e74c3c' if x > 90 else '#f39c12' if x > 50 else '#27ae60' 
              for x in waste_percentages]
    bars = ax2.bar(x_pos, waste_percentages, color=colors, alpha=0.8)
    
    for bar, pct in zip(bars, waste_percentages):
        ax2.text(bar.get_x() + bar.get_width()/2., pct,
                f'{pct:.0f}%', ha='center', va='bottom', fontsize=9)
    
    ax2.set_xlabel('Object Size', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Waste Percentage (%)', fontsize=12, fontweight='bold')
    ax2.set_title('I/O Waste Percentage by Object Size', fontsize=14, fontweight='bold')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(sizes, rotation=45)
    ax2.set_ylim(0, 105)
    ax2.axhline(y=50, color='gray', linestyle='--', alpha=0.5, label='50% threshold')
    ax2.axhline(y=90, color='red', linestyle='--', alpha=0.5, label='90% threshold')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return fig

def main():
    if len(sys.argv) < 2:
        # Try to find the most recent results directory
        dirs = glob.glob('minio_test_results_*')
        if dirs:
            import os
            results_dir = max(dirs, key=os.path.getctime)
            print(f"Using latest results directory: {results_dir}")
        else:
            print("Usage: python compare_bytes_across_sizes.py <results_directory>")
            sys.exit(1)
    else:
        results_dir = sys.argv[1]
    
    # First, parse all trace files if JSON files don't exist
    trace_files = glob.glob(f"{results_dir}/*_trace.log")
    
    print(f"Found {len(trace_files)} trace files")
    print("Parsing trace files to extract actual bytes...")
    print("-" * 40)
    
    for trace_file in trace_files:
        json_file = trace_file.replace('.log', '_bytes_data.json')
        if not Path(json_file).exists():
            print(f"Parsing {Path(trace_file).name}...")
            # Import the parser
            from parse_actual_bytes import IOTraceParser
            
            parser = IOTraceParser(trace_file)
            parser.parse_file()
            parser.export_json(json_file)
    
    # Load all analyses
    data = load_all_analyses(results_dir)
    
    if not data:
        print("No analysis data found!")
        sys.exit(1)
    
    # Generate comparison table
    results = generate_comparison_table(data)
    
    # Generate detailed report
    detailed_report = generate_detailed_report(data)
    print(detailed_report)
    
    # Save report
    report_file = Path(results_dir) / "bytes_comparison_report.txt"
    with open(report_file, 'w') as f:
        f.write("ACTUAL BYTES COMPARISON REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(detailed_report)
    print(f"\nReport saved to: {report_file}")
    
    # Create visualizations
    fig1 = visualize_bytes_flow(data)
    fig1.savefig(Path(results_dir) / 'bytes_flow_comparison.pdf', format='pdf', dpi=150)
    
    fig2 = create_waste_analysis_chart(data)
    fig2.savefig(Path(results_dir) / 'io_waste_analysis.pdf', format='pdf', dpi=150)
    
    print(f"Visualizations saved to {results_dir}/")
    
    plt.show()

if __name__ == "__main__":
    main()
