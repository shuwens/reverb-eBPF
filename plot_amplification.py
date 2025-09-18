#!/usr/bin/env python3

# Script to visualize MinIO I/O amplification test results
# File: plot_amplification.py

import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def plot_results(csv_file):
    """Plot the amplification test results"""
    
    # Read the CSV data
    df = pd.read_csv(csv_file)
    
    # Create figure with subplots
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('MinIO I/O Amplification Analysis', fontsize=16, fontweight='bold')
    
    # Object size labels for x-axis
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    x_pos = np.arange(len(size_labels))
    
    # 1. Amplification Factor (log scale)
    ax1 = axes[0, 0]
    ax1.bar(x_pos, df['Amplification'], color='red', alpha=0.7)
    ax1.set_xlabel('Object Size')
    ax1.set_ylabel('Amplification Factor (x)')
    ax1.set_title('I/O Amplification by Object Size')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(size_labels, rotation=45)
    ax1.set_yscale('log')
    ax1.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for i, v in enumerate(df['Amplification']):
        ax1.text(i, v, f'{v:.1f}x', ha='center', va='bottom')
    
    # 2. I/O Distribution Stacked Bar
    ax2 = axes[0, 1]
    width = 0.6
    
    # Create stacked bars
    p1 = ax2.bar(x_pos, df['Data_Percent'], width, label='Data', color='#2ecc71')
    p2 = ax2.bar(x_pos, df['Metadata_Percent'], width, bottom=df['Data_Percent'],
                 label='Metadata', color='#3498db')
    p3 = ax2.bar(x_pos, df['Journal_Percent'], width, 
                 bottom=df['Data_Percent'] + df['Metadata_Percent'],
                 label='Journal', color='#e74c3c')
    
    ax2.set_xlabel('Object Size')
    ax2.set_ylabel('Percentage (%)')
    ax2.set_title('I/O Category Distribution by Object Size')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(size_labels, rotation=45)
    ax2.legend(loc='upper right')
    ax2.set_ylim(0, 100)
    ax2.grid(True, alpha=0.3)
    
    # 3. Amplification Trend Line (log-log plot)
    ax3 = axes[1, 0]
    ax3.loglog(df['Object_Size'], df['Amplification'], 'o-', color='blue', 
               linewidth=2, markersize=8)
    ax3.set_xlabel('Object Size (bytes)')
    ax3.set_ylabel('Amplification Factor (x)')
    ax3.set_title('Amplification vs Object Size (Log-Log Scale)')
    ax3.grid(True, which="both", ls="-", alpha=0.2)
    
    # Add reference lines
    ax3.axhline(y=2, color='green', linestyle='--', alpha=0.5, 
                label='Ideal (2x for replication)')
    ax3.axhline(y=10, color='orange', linestyle='--', alpha=0.5, 
                label='Acceptable (<10x)')
    ax3.axhline(y=100, color='red', linestyle='--', alpha=0.5, 
                label='Poor (>100x)')
    ax3.legend()
    
    # 4. Data vs Overhead Comparison
    ax4 = axes[1, 1]
    
    # Calculate overhead (metadata + journal)
    overhead_percent = df['Metadata_Percent'] + df['Journal_Percent']
    
    x = np.arange(len(size_labels))
    width = 0.35
    
    rects1 = ax4.bar(x - width/2, df['Data_Percent'], width, label='Data %', 
                     color='#27ae60')
    rects2 = ax4.bar(x + width/2, overhead_percent, width, label='Overhead %', 
                     color='#c0392b')
    
    ax4.set_xlabel('Object Size')
    ax4.set_ylabel('Percentage (%)')
    ax4.set_title('Data vs Overhead (Metadata + Journal)')
    ax4.set_xticks(x)
    ax4.set_xticklabels(size_labels, rotation=45)
    ax4.legend()
    ax4.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for rect in rects1:
        height = rect.get_height()
        ax4.annotate(f'{height:.0f}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
    
    for rect in rects2:
        height = rect.get_height()
        ax4.annotate(f'{height:.0f}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    
    # Save the plot
    output_file = csv_file.replace('.csv', '_visualization.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"Plot saved to: {output_file}")
    
    # Also save individual plots
    save_individual_plots(df, csv_file)
    
    plt.show()

def save_individual_plots(df, csv_file):
    """Save individual plots for detailed analysis"""
    
    base_dir = Path(csv_file).parent
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    
    # 1. Amplification comparison
    plt.figure(figsize=(10, 6))
    colors = ['red' if x > 100 else 'orange' if x > 10 else 'green' 
              for x in df['Amplification']]
    plt.bar(size_labels, df['Amplification'], color=colors, alpha=0.7)
    plt.xlabel('Object Size', fontsize=12)
    plt.ylabel('Amplification Factor (x)', fontsize=12)
    plt.title('MinIO I/O Amplification by Object Size', fontsize=14, fontweight='bold')
    plt.yscale('log')
    plt.grid(True, alpha=0.3)
    
    # Add horizontal lines for reference
    plt.axhline(y=2, color='green', linestyle='--', alpha=0.5, label='Ideal (2x)')
    plt.axhline(y=10, color='orange', linestyle='--', alpha=0.5, label='Acceptable')
    plt.axhline(y=100, color='red', linestyle='--', alpha=0.5, label='Poor')
    plt.legend()
    
    for i, v in enumerate(df['Amplification']):
        plt.text(i, v, f'{v:.1f}x', ha='center', va='bottom')
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(base_dir / 'amplification_only.png', dpi=150)
    plt.close()
    
    # 2. I/O distribution pie charts for small vs large objects
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
    
    # Small object (100B)
    small_idx = 2  # 100B
    sizes = [df.iloc[small_idx]['Data_Percent'], 
             df.iloc[small_idx]['Metadata_Percent'],
             df.iloc[small_idx]['Journal_Percent']]
    ax1.pie(sizes, labels=['Data', 'Metadata', 'Journal'], autopct='%1.1f%%',
            colors=['#2ecc71', '#3498db', '#e74c3c'])
    ax1.set_title('100B Object I/O Distribution')
    
    # Medium object (1MB)
    med_idx = 6  # 1MB
    sizes = [df.iloc[med_idx]['Data_Percent'], 
             df.iloc[med_idx]['Metadata_Percent'],
             df.iloc[med_idx]['Journal_Percent']]
    ax2.pie(sizes, labels=['Data', 'Metadata', 'Journal'], autopct='%1.1f%%',
            colors=['#2ecc71', '#3498db', '#e74c3c'])
    ax2.set_title('1MB Object I/O Distribution')
    
    # Large object (100MB)
    large_idx = 8  # 100MB
    sizes = [df.iloc[large_idx]['Data_Percent'], 
             df.iloc[large_idx]['Metadata_Percent'],
             df.iloc[large_idx]['Journal_Percent']]
    ax3.pie(sizes, labels=['Data', 'Metadata', 'Journal'], autopct='%1.1f%%',
            colors=['#2ecc71', '#3498db', '#e74c3c'])
    ax3.set_title('100MB Object I/O Distribution')
    
    plt.suptitle('I/O Distribution Comparison', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(base_dir / 'io_distribution_comparison.png', dpi=150)
    plt.close()
    
    print(f"Additional plots saved to: {base_dir}")

def main():
    if len(sys.argv) < 2:
        # Try to find the most recent results directory
        import glob
        import os
        
        dirs = glob.glob('minio_test_results_*')
        if dirs:
            latest_dir = max(dirs, key=os.path.getctime)
            csv_file = f"{latest_dir}/amplification_data.csv"
            if Path(csv_file).exists():
                print(f"Using latest results: {csv_file}")
                plot_results(csv_file)
            else:
                print(f"Error: CSV file not found in {latest_dir}")
                sys.exit(1)
        else:
            print("Usage: python plot_amplification.py <path_to_amplification_data.csv>")
            print("   or: python plot_amplification.py  (to use latest results)")
            sys.exit(1)
    else:
        csv_file = sys.argv[1]
        if not Path(csv_file).exists():
            print(f"Error: File {csv_file} not found")
            sys.exit(1)
        plot_results(csv_file)

if __name__ == "__main__":
    main()
