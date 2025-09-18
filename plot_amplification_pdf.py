#!/usr/bin/env python3

# Script to generate individual PDF plots for MinIO I/O amplification analysis
# File: plot_amplification_pdf.py

import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.backends.backend_pdf as pdf_backend
import numpy as np
from pathlib import Path
import datetime

# Set the default font and style
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11

def create_amplification_plot(df, output_dir):
    """Create amplification factor bar plot"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    x_pos = np.arange(len(size_labels))
    
    # Color bars based on amplification level
    colors = ['#e74c3c' if x > 100 else '#f39c12' if x > 10 else '#27ae60' 
              for x in df['Amplification']]
    
    bars = ax.bar(x_pos, df['Amplification'], color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
    
    # Add value labels on bars
    for i, (bar, val) in enumerate(zip(bars, df['Amplification'])):
        height = bar.get_height()
        if val >= 1000:
            label = f'{val/1000:.1f}K×'
        else:
            label = f'{val:.1f}×'
        ax.text(bar.get_x() + bar.get_width()/2., height,
                label, ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    # Add reference lines
    ax.axhline(y=2, color='green', linestyle='--', alpha=0.5, linewidth=2, label='Ideal (2× for replication)')
    ax.axhline(y=10, color='orange', linestyle='--', alpha=0.5, linewidth=2, label='Acceptable (<10×)')
    ax.axhline(y=100, color='red', linestyle='--', alpha=0.5, linewidth=2, label='Poor (>100×)')
    
    ax.set_xlabel('Object Size', fontsize=14, fontweight='bold')
    ax.set_ylabel('Amplification Factor (×)', fontsize=14, fontweight='bold')
    ax.set_title('MinIO I/O Amplification by Object Size', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(size_labels, fontsize=12)
    ax.set_yscale('log')
    ax.set_ylim(1, max(df['Amplification']) * 2)
    ax.legend(loc='upper right', fontsize=11)
    ax.grid(True, alpha=0.3, linestyle='--')
    
    # Add timestamp and info
    fig.text(0.99, 0.01, f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}',
             ha='right', va='bottom', fontsize=9, alpha=0.7)
    
    plt.tight_layout()
    pdf_path = output_dir / 'amplification_factor.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_io_distribution_plot(df, output_dir):
    """Create stacked bar chart for I/O distribution"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    x_pos = np.arange(len(size_labels))
    width = 0.7
    
    # Create stacked bars
    p1 = ax.bar(x_pos, df['Data_Percent'], width, label='Data I/O', 
                color='#2ecc71', edgecolor='black', linewidth=1)
    p2 = ax.bar(x_pos, df['Metadata_Percent'], width, bottom=df['Data_Percent'],
                label='Metadata I/O', color='#3498db', edgecolor='black', linewidth=1)
    p3 = ax.bar(x_pos, df['Journal_Percent'], width, 
                bottom=df['Data_Percent'] + df['Metadata_Percent'],
                label='Journal I/O', color='#e74c3c', edgecolor='black', linewidth=1)
    
    # Add percentage labels
    for i in range(len(size_labels)):
        # Data percentage
        if df['Data_Percent'][i] > 5:
            ax.text(i, df['Data_Percent'][i]/2, f"{df['Data_Percent'][i]:.0f}%",
                    ha='center', va='center', fontweight='bold', color='white')
        
        # Metadata percentage
        if df['Metadata_Percent'][i] > 5:
            ax.text(i, df['Data_Percent'][i] + df['Metadata_Percent'][i]/2,
                    f"{df['Metadata_Percent'][i]:.0f}%",
                    ha='center', va='center', fontweight='bold', color='white')
        
        # Journal percentage
        if df['Journal_Percent'][i] > 5:
            ax.text(i, df['Data_Percent'][i] + df['Metadata_Percent'][i] + df['Journal_Percent'][i]/2,
                    f"{df['Journal_Percent'][i]:.0f}%",
                    ha='center', va='center', fontweight='bold', color='white')
    
    ax.set_xlabel('Object Size', fontsize=14, fontweight='bold')
    ax.set_ylabel('Percentage of Total I/O (%)', fontsize=14, fontweight='bold')
    ax.set_title('I/O Category Distribution by Object Size', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(size_labels, fontsize=12)
    ax.legend(loc='upper left', fontsize=12)
    ax.set_ylim(0, 100)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    
    plt.tight_layout()
    pdf_path = output_dir / 'io_distribution.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_loglog_plot(df, output_dir):
    """Create log-log plot of amplification vs size"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Plot the main trend
    ax.loglog(df['Object_Size'], df['Amplification'], 'o-', color='#2c3e50', 
              linewidth=3, markersize=10, markerfacecolor='#3498db', 
              markeredgecolor='#2c3e50', markeredgewidth=2, label='Measured Amplification')
    
    # Add reference lines
    ax.axhline(y=2, color='#27ae60', linestyle='--', alpha=0.7, linewidth=2,
              label='Ideal (2× replication)')
    ax.axhline(y=10, color='#f39c12', linestyle='--', alpha=0.7, linewidth=2,
              label='Acceptable threshold (10×)')
    ax.axhline(y=100, color='#e74c3c', linestyle='--', alpha=0.7, linewidth=2,
              label='Poor performance (100×)')
    
    # Add annotations for key points
    for i, label in enumerate(['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']):
        if i % 2 == 0:  # Annotate every other point to avoid crowding
            ax.annotate(label, 
                       xy=(df['Object_Size'][i], df['Amplification'][i]),
                       xytext=(10, 10), textcoords='offset points',
                       fontsize=9, alpha=0.8,
                       bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.3))
    
    ax.set_xlabel('Object Size (bytes)', fontsize=14, fontweight='bold')
    ax.set_ylabel('Amplification Factor (×)', fontsize=14, fontweight='bold')
    ax.set_title('I/O Amplification vs Object Size (Log-Log Scale)', 
                fontsize=16, fontweight='bold', pad=20)
    ax.grid(True, which="both", ls="--", alpha=0.3)
    ax.legend(loc='upper right', fontsize=11)
    
    # Set axis limits
    ax.set_xlim(0.5, 200000000)
    ax.set_ylim(1, max(df['Amplification']) * 2)
    
    plt.tight_layout()
    pdf_path = output_dir / 'amplification_loglog.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_overhead_comparison_plot(df, output_dir):
    """Create comparison of data vs overhead"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    overhead_percent = df['Metadata_Percent'] + df['Journal_Percent']
    
    x = np.arange(len(size_labels))
    width = 0.35
    
    # Create bars
    bars1 = ax.bar(x - width/2, df['Data_Percent'], width, label='Data %',
                   color='#27ae60', alpha=0.8, edgecolor='black', linewidth=1.5)
    bars2 = ax.bar(x + width/2, overhead_percent, width, label='Overhead % (Metadata + Journal)',
                   color='#c0392b', alpha=0.8, edgecolor='black', linewidth=1.5)
    
    # Add value labels
    for bar in bars1:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.0f}%', ha='center', va='bottom',
                fontweight='bold', fontsize=10)
    
    for bar in bars2:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.0f}%', ha='center', va='bottom',
                fontweight='bold', fontsize=10)
    
    # Add 50% reference line
    ax.axhline(y=50, color='gray', linestyle=':', alpha=0.5, linewidth=2)
    ax.text(len(size_labels)-0.5, 51, '50% threshold', fontsize=10, alpha=0.7)
    
    ax.set_xlabel('Object Size', fontsize=14, fontweight='bold')
    ax.set_ylabel('Percentage of Total I/O (%)', fontsize=14, fontweight='bold')
    ax.set_title('Data vs Overhead (Metadata + Journal) Comparison', 
                fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, fontsize=12)
    ax.legend(loc='upper right', fontsize=12)
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3, axis='y', linestyle='--')
    
    plt.tight_layout()
    pdf_path = output_dir / 'data_vs_overhead.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_pie_charts_comparison(df, output_dir):
    """Create pie charts comparing small, medium, and large objects"""
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    
    # Define indices for different sizes
    small_idx = 2   # 100B
    medium_idx = 6  # 1MB
    large_idx = 8   # 100MB
    
    colors = ['#2ecc71', '#3498db', '#e74c3c']
    
    # Small object (100B)
    sizes_small = [df.iloc[small_idx]['Data_Percent'],
                   df.iloc[small_idx]['Metadata_Percent'],
                   df.iloc[small_idx]['Journal_Percent']]
    wedges1, texts1, autotexts1 = axes[0].pie(sizes_small, labels=['Data', 'Metadata', 'Journal'],
                                                autopct='%1.1f%%', colors=colors,
                                                startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    axes[0].set_title('100B Object\nI/O Distribution', fontsize=14, fontweight='bold')
    
    # Medium object (1MB)
    sizes_medium = [df.iloc[medium_idx]['Data_Percent'],
                    df.iloc[medium_idx]['Metadata_Percent'],
                    df.iloc[medium_idx]['Journal_Percent']]
    wedges2, texts2, autotexts2 = axes[1].pie(sizes_medium, labels=['Data', 'Metadata', 'Journal'],
                                                autopct='%1.1f%%', colors=colors,
                                                startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    axes[1].set_title('1MB Object\nI/O Distribution', fontsize=14, fontweight='bold')
    
    # Large object (100MB)
    sizes_large = [df.iloc[large_idx]['Data_Percent'],
                   df.iloc[large_idx]['Metadata_Percent'],
                   df.iloc[large_idx]['Journal_Percent']]
    wedges3, texts3, autotexts3 = axes[2].pie(sizes_large, labels=['Data', 'Metadata', 'Journal'],
                                                autopct='%1.1f%%', colors=colors,
                                                startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    axes[2].set_title('100MB Object\nI/O Distribution', fontsize=14, fontweight='bold')
    
    # Make percentage text white for better visibility
    for autotext in autotexts1 + autotexts2 + autotexts3:
        autotext.set_color('white')
    
    plt.suptitle('I/O Distribution Comparison: Small vs Medium vs Large Objects',
                 fontsize=16, fontweight='bold', y=1.05)
    
    plt.tight_layout()
    pdf_path = output_dir / 'io_distribution_pies.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_summary_table(df, output_dir):
    """Create a summary table as PDF"""
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare table data
    size_labels = ['1B', '10B', '100B', '1KB', '10KB', '100KB', '1MB', '10MB', '100MB']
    
    # Format amplification values
    amp_formatted = []
    for val in df['Amplification']:
        if val >= 1000:
            amp_formatted.append(f'{val/1000:.1f}K×')
        else:
            amp_formatted.append(f'{val:.1f}×')
    
    table_data = []
    for i in range(len(size_labels)):
        row = [
            size_labels[i],
            amp_formatted[i],
            f"{df['Data_Percent'][i]:.1f}%",
            f"{df['Metadata_Percent'][i]:.1f}%",
            f"{df['Journal_Percent'][i]:.1f}%",
            f"{df['Metadata_Percent'][i] + df['Journal_Percent'][i]:.1f}%"
        ]
        table_data.append(row)
    
    # Create table
    table = ax.table(cellText=table_data,
                     colLabels=['Object Size', 'Amplification', 'Data %', 'Metadata %', 'Journal %', 'Total Overhead %'],
                     cellLoc='center',
                     loc='center',
                     colWidths=[0.15, 0.18, 0.15, 0.15, 0.15, 0.22])
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 2)
    
    # Color the header
    for i in range(6):
        table[(0, i)].set_facecolor('#3498db')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Color rows based on amplification level
    for i in range(1, len(table_data) + 1):
        amp_val = df['Amplification'][i-1]
        if amp_val > 100:
            color = '#ffebee'  # Light red
        elif amp_val > 10:
            color = '#fff3e0'  # Light orange
        else:
            color = '#e8f5e9'  # Light green
        
        for j in range(6):
            table[(i, j)].set_facecolor(color)
    
    plt.title('MinIO I/O Amplification Summary Table', fontsize=16, fontweight='bold', pad=20)
    
    # Add notes
    note_text = ("Note: Amplification shows how many times the original data size is multiplied at the device layer.\n"
                 "Overhead % = Metadata % + Journal %")
    plt.figtext(0.5, 0.08, note_text, ha='center', fontsize=10, style='italic', alpha=0.7)
    
    plt.tight_layout()
    pdf_path = output_dir / 'summary_table.pdf'
    plt.savefig(pdf_path, format='pdf', bbox_inches='tight', dpi=150)
    plt.close()
    print(f"  ✓ Saved: {pdf_path}")

def create_all_plots(csv_file):
    """Generate all plots as individual PDF files"""
    
    # Read the CSV data
    df = pd.read_csv(csv_file)
    
    # Create output directory
    output_dir = Path(csv_file).parent / 'pdf_plots'
    output_dir.mkdir(exist_ok=True)
    
    print(f"\nGenerating PDF plots in: {output_dir}")
    print("-" * 50)
    
    # Generate each plot
    create_amplification_plot(df, output_dir)
    create_io_distribution_plot(df, output_dir)
    create_loglog_plot(df, output_dir)
    create_overhead_comparison_plot(df, output_dir)
    create_pie_charts_comparison(df, output_dir)
    create_summary_table(df, output_dir)
    
    print("-" * 50)
    print(f"✅ All PDF plots generated successfully!")
    print(f"📁 Location: {output_dir}")
    
    return output_dir

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
                create_all_plots(csv_file)
            else:
                print(f"Error: CSV file not found in {latest_dir}")
                sys.exit(1)
        else:
            print("Usage: python plot_amplification_pdf.py <path_to_amplification_data.csv>")
            print("   or: python plot_amplification_pdf.py  (to use latest results)")
            sys.exit(1)
    else:
        csv_file = sys.argv[1]
        if not Path(csv_file).exists():
            print(f"Error: File {csv_file} not found")
            sys.exit(1)
        create_all_plots(csv_file)

if __name__ == "__main__":
    main()
