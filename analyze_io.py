#!/usr/bin/env python3

"""
I/O Amplification Analyzer and Visualizer
Processes eBPF trace data to calculate I/O amplification metrics
and generate visualizations for storage systems research.
"""

import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime
from collections import defaultdict
import sys
import os


class IOAmplificationAnalyzer:
    def __init__(self, trace_file):
        """Initialize analyzer with trace data."""
        self.trace_file = trace_file
        self.events = []
        self.systems_data = defaultdict(
            lambda: {
                "syscall_reads": 0,
                "syscall_writes": 0,
                "vfs_reads": 0,
                "vfs_writes": 0,
                "block_reads": 0,
                "block_writes": 0,
                "read_bytes": 0,
                "write_bytes": 0,
                "read_latency": [],
                "write_latency": [],
            }
        )

    def load_data(self):
        """Load and parse trace data from JSON file."""
        try:
            with open(self.trace_file, "r") as f:
                # Handle both individual event lines and summary format
                content = f.read().strip()
                if content.startswith('{"summary"'):
                    # Summary format
                    data = json.loads(content)
                    self._parse_summary(data)
                else:
                    # Individual events format
                    for line in content.split("\n"):
                        if line.strip() and line.startswith("{"):
                            try:
                                event = json.loads(line.strip())
                                self.events.append(event)
                            except json.JSONDecodeError:
                                continue
                    self._aggregate_events()
        except Exception as e:
            print(f"Error loading trace data: {e}")
            sys.exit(1)

    def _parse_summary(self, data):
        """Parse summary format data."""
        summary = data.get("summary", {})
        for system_name, stats in summary.items():
            system_data = self.systems_data[system_name]
            system_data.update(stats)

    def _aggregate_events(self):
        """Aggregate individual events into system statistics."""
        for event in self.events:
            system = event.get("system", "Unknown")
            event_type = event.get("event_type", "")
            size = event.get("size", 0)
            latency = event.get("latency_us", 0)

            system_data = self.systems_data[system]

            if "READ" in event_type:
                if "SYSCALL" in event_type:
                    system_data["syscall_reads"] += 1
                elif "VFS" in event_type:
                    system_data["vfs_reads"] += 1
                elif "BLOCK" in event_type:
                    system_data["block_reads"] += 1

                system_data["read_bytes"] += size
                system_data["read_latency"].append(latency)

            elif "WRITE" in event_type:
                if "SYSCALL" in event_type:
                    system_data["syscall_writes"] += 1
                elif "VFS" in event_type:
                    system_data["vfs_writes"] += 1
                elif "BLOCK" in event_type:
                    system_data["block_writes"] += 1

                system_data["write_bytes"] += size
                system_data["write_latency"].append(latency)

    def calculate_amplification(self):
        """Calculate I/O amplification factors for each system."""
        results = {}

        for system, data in self.systems_data.items():
            if data["syscall_reads"] + data["syscall_writes"] == 0:
                continue  # Skip systems with no activity

            # Calculate amplification factors
            read_amp = 0
            write_amp = 0

            if data["syscall_reads"] > 0:
                total_backend_reads = data["vfs_reads"] + data["block_reads"]
                read_amp = total_backend_reads / data["syscall_reads"]

            if data["syscall_writes"] > 0:
                total_backend_writes = data["vfs_writes"] + data["block_writes"]
                write_amp = total_backend_writes / data["syscall_writes"]

            # Calculate average latencies
            avg_read_latency = (
                np.mean(data["read_latency"]) if data["read_latency"] else 0
            )
            avg_write_latency = (
                np.mean(data["write_latency"]) if data["write_latency"] else 0
            )

            results[system] = {
                "read_amplification": read_amp,
                "write_amplification": write_amp,
                "syscall_reads": data["syscall_reads"],
                "syscall_writes": data["syscall_writes"],
                "total_backend_reads": data["vfs_reads"] + data["block_reads"],
                "total_backend_writes": data["vfs_writes"] + data["block_writes"],
                "read_bytes": data["read_bytes"],
                "write_bytes": data["write_bytes"],
                "avg_read_latency": avg_read_latency,
                "avg_write_latency": avg_write_latency,
                "total_operations": data["syscall_reads"] + data["syscall_writes"],
            }

        return results

    def print_summary(self, results):
        """Print a detailed summary of I/O amplification analysis."""
        print("\n" + "=" * 80)
        print("I/O AMPLIFICATION ANALYSIS SUMMARY")
        print("=" * 80)

        # Sort by total operations for better presentation
        sorted_systems = sorted(
            results.items(), key=lambda x: x[1]["total_operations"], reverse=True
        )

        for system, stats in sorted_systems:
            print(f"\n{system}:")
            print(
                f"  Syscall Operations: {stats['syscall_reads']:,} reads, {stats['syscall_writes']:,} writes"
            )
            print(
                f"  Backend Operations: {stats['total_backend_reads']:,} reads, {stats['total_backend_writes']:,} writes"
            )
            print(f"  Read Amplification: {stats['read_amplification']:.2f}x")
            print(f"  Write Amplification: {stats['write_amplification']:.2f}x")
            print(
                f"  Data Transfer: {self._format_bytes(stats['read_bytes'])} read, {self._format_bytes(stats['write_bytes'])} written"
            )
            print(
                f"  Avg Latency: {stats['avg_read_latency']:.2f}μs read, {stats['avg_write_latency']:.2f}μs write"
            )

            # Efficiency score (lower is better)
            efficiency_score = (
                stats["read_amplification"] + stats["write_amplification"]
            ) / 2
            print(f"  Efficiency Score: {efficiency_score:.2f} (lower is better)")

    def _format_bytes(self, bytes_val):
        """Format bytes in human readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f}TB"

    def generate_visualizations(self, results, output_dir="plots"):
        """Generate various visualizations of the I/O amplification data."""
        if not results:
            print("No data to visualize.")
            return

        os.makedirs(output_dir, exist_ok=True)

        # Set up the plotting style
        plt.style.use("default")
        sns.set_palette("husl")

        # 1. Amplification Comparison Bar Chart
        self._plot_amplification_comparison(results, output_dir)

        # 2. Operations Breakdown
        self._plot_operations_breakdown(results, output_dir)

        # 3. Latency Analysis
        self._plot_latency_analysis(results, output_dir)

        # 4. Efficiency Scatter Plot
        self._plot_efficiency_scatter(results, output_dir)

        # 5. Data Transfer Analysis
        self._plot_data_transfer(results, output_dir)

        print(f"\nVisualizations saved to '{output_dir}' directory")

    def _plot_amplification_comparison(self, results, output_dir):
        """Plot I/O amplification comparison across systems."""
        systems = list(results.keys())
        read_amps = [results[s]["read_amplification"] for s in systems]
        write_amps = [results[s]["write_amplification"] for s in systems]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Read amplification
        bars1 = ax1.bar(systems, read_amps, alpha=0.7, color="skyblue")
        ax1.set_title("Read Amplification Factor by System")
        ax1.set_ylabel("Amplification Factor")
        ax1.tick_params(axis="x", rotation=45)

        # Add value labels on bars
        for bar, val in zip(bars1, read_amps):
            height = bar.get_height()
            ax1.annotate(
                f"{val:.2f}x",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
            )

        # Write amplification
        bars2 = ax2.bar(systems, write_amps, alpha=0.7, color="lightcoral")
        ax2.set_title("Write Amplification Factor by System")
        ax2.set_ylabel("Amplification Factor")
        ax2.tick_params(axis="x", rotation=45)

        for bar, val in zip(bars2, write_amps):
            height = bar.get_height()
            ax2.annotate(
                f"{val:.2f}x",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
            )

        plt.tight_layout()
        plt.savefig(
            f"{output_dir}/amplification_comparison.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

    def _plot_operations_breakdown(self, results, output_dir):
        """Plot operations breakdown showing syscall vs backend operations."""
        systems = list(results.keys())
        if not systems:
            return

        fig, ax = plt.subplots(figsize=(12, 8))

        x = np.arange(len(systems))
        width = 0.35

        syscall_ops = [
            results[s]["syscall_reads"] + results[s]["syscall_writes"] for s in systems
        ]
        backend_ops = [
            results[s]["total_backend_reads"] + results[s]["total_backend_writes"]
            for s in systems
        ]

        bars1 = ax.bar(
            x - width / 2, syscall_ops, width, label="Syscall Operations", alpha=0.8
        )
        bars2 = ax.bar(
            x + width / 2, backend_ops, width, label="Backend Operations", alpha=0.8
        )

        ax.set_xlabel("Storage System")
        ax.set_ylabel("Number of Operations")
        ax.set_title("Syscall vs Backend Operations Comparison")
        ax.set_xticks(x)
        ax.set_xticklabels(systems, rotation=45)
        ax.legend()
        ax.set_yscale("log")  # Use log scale for better visibility

        plt.tight_layout()
        plt.savefig(
            f"{output_dir}/operations_breakdown.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

    def _plot_latency_analysis(self, results, output_dir):
        """Plot latency analysis."""
        systems = list(results.keys())
        read_latencies = [results[s]["avg_read_latency"] for s in systems]
        write_latencies = [results[s]["avg_write_latency"] for s in systems]

        fig, ax = plt.subplots(figsize=(10, 6))

        x = np.arange(len(systems))
        width = 0.35

        bars1 = ax.bar(
            x - width / 2, read_latencies, width, label="Read Latency", alpha=0.7
        )
        bars2 = ax.bar(
            x + width / 2, write_latencies, width, label="Write Latency", alpha=0.7
        )

        ax.set_xlabel("Storage System")
        ax.set_ylabel("Average Latency (μs)")
        ax.set_title("Average I/O Latency by System")
        ax.set_xticks(x)
        ax.set_xticklabels(systems, rotation=45)
        ax.legend()

        plt.tight_layout()
        plt.savefig(f"{output_dir}/latency_analysis.png", dpi=300, bbox_inches="tight")
        plt.close()

    def _plot_efficiency_scatter(self, results, output_dir):
        """Plot efficiency scatter plot (amplification vs operations)."""
        fig, ax = plt.subplots(figsize=(10, 8))

        for system, stats in results.items():
            total_amp = stats["read_amplification"] + stats["write_amplification"]
            total_ops = stats["total_operations"]

            ax.scatter(total_ops, total_amp, s=100, alpha=0.7, label=system)
            ax.annotate(
                system,
                (total_ops, total_amp),
                xytext=(5, 5),
                textcoords="offset points",
                fontsize=9,
            )

        ax.set_xlabel("Total Operations")
        ax.set_ylabel("Total Amplification Factor")
        ax.set_title("I/O Efficiency: Amplification vs Operation Count")
        ax.set_xscale("log")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(
            f"{output_dir}/efficiency_scatter.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

    def _plot_data_transfer(self, results, output_dir):
        """Plot data transfer analysis."""
        systems = list(results.keys())
        read_bytes = [results[s]["read_bytes"] for s in systems]
        write_bytes = [results[s]["write_bytes"] for s in systems]

        fig, ax = plt.subplots(figsize=(12, 6))

        x = np.arange(len(systems))
        width = 0.35

        bars1 = ax.bar(x - width / 2, read_bytes, width, label="Bytes Read", alpha=0.7)
        bars2 = ax.bar(
            x + width / 2, write_bytes, width, label="Bytes Written", alpha=0.7
        )

        ax.set_xlabel("Storage System")
        ax.set_ylabel("Bytes Transferred")
        ax.set_title("Data Transfer Volume by System")
        ax.set_xticks(x)
        ax.set_xticklabels(systems, rotation=45)
        ax.legend()
        ax.set_yscale("log")

        # Format y-axis labels
        ax.yaxis.set_major_formatter(
            plt.FuncFormatter(lambda x, p: self._format_bytes(x))
        )

        plt.tight_layout()
        plt.savefig(f"{output_dir}/data_transfer.png", dpi=300, bbox_inches="tight")
        plt.close()

    def export_results(self, results, output_file="io_amplification_results.csv"):
        """Export results to CSV for further analysis."""
        df_data = []
        for system, stats in results.items():
            df_data.append(
                {
                    "System": system,
                    "Read_Amplification": stats["read_amplification"],
                    "Write_Amplification": stats["write_amplification"],
                    "Syscall_Reads": stats["syscall_reads"],
                    "Syscall_Writes": stats["syscall_writes"],
                    "Backend_Reads": stats["total_backend_reads"],
                    "Backend_Writes": stats["total_backend_writes"],
                    "Read_Bytes": stats["read_bytes"],
                    "Write_Bytes": stats["write_bytes"],
                    "Avg_Read_Latency_us": stats["avg_read_latency"],
                    "Avg_Write_Latency_us": stats["avg_write_latency"],
                    "Total_Operations": stats["total_operations"],
                }
            )

        df = pd.DataFrame(df_data)
        df.to_csv(output_file, index=False)
        print(f"Results exported to {output_file}")
        return df


def main():
    parser = argparse.ArgumentParser(
        description="Analyze I/O amplification from eBPF traces"
    )
    parser.add_argument("trace_file", help="JSON trace file from eBPF tracer")
    parser.add_argument(
        "-v", "--visualize", action="store_true", help="Generate visualization plots"
    )
    parser.add_argument(
        "-o", "--output", default="plots", help="Output directory for plots"
    )
    parser.add_argument("-e", "--export", help="Export results to CSV file")
    parser.add_argument(
        "--no-summary", action="store_true", help="Skip printing summary to console"
    )

    args = parser.parse_args()

    if not os.path.exists(args.trace_file):
        print(f"Error: Trace file '{args.trace_file}' not found.")
        sys.exit(1)

    print(f"Analyzing I/O amplification from: {args.trace_file}")

    # Initialize analyzer and load data
    analyzer = IOAmplificationAnalyzer(args.trace_file)
    analyzer.load_data()

    # Calculate amplification metrics
    results = analyzer.calculate_amplification()

    if not results:
        print("No storage system activity found in trace data.")
        sys.exit(1)

    # Print summary
    if not args.no_summary:
        analyzer.print_summary(results)

    # Generate visualizations
    if args.visualize:
        analyzer.generate_visualizations(results, args.output)

    # Export results
    if args.export:
        analyzer.export_results(results, args.export)

    print(f"\nAnalysis complete. Found {len(results)} active storage systems.")


if __name__ == "__main__":
    main()
