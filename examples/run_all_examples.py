#!/usr/bin/env python3
"""
PacketFuzz Example Runner - Modernized for Enhanced Features

This script demonstrates the latest PacketFuzz capabilities including:
- 250x performance improvement with optimized fuzzing
- Hierarchical packet breakdown (IP → TCP → HTTP) 
- Enhanced mutator identification ([libfuzzer], [scapy], [dict])
- Multiple report formats (JSON, HTML, Markdown, YAML, SARIF)
- Advanced debugging and analysis features

Usage:
    python run_all_examples.py [OPTIONS]
    
Options:
    --quick         Run with reduced iterations for fast demonstration
    --disable-network  Disable network transmission (safe mode)
    --verbose       Enable enhanced debugging output (-vvv)
    --report-formats FORMAT  Generate reports in specified formats (json,html,markdown,yaml,sarif,csv,all)
    --help          Show this help message

Examples:
    # Quick demo run (recommended)
    python run_all_examples.py --quick --disable-network
    
    # Full debugging with all report formats
    python run_all_examples.py --verbose --report-formats all --disable-network
    
    # Performance benchmark run
    python run_all_examples.py --disable-network --report-formats json
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path

# Add the project root to the path so we can import packetfuzz
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_campaign_file_cli(file_path, args):
    """
    Run a campaign file using the CLI with enhanced options.
    
    Demonstrates modern PacketFuzz CLI capabilities:
    - Performance optimizations (--max-iterations)
    - Enhanced debugging (--verbose levels)
    - Multiple report formats (--report-formats)
    - Safe testing (--disable-network)
    """
    cmd = [sys.executable, "-m", "packetfuzz", str(file_path)]
    
    # Add common safety and performance options
    if args.disable_network:
        cmd.append("--disable-network")
    
    if args.quick:
        cmd.extend(["--max-iterations", "2"])
    
    if args.verbose:
        cmd.append("-vvv")  # Maximum verbosity for hierarchical packet breakdown
    
    if args.report_formats:
        # Split comma-separated formats and add them as separate arguments
        formats = [f.strip() for f in args.report_formats.split(',')]
        cmd.extend(["--report-formats"] + formats)
    
    print(f"\n{'='*60}")
    print(f"Running: {file_path.name}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(cmd, capture_output=False, text=True, cwd=project_root)
        end_time = time.time()
        
        if result.returncode == 0:
            print(f"SUCCESS: {file_path.name} completed in {end_time - start_time:.2f}s")
        else:
            print(f"FAILED: {file_path.name} (exit code: {result.returncode})")
            return False
            
    except (OSError, subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"ERROR: Failed to run {file_path.name}: {e}")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description="PacketFuzz Example Runner - Showcasing Enhanced Features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""


Recommended Usage:
  python run_all_examples.py --quick --disable-network --verbose
        """
    )
    
    parser.add_argument("--quick", action="store_true",
                       help="Run with reduced iterations for fast demonstration")
    parser.add_argument("--disable-network", action="store_true",
                       help="Disable network transmission (recommended for testing)")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable maximum verbosity (-vvv) for hierarchical packet breakdown")
    parser.add_argument("--report-formats", type=str, default="json,html",
                       help="Report formats to generate (json,html,markdown,yaml,sarif,csv,all)")
    
    args = parser.parse_args()
    
    examples_dir = Path(__file__).parent
    
    # Define example categories and their purposes
    example_categories = [
        {
            "name": "Basic Examples",
            "description": "Core PacketFuzz functionality and new features",
            "path": examples_dir / "basic",
            "files": [
                "01_quick_start.py",           # Performance showcase & basic usage
                "02_enhanced_debugging.py",    # Hierarchical packet breakdown
                "03_fuzzfield_basics.py",      # Field-level fuzzing
                "04_weighted_mutators.py",     # Mutator identification
                "05_campaign_types.py"         # Campaign patterns
            ]
        },
        {
            "name": "Intermediate Examples", 
            "description": "Advanced configuration and reporting features",
            "path": examples_dir / "intermediate",
            "files": [
                "01_campaign_inheritance.py",  # Campaign architecture
                "02_reporting_analysis.py",    # Multiple report formats
                "03_callback_basics.py"        # Event handling
            ]
        },
        {
            "name": "Advanced Examples",
            "description": "Complex scenarios and custom implementations", 
            "path": examples_dir / "advanced",
            "files": [
                "01_complex_campaigns.py",     # Multi-protocol campaigns
                "02_pcap_analysis.py",         # PCAP processing
                "03_custom_protocols.py"       # Protocol extensions
            ]
        }
    ]
    
    
    if args.quick:
        print("Quick mode: Running with reduced iterations for fast demonstration")
    if args.disable_network:
        print("Safe mode: Network transmission disabled")
    if args.verbose:
        print("Debug mode: Maximum verbosity enabled for hierarchical packet breakdown")
    
    print(f"Report formats: {args.report_formats}")
    print()
    
    total_examples = 0
    successful_examples = 0
    start_time = time.time()
    
    for category in example_categories:
        print(f"\n{category['name']}")
        print(f"{category['description']}")
        print("-" * 50)
        
        for file_name in category['files']:
            file_path = category['path'] / file_name
            
            if file_path.exists():
                total_examples += 1
                if run_campaign_file_cli(file_path, args):
                    successful_examples += 1
                    
                # Add small delay between examples for readability
                if not args.quick:
                    time.sleep(1)
            else:
                print(f"SKIP: {file_name} not found")
    
    end_time = time.time()
    
    # Final summary
    print(f"\n{'='*60}")
    print("EXECUTION SUMMARY")
    print(f"{'='*60}")
    print(f"Total Examples: {total_examples}")
    print(f"Successful: {successful_examples}")
    print(f"Failed: {total_examples - successful_examples}")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    
    if successful_examples == total_examples:
        print("All examples completed successfully!")
        print("\nCheck the following directories for outputs:")
        print("   artifacts/pcaps/     - Captured packets")
        print("   artifacts/reports/   - Analysis reports") 
        print("   artifacts/logs/      - Fuzz history with hierarchical breakdown")
    else:
        print(f"WARNING: {total_examples - successful_examples} examples failed")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
