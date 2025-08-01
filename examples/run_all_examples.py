#!/usr/bin/env python3
"""
Run All Examples - CLI-Based Example Runner

Executes all campaign config files using the packetfuzz CLI with --dry-run to validate them.
Provides summary statistics and validates that all campaign files load correctly.
"""

import sys
import os
import subprocess
from pathlib import Path

def discover_campaign_files(directory):
    """Discover all Python campaign config files in a directory."""
    campaign_files = []
    if os.path.exists(directory):
        for file in sorted(os.listdir(directory)):
            if file.endswith('.py') and not file.startswith('__'):
                campaign_files.append(os.path.join(directory, file))
    return campaign_files

def run_campaign_file_cli(file_path):
    """Run packetfuzz CLI on a campaign file with --dry-run and return success status."""
    try:
        print(f"Validating {file_path} with packetfuzz CLI...")
        result = subprocess.run([
            sys.executable, "../packetfuzz.py", file_path, "--dry-run"
        ], capture_output=True, text=True, cwd=os.path.dirname(__file__))
        if result.returncode == 0:
            print(f"{os.path.basename(file_path)} validated successfully\n")
            return True
        else:
            print(f"{os.path.basename(file_path)} failed validation:\n{result.stdout}\n{result.stderr}\n")
            return False
    except Exception as e:
        print(f"Error running packetfuzz CLI on {file_path}: {e}\n")
        return False

def run_example_category_cli(category_name, directory):
    print(f"{'=' * 20} {category_name.upper()} CAMPAIGN FILES {'=' * 20}")
    campaign_files = discover_campaign_files(directory)
    if not campaign_files:
        print(f"No campaign files found in {directory}")
        return [], []
    print(f"Found {len(campaign_files)} campaign files in {category_name}:")
    for campaign_file in campaign_files:
        print(f"  • {os.path.basename(campaign_file)}")
    print()
    successes = []
    failures = []
    for campaign_path in campaign_files:
        if run_campaign_file_cli(campaign_path):
            successes.append(campaign_path)
        else:
            failures.append(campaign_path)
    print(f"{category_name.title()} Summary: {len(successes)}/{len(campaign_files)} successful")
    if failures:
        print("Failed campaign files:")
        for failure in failures:
            print(f"   • {os.path.basename(failure)}")
    print()
    return successes, failures

def main():
    print("SCAPY FUZZER - CLI-BASED CAMPAIGN VALIDATION RUNNER")
    print("=" * 60)
    print()
    examples_dir = os.path.dirname(os.path.abspath(__file__))
    original_dir = os.getcwd()
    os.chdir(examples_dir)
    try:
        all_successes = []
        all_failures = []
        categories = [
            ("Basic", "basic"),
            ("Intermediate", "intermediate"),
            ("Advanced", "advanced")
        ]
        for category_name, directory in categories:
            successes, failures = run_example_category_cli(category_name, directory)
            all_successes.extend(successes)
            all_failures.extend(failures)
        print("=" * 60)
        print("FINAL RESULTS")
        print("=" * 60)
        total_campaigns = len(all_successes) + len(all_failures)
        success_rate = (len(all_successes) / total_campaigns * 100) if total_campaigns > 0 else 0
        print(f"Total Campaign Files Run: {total_campaigns}")
        print(f"Successful: {len(all_successes)}")
        print(f"Failed: {len(all_failures)}")
        print(f"Success Rate: {success_rate:.1f}%")
        if all_failures:
            print("\nFailed Campaign Files:")
            for failure in all_failures:
                print(f"   • {os.path.basename(failure)}")
        if len(all_failures) == 0:
            print("\nALL CAMPAIGN FILES PASSED! Framework is working correctly.")
            return True
        else:
            print(f"\n{len(all_failures)} campaign files failed. Check output above for details.")
            return False
    finally:
        os.chdir(original_dir)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
