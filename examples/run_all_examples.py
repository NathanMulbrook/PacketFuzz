#!/usr/bin/env python3
"""
Run All Examples - Comprehensive Example Runner

Executes all examples in the proper order: basic → intermediate → advanced → config
Provides summary statistics and validates that all examples work correctly.
"""

import sys
import os
import importlib.util
import traceback
from pathlib import Path

def run_python_file(file_path):
    """Run a Python file and return success status."""
    try:
        print(f"Running {file_path}")
        
        # Load and execute the module
        spec = importlib.util.spec_from_file_location("example_module", file_path)
        if spec is None or spec.loader is None:
            print(f"Cannot load module from {file_path}")
            return False
            
        module = importlib.util.module_from_spec(spec)
        
        # Capture stdout to reduce noise
        import io
        import contextlib
        
        stdout_buffer = io.StringIO()
        with contextlib.redirect_stdout(stdout_buffer):
            spec.loader.exec_module(module)
            
            # Try to run main() if it exists
            if hasattr(module, 'main'):
                result = module.main()
                if result is None:
                    result = True  # Assume success if no return value
            else:
                result = True  # Module executed without error
        
        # Print captured output
        output = stdout_buffer.getvalue()
        if output:
            print(output)
        
        if result:
            print(f"{os.path.basename(file_path)} completed successfully\n")
            return True
        else:
            print(f"{os.path.basename(file_path)} reported failure\n")
            return False
            
    except Exception as e:
        print(f"{os.path.basename(file_path)} crashed: {str(e)}")
        print(f"   {traceback.format_exc()}\n")
        return False

def discover_examples(directory):
    """Discover all Python example files in a directory."""
    examples = []
    if os.path.exists(directory):
        for file in sorted(os.listdir(directory)):
            if file.endswith('.py') and not file.startswith('__'):
                examples.append(os.path.join(directory, file))
    return examples

def run_example_category(category_name, directory):
    """Run all examples in a category."""
    print(f"{'=' * 20} {category_name.upper()} EXAMPLES {'=' * 20}")
    
    examples = discover_examples(directory)
    if not examples:
        print(f"No examples found in {directory}")
        return [], []
    
    print(f"Found {len(examples)} examples in {category_name}:")
    for example in examples:
        print(f"  • {os.path.basename(example)}")
    print()
    
    successes = []
    failures = []
    
    for example_path in examples:
        if run_python_file(example_path):
            successes.append(example_path)
        else:
            failures.append(example_path)
    
    print(f"{category_name.title()} Summary: {len(successes)}/{len(examples)} successful")
    if failures:
        print("Failed examples:")
        for failure in failures:
            print(f"   • {os.path.basename(failure)}")
    print()
    
    return successes, failures

def main():
    """Run all examples in order."""
    print("SCAPY FUZZER - COMPREHENSIVE EXAMPLE RUNNER")
    print("=" * 60)
    print()
    
    # Change to examples directory
    examples_dir = os.path.dirname(os.path.abspath(__file__))
    original_dir = os.getcwd()
    os.chdir(examples_dir)
    
    try:
        all_successes = []
        all_failures = []
        
        # Run examples in progression order
        categories = [
            ("Basic", "basic"),
            ("Intermediate", "intermediate"), 
            ("Advanced", "advanced"),
            ("Configuration", "config")
        ]
        
        for category_name, directory in categories:
            successes, failures = run_example_category(category_name, directory)
            all_successes.extend(successes)
            all_failures.extend(failures)
        
        # Final summary
        print("=" * 60)
        print("FINAL RESULTS")
        print("=" * 60)
        
        total_examples = len(all_successes) + len(all_failures)
        success_rate = (len(all_successes) / total_examples * 100) if total_examples > 0 else 0
        
        print(f"Total Examples Run: {total_examples}")
        print(f"Successful: {len(all_successes)}")
        print(f"Failed: {len(all_failures)}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if all_failures:
            print("\nFailed Examples:")
            for failure in all_failures:
                print(f"   • {os.path.basename(failure)}")
        
        if len(all_failures) == 0:
            print("\nALL EXAMPLES PASSED! Framework is working correctly.")
            return True
        else:
            print(f"\n{len(all_failures)} examples failed. Check output above for details.")
            return False
    
    finally:
        # Restore original directory
        os.chdir(original_dir)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
