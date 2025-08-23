#!/usr/bin/env python3
"""
Enhanced Test Runner for PacketFuzz

This script runs all the enhanced tests with detailed logging and reporting.
It provides comprehensive validation of the fuzzer functionality including:

1. PCAP content validation
2. Mutation effectiveness testing  
3. Statistical analysis
4. Performance benchmarking
5. Error resilience testing

Usage:
    python run_enhanced_tests.py [--verbose] [--test-pattern PATTERN]
"""

import sys
import os
import unittest
import logging
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import pytest for better reporting
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False


class EnhancedTestResult(unittest.TextTestResult):
    """Enhanced test result with detailed logging and metrics collection"""
    
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.test_metrics = {}
        self.start_times = {}
        self.logger = logging.getLogger('test_runner')
    
    def startTest(self, test):
        super().startTest(test)
        self.start_times[test] = time.time()
        self.logger.info(f"Starting {test._testMethodName}")
    
    def stopTest(self, test):
        super().stopTest(test)
        if test in self.start_times:
            duration = time.time() - self.start_times[test]
            self.test_metrics[test._testMethodName] = {
                'duration': duration,
                'status': 'passed' if self.wasSuccessful() else 'failed'
            }
            self.logger.info(f"Completed {test._testMethodName} in {duration:.2f}s")
    
    def addError(self, test, err):
        super().addError(test, err)
        self.logger.error(f"ERROR in {test._testMethodName}: {err[1]}")
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.logger.error(f"FAILURE in {test._testMethodName}: {err[1]}")
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.logger.warning(f"SKIPPED {test._testMethodName}: {reason}")


class EnhancedTestRunner:
    """Enhanced test runner with comprehensive reporting"""
    
    def __init__(self, verbosity=2):
        self.verbosity = verbosity
        self.logger = logging.getLogger('test_runner')
        self.setup_logging()
        
    def setup_logging(self):
        """Configure comprehensive logging for test execution"""
        # Configure root logger
        logging.basicConfig(
            level=logging.INFO if self.verbosity >= 2 else logging.WARNING,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('test_execution.log', mode='w')
            ]
        )
        
        # Set specific logger levels
        if self.verbosity >= 3:
            logging.getLogger('fuzzer_validation').setLevel(logging.DEBUG)
            logging.getLogger('integration').setLevel(logging.DEBUG)
        
        self.logger.info("Enhanced test runner initialized")
    
    def discover_tests(self, pattern="test_*.py"):
        """Discover test files matching the pattern"""
        test_dir = Path(__file__).parent
        test_files = list(test_dir.glob(pattern))
        
        # Prioritize our enhanced test files
        priority_tests = [
            'test_fuzzer_validation.py',
            'test_pcap_functionality.py', 
            'test_packet_pipeline.py',
            'test_core.py',
            'test_integration.py'
        ]
        
        # Sort files with priority tests first
        def test_priority(test_file):
            name = test_file.name
            if name in priority_tests:
                return priority_tests.index(name)
            return len(priority_tests)
        
        test_files.sort(key=test_priority)
        
        self.logger.info(f"Discovered {len(test_files)} test files: {[f.name for f in test_files]}")
        return test_files
    
    def run_test_file(self, test_file: Path) -> Dict[str, Any]:
        """Run a single test file and collect metrics"""
        self.logger.info(f"Running test file: {test_file.name}")
        
        # Load the test module
        module_name = test_file.stem
        spec = __import__(module_name)
        
        # Discover tests in the module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(spec)
        
        # Run tests with enhanced result collection
        runner = unittest.TextTestRunner(
            stream=sys.stdout,
            verbosity=self.verbosity,
            resultclass=EnhancedTestResult
        )
        
        start_time = time.time()
        result = runner.run(suite)
        end_time = time.time()
        
        # Collect metrics
        metrics = {
            'file': test_file.name,
            'total_tests': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'skipped': len(result.skipped),
            'duration': end_time - start_time,
            'success_rate': (result.testsRun - len(result.failures) - len(result.errors)) / max(result.testsRun, 1)
        }
        
        if hasattr(result, 'test_metrics'):
            metrics['individual_tests'] = result.test_metrics
        
        self.logger.info(f"Test file {test_file.name} completed: "
                        f"{metrics['total_tests']} tests, "
                        f"{metrics['failures']} failures, "
                        f"{metrics['errors']} errors, "
                        f"{metrics['skipped']} skipped")
        
        return metrics
    
    def run_all_tests(self, pattern="test_*.py") -> Dict[str, Any]:
        """Run all tests and generate comprehensive report"""
        self.logger.info("Starting enhanced test execution")
        
        start_time = time.time()
        test_files = self.discover_tests(pattern)
        
        all_metrics = []
        total_tests = 0
        total_failures = 0
        total_errors = 0
        total_skipped = 0
        
        for test_file in test_files:
            try:
                metrics = self.run_test_file(test_file)
                all_metrics.append(metrics)
                
                total_tests += metrics['total_tests']
                total_failures += metrics['failures']
                total_errors += metrics['errors']
                total_skipped += metrics['skipped']
                
            except Exception as e:
                self.logger.error(f"Failed to run test file {test_file.name}: {e}")
                all_metrics.append({
                    'file': test_file.name,
                    'error': str(e),
                    'total_tests': 0,
                    'failures': 0,
                    'errors': 1,
                    'skipped': 0,
                    'duration': 0,
                    'success_rate': 0
                })
                total_errors += 1
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Generate comprehensive report
        overall_metrics = {
            'total_duration': total_duration,
            'total_tests': total_tests,
            'total_failures': total_failures,
            'total_errors': total_errors,
            'total_skipped': total_skipped,
            'overall_success_rate': (total_tests - total_failures - total_errors) / max(total_tests, 1),
            'test_files': all_metrics
        }
        
        self.generate_report(overall_metrics)
        return overall_metrics
    
    def generate_report(self, metrics: Dict[str, Any]):
        """Generate comprehensive test execution report"""
        print("\n" + "="*80)
        print("ENHANCED TEST EXECUTION REPORT")
        print("="*80)
        
        # Overall summary
        print(f"\nOVERALL SUMMARY:")
        print(f"  Total Duration: {metrics['total_duration']:.2f} seconds")
        print(f"  Total Tests: {metrics['total_tests']}")
        print(f"  Passed: {metrics['total_tests'] - metrics['total_failures'] - metrics['total_errors']}")
        print(f"  Failed: {metrics['total_failures']}")
        print(f"  Errors: {metrics['total_errors']}")
        print(f"  Skipped: {metrics['total_skipped']}")
        print(f"  Success Rate: {metrics['overall_success_rate']:.1%}")
        
        # Per-file breakdown
        print(f"\nPER-FILE BREAKDOWN:")
        for file_metrics in metrics['test_files']:
            if 'error' in file_metrics:
                print(f"  {file_metrics['file']}: ERROR - {file_metrics['error']}")
            else:
                print(f"  {file_metrics['file']}: "
                      f"{file_metrics['total_tests']} tests, "
                      f"{file_metrics['success_rate']:.1%} success, "
                      f"{file_metrics['duration']:.2f}s")
        
        # Performance analysis
        print(f"\nPERFORMANCE ANALYSIS:")
        if metrics['test_files']:
            durations = [f['duration'] for f in metrics['test_files'] if 'duration' in f]
            if durations:
                avg_duration = sum(durations) / len(durations)
                max_duration = max(durations)
                min_duration = min(durations)
                
                print(f"  Average test file duration: {avg_duration:.2f}s")
                print(f"  Slowest test file: {max_duration:.2f}s")
                print(f"  Fastest test file: {min_duration:.2f}s")
        
        # Recommendations
        print(f"\nRECOMMENDATIONS:")
        if metrics['total_failures'] > 0:
            print(f"  • Investigate {metrics['total_failures']} test failures")
        if metrics['total_errors'] > 0:
            print(f"  • Fix {metrics['total_errors']} test errors")
        if metrics['total_skipped'] > 0:
            print(f"  • Review {metrics['total_skipped']} skipped tests")
        if metrics['overall_success_rate'] < 0.9:
            print(f"  • Success rate below 90% - needs attention")
        
        print("="*80)


def main():
    """Main entry point for enhanced test runner"""
    parser = argparse.ArgumentParser(description='Enhanced PacketFuzz Test Runner')
    parser.add_argument('--verbose', '-v', action='count', default=2,
                       help='Increase verbosity (use -vv for debug output)')
    parser.add_argument('--test-pattern', '-p', default='test_*.py',
                       help='Pattern for test file discovery')
    parser.add_argument('--use-pytest', action='store_true',
                       help='Use pytest instead of unittest (if available)')
    
    args = parser.parse_args()
    
    if args.use_pytest and PYTEST_AVAILABLE:
        # Use pytest for enhanced reporting
        pytest_args = ['-v', '--tb=short']
        if args.verbose >= 3:
            pytest_args.append('-s')
        
        pytest_args.append(args.test_pattern)
        return pytest.main(pytest_args)
    else:
        # Use our enhanced unittest runner
        runner = EnhancedTestRunner(verbosity=args.verbose)
        metrics = runner.run_all_tests(args.test_pattern)
        
        # Return appropriate exit code
        if metrics['total_failures'] > 0 or metrics['total_errors'] > 0:
            return 1
        else:
            return 0


if __name__ == "__main__":
    sys.exit(main())
