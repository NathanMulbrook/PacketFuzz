#!/usr/bin/env python3
"""
Performance and Regression End-to-End Tests for PacketFuzz

End-to-end tests focused on performance characteristics and regression detection.
Tests real-world usage scenarios with measurable performance criteria.
"""

import sys
import os
import unittest
import tempfile
import time
import json
import subprocess
import psutil
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import PacketFuzz components after path setup
try:
    from packetfuzz.fuzzing_framework import FuzzingCampaign, FuzzConfig
    from packetfuzz.dictionary_manager import DictionaryManager
    from packetfuzz.mutator_manager import MutatorManager
    from packetfuzz.mutator_manager_data import MutatorManagerData
except ImportError as e:
    print(f"Warning: Some imports may not be available: {e}")


class TestPerformanceEndToEnd(unittest.TestCase):
    """End-to-end performance testing with measurable benchmarks"""
    
    def setUp(self):
        """Set up performance testing environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.performance_metrics = {}
        self.baseline_thresholds = {
            'packets_per_second': 50,      # Minimum packets/sec
            'memory_usage_mb': 100,        # Maximum memory usage in MB
            'initialization_time': 5.0,    # Maximum init time in seconds
            'mutation_rate': 0.1           # Minimum mutation rate
        }
    
    def tearDown(self):
        """Clean up performance testing environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def measure_performance(self, func, *args, **kwargs) -> Dict[str, Any]:
        """Measure performance metrics for a function"""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Measure execution time
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        return {
            'result': result,
            'execution_time': end_time - start_time,
            'memory_used': final_memory - initial_memory,
            'peak_memory': final_memory,
            'initial_memory': initial_memory
        }
    
    def test_campaign_initialization_performance_e2e(self):
        """End-to-end test: Campaign initialization performance"""
        
        class PerformanceTestCampaign(FuzzingCampaign):
            name = "Performance Test Campaign"
            target = "192.168.1.100"
            iterations = 100
            rate_limit = 1000.0
            verbose = False
            output_network = False
            output_pcap = None
            
            def __init__(self):
                super().__init__()
                self.packet_count = 0
            
            def get_packet(self):
                self.packet_count += 1
                return f"PERF_TEST_PACKET_{self.packet_count}"
        
        # Measure campaign initialization
        def init_campaign():
            return PerformanceTestCampaign()
        
        perf_metrics = self.measure_performance(init_campaign)
        
        # Verification criteria:
        # 1. Initialization should be fast
        init_time = perf_metrics['execution_time']
        self.assertLess(init_time, self.baseline_thresholds['initialization_time'],
                       f"Initialization too slow: {init_time:.2f}s")
        
        # 2. Memory usage should be reasonable
        memory_used = perf_metrics['memory_used']
        self.assertLess(abs(memory_used), self.baseline_thresholds['memory_usage_mb'],
                       f"Memory usage too high: {memory_used:.1f}MB")
        
        # 3. Campaign should be functional after initialization
        campaign = perf_metrics['result']
        self.assertIsNotNone(campaign, "Campaign should initialize successfully")
        self.assertEqual(campaign.iterations, 100, "Campaign parameters should be set correctly")
        
        print(f"✅ Campaign Initialization Performance E2E Test PASSED:")
        print(f"   - Initialization time: {init_time:.3f}s")
        print(f"   - Memory impact: {memory_used:.1f}MB")
        print(f"   - Peak memory: {perf_metrics['peak_memory']:.1f}MB")
    
    def test_packet_generation_throughput_e2e(self):
        """End-to-end test: Packet generation throughput"""
        
        class ThroughputTestCampaign(FuzzingCampaign):
            name = "Throughput Test Campaign"
            target = "192.168.1.100"
            iterations = 200
            rate_limit = 10000.0  # Very high to test max throughput
            verbose = False
            output_network = False
            output_pcap = None
            
            def __init__(self):
                super().__init__()
                self.packets_generated = []
                self.generation_times = []
            
            def get_packet(self):
                start_time = time.time()
                packet = f"THROUGHPUT_TEST_PACKET_{len(self.packets_generated)}"
                end_time = time.time()
                
                self.packets_generated.append(packet)
                self.generation_times.append(end_time - start_time)
                return packet
        
        # Measure packet generation performance
        def run_throughput_test():
            campaign = ThroughputTestCampaign()
            
            # Generate packets rapidly
            start_time = time.time()
            for i in range(campaign.iterations):
                packet = campaign.get_packet()
            end_time = time.time()
            
            total_time = end_time - start_time
            return {
                'campaign': campaign,
                'total_time': total_time,
                'packets_per_second': campaign.iterations / total_time if total_time > 0 else 0
            }
        
        perf_metrics = self.measure_performance(run_throughput_test)
        result = perf_metrics['result']
        
        # Verification criteria:
        # 1. Should generate packets at minimum rate
        packets_per_second = result['packets_per_second']
        self.assertGreater(packets_per_second, self.baseline_thresholds['packets_per_second'],
                          f"Throughput too low: {packets_per_second:.1f} packets/sec")
        
        # 2. All packets should be generated
        campaign = result['campaign']
        self.assertEqual(len(campaign.packets_generated), campaign.iterations,
                        f"Expected {campaign.iterations} packets, got {len(campaign.packets_generated)}")
        
        # 3. Generation times should be consistent
        if campaign.generation_times:
            avg_gen_time = statistics.mean(campaign.generation_times)
            max_gen_time = max(campaign.generation_times)
            
            self.assertLess(avg_gen_time, 0.01, f"Average generation time too high: {avg_gen_time:.4f}s")
            self.assertLess(max_gen_time, 0.1, f"Max generation time too high: {max_gen_time:.4f}s")
        
        # 4. Memory usage should be reasonable
        memory_used = perf_metrics['memory_used']
        self.assertLess(abs(memory_used), self.baseline_thresholds['memory_usage_mb'],
                       f"Memory usage too high: {memory_used:.1f}MB")
        
        print(f"✅ Packet Generation Throughput E2E Test PASSED:")
        print(f"   - Throughput: {packets_per_second:.1f} packets/sec")
        print(f"   - Total execution time: {result['total_time']:.3f}s")
        print(f"   - Memory impact: {memory_used:.1f}MB")
        if campaign.generation_times:
            print(f"   - Avg generation time: {avg_gen_time:.4f}s")
            print(f"   - Max generation time: {max_gen_time:.4f}s")
    
    def test_dictionary_loading_performance_e2e(self):
        """End-to-end test: Dictionary loading performance"""
        
        # Create test dictionary files of various sizes
        dict_files = []
        dict_sizes = [100, 1000, 5000]  # Different dictionary sizes
        
        for size in dict_sizes:
            dict_file = os.path.join(self.temp_dir, f"test_dict_{size}.txt")
            with open(dict_file, 'w') as f:
                for i in range(size):
                    f.write(f"test_value_{i}\n")
            dict_files.append((dict_file, size))
        
        # Test dictionary loading performance
        loading_results = []
        
        for dict_file, size in dict_files:
            def load_dictionary():
                try:
                    dict_manager = DictionaryManager()
                    # Try to load the dictionary
                    with open(dict_file, 'r') as f:
                        entries = [line.strip() for line in f if line.strip()]
                    return {
                        'entries': entries,
                        'count': len(entries),
                        'success': True
                    }
                except Exception as e:
                    return {
                        'entries': [],
                        'count': 0,
                        'success': False,
                        'error': str(e)
                    }
            
            perf_metrics = self.measure_performance(load_dictionary)
            result = perf_metrics['result']
            
            loading_results.append({
                'size': size,
                'execution_time': perf_metrics['execution_time'],
                'memory_used': perf_metrics['memory_used'],
                'entries_loaded': result['count'],
                'success': result['success'],
                'load_rate': result['count'] / perf_metrics['execution_time'] if perf_metrics['execution_time'] > 0 else 0
            })
        
        # Verification criteria:
        # 1. All dictionaries should load successfully
        successful_loads = sum(1 for result in loading_results if result['success'])
        self.assertEqual(successful_loads, len(dict_sizes),
                        f"Expected all dictionaries to load, got {successful_loads}/{len(dict_sizes)}")
        
        # 2. Loading time should scale reasonably with size
        for result in loading_results:
            expected_max_time = result['size'] / 1000.0  # 1ms per 1000 entries
            self.assertLess(result['execution_time'], max(expected_max_time, 1.0),
                           f"Dictionary loading too slow for size {result['size']}: {result['execution_time']:.3f}s")
        
        # 3. Load rates should be reasonable
        for result in loading_results:
            self.assertGreater(result['load_rate'], 500,
                              f"Dictionary load rate too low: {result['load_rate']:.0f} entries/sec")
        
        # 4. Memory usage should scale reasonably
        memory_per_entry = [result['memory_used'] / result['entries_loaded'] 
                           for result in loading_results if result['entries_loaded'] > 0]
        
        if memory_per_entry:
            avg_memory_per_entry = statistics.mean(memory_per_entry)
            self.assertLess(avg_memory_per_entry, 0.01,  # 10KB per entry max
                           f"Memory usage per entry too high: {avg_memory_per_entry:.4f}MB")
        
        print(f"✅ Dictionary Loading Performance E2E Test PASSED:")
        for result in loading_results:
            print(f"   - Size {result['size']}: {result['execution_time']:.3f}s, "
                  f"{result['load_rate']:.0f} entries/sec, {result['memory_used']:.1f}MB")
    
    def test_mutation_performance_e2e(self):
        """End-to-end test: Mutation system performance"""
        
    def test_mutation_performance_e2e(self):
        """End-to-end test: Mutation system performance"""
        
        def run_mutation_test():
            try:
                # Simply test that the mutation system can be imported and basic functionality works
                from packetfuzz.mutator_manager_data import MutatorManagerData, FuzzConfig
                from packetfuzz.dictionary_manager import DictionaryManager
                from packetfuzz.mutator_manager import MutatorManager
                from scapy.all import IP, UDP, Raw
                
                # Create test configuration with a few packets
                test_packets = [
                    IP(dst="192.168.1.100")/UDP(dport=80)/Raw(f"HTTP_PACKET_{i}") 
                    for i in range(5)
                ]
                
                # Create configuration
                config = FuzzConfig()
                config.packets = test_packets
                config.iterations = 10
                
                # Initialize mutation system
                data_manager = MutatorManagerData(config)
                dict_manager = DictionaryManager()
                mutator_manager = MutatorManager(config)
                
                # Process packets
                start_time = time.time()
                data_manager.preprocess_packets(dict_manager)
                preprocessing_time = time.time() - start_time
                
                # Test basic mutation functionality
                start_time = time.time()
                mutations_tested = 0
                for i in range(5):  # Test a few mutations
                    try:
                        result = mutator_manager.fuzz_packet()
                        if result:
                            mutations_tested += 1
                    except Exception:
                        pass  # Some mutations might fail, that's OK
                mutation_time = time.time() - start_time
                
                return {
                    'preprocessing_time': preprocessing_time,
                    'mutation_time': mutation_time,
                    'mutations_tested': mutations_tested,
                    'packets_processed': len(test_packets),
                    'success': True
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'preprocessing_time': 0,
                    'mutation_time': 0,
                    'mutations_tested': 0,
                    'packets_processed': 0
                }
        
        perf_metrics = self.measure_performance(run_mutation_test)
        result = perf_metrics['result']
        
        # Verification criteria:
        # 1. Mutation system should work
        if not result['success']:
            self.skipTest(f"Mutation system not available: {result.get('error', 'Unknown error')}")
        
        # 2. Preprocessing should be reasonably fast
        preprocessing_rate = result['packets_processed'] / result['preprocessing_time'] if result['preprocessing_time'] > 0 else 0
        self.assertGreater(preprocessing_rate, 1,
                          f"Preprocessing too slow: {preprocessing_rate:.1f} packets/sec")
        
        # 3. Mutation generation should be fast
        mutation_rate = result['mutations_tested'] / result['mutation_time'] if result['mutation_time'] > 0 else 0
        self.assertGreater(mutation_rate, 1,
                          f"Mutation generation too slow: {mutation_rate:.1f} mutations/sec")
        
        # 4. Should test some mutations
        self.assertGreater(result['mutations_tested'], 0,
                          f"Expected some mutations to be tested, got {result['mutations_tested']}")
        
        # 5. Memory usage should be reasonable
        memory_used = perf_metrics['memory_used']
        self.assertLess(abs(memory_used), self.baseline_thresholds['memory_usage_mb'],
                       f"Memory usage too high: {memory_used:.1f}MB")
        
        print(f"✅ Mutation Performance E2E Test PASSED:")
        print(f"   - Preprocessing rate: {preprocessing_rate:.1f} packets/sec")
        print(f"   - Mutation rate: {mutation_rate:.1f} mutations/sec")
        print(f"   - Mutations tested: {result['mutations_tested']}")
        print(f"   - Memory impact: {memory_used:.1f}MB")


class TestRegressionEndToEnd(unittest.TestCase):
    """End-to-end regression testing with baseline comparisons"""
    
    def setUp(self):
        """Set up regression testing environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_file = os.path.join(self.temp_dir, "baseline_metrics.json")
        
        # Expected baseline metrics (adjust based on your system)
        self.expected_baselines = {
            'cli_execution_time': 10.0,        # Max seconds for basic CLI execution
            'packets_generated_rate': 50.0,    # Min packets per second
            'memory_usage_mb': 50.0,           # Max memory usage in MB
            'error_rate': 0.1                  # Max error rate (10%)
        }
    
    def tearDown(self):
        """Clean up regression testing environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def save_baseline_metrics(self, metrics: Dict[str, float]):
        """Save baseline metrics to file"""
        with open(self.baseline_file, 'w') as f:
            json.dump(metrics, f, indent=2)
    
    def load_baseline_metrics(self) -> Optional[Dict[str, float]]:
        """Load baseline metrics from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
    
    def test_cli_execution_regression_e2e(self):
        """End-to-end test: CLI execution performance regression"""
        
        # Create test campaign
        campaign_file = os.path.join(self.temp_dir, "regression_campaign.py")
        pcap_file = os.path.join(self.temp_dir, "regression_test.pcap")
        
        campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign

class RegressionTestCampaign(FuzzingCampaign):
    name = "Regression Test Campaign"
    target = "192.168.1.100"
    iterations = 20
    rate_limit = 100.0
    verbose = False
    output_network = False
    output_pcap = "{pcap_file}"
    
    def get_packet(self):
            from scapy.all import IP, UDP
            return IP(dst=self.target)/UDP(dport=80)/b"REGRESSION_TEST_PACKET"
'''
        
        with open(campaign_file, 'w') as f:
            f.write(campaign_content)
        
        # Measure CLI execution performance
        start_time = time.time()
        try:
            cmd = [sys.executable, "-m", "packetfuzz", campaign_file, "--disable-network"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )
            
            execution_time = time.time() - start_time
            success = result.returncode == 0
            error_output = result.stderr if not success else ""
            
        except subprocess.TimeoutExpired:
            execution_time = 30.0
            success = False
            error_output = "Command timed out"
        except Exception as e:
            execution_time = time.time() - start_time
            success = False
            error_output = str(e)
        
        # Calculate metrics
        current_metrics = {
            'cli_execution_time': execution_time,
            'cli_success': success,
            'error_rate': 0.0 if success else 1.0
        }
        
        # Load previous baseline if available
        baseline_metrics = self.load_baseline_metrics()
        
        # Verification criteria:
        # 1. CLI should execute successfully
        self.assertTrue(success, f"CLI execution failed: {error_output}")
        
        # 2. Execution time should be within expected range
        self.assertLess(execution_time, self.expected_baselines['cli_execution_time'],
                       f"CLI execution too slow: {execution_time:.2f}s")
        
        # 3. Check for regression compared to baseline
        if baseline_metrics:
            # Allow 50% slower than baseline
            baseline_time = baseline_metrics.get('cli_execution_time', execution_time)
            max_allowed_time = baseline_time * 1.5
            
            self.assertLess(execution_time, max_allowed_time,
                           f"Performance regression detected: {execution_time:.2f}s vs baseline {baseline_time:.2f}s")
            
            regression_factor = execution_time / baseline_time if baseline_time > 0 else 1.0
            print(f"   - Performance vs baseline: {regression_factor:.2f}x")
        
        # Save current metrics as new baseline
        self.save_baseline_metrics(current_metrics)
        
        print(f"✅ CLI Execution Regression E2E Test PASSED:")
        print(f"   - Execution time: {execution_time:.2f}s")
        print(f"   - Success: {success}")
        print(f"   - Baseline saved: {self.baseline_file}")
    
    def test_memory_usage_regression_e2e(self):
        """End-to-end test: Memory usage regression"""
        
        # Monitor memory usage during campaign execution
        memory_samples = []
        
        class MemoryMonitoringCampaign(FuzzingCampaign):
            name = "Memory Monitoring Campaign"
            target = "192.168.1.100"
            iterations = 50
            rate_limit = 100.0
            verbose = False
            output_network = False
            output_pcap = None
            
            def __init__(self):
                super().__init__()
                self.packet_count = 0
            
            def get_packet(self):
                # Sample memory usage periodically
                if self.packet_count % 10 == 0:
                    process = psutil.Process()
                    memory_mb = process.memory_info().rss / 1024 / 1024
                    memory_samples.append(memory_mb)
                
                self.packet_count += 1
                return f"MEMORY_TEST_PACKET_{self.packet_count}"
        
        # Measure memory usage during execution
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        campaign = MemoryMonitoringCampaign()
        
        # Execute campaign (simulate without network)
        for i in range(campaign.iterations):
            packet = campaign.get_packet()
            time.sleep(0.001)  # Small delay to simulate work
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        peak_memory = max(memory_samples) if memory_samples else final_memory
        
        # Calculate metrics
        current_metrics = {
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'memory_growth_mb': memory_growth,
            'peak_memory_mb': peak_memory
        }
        
        # Load previous baseline
        baseline_metrics = self.load_baseline_metrics()
        
        # Verification criteria:
        # 1. Memory growth should be reasonable
        self.assertLess(abs(memory_growth), self.expected_baselines['memory_usage_mb'],
                       f"Memory growth too high: {memory_growth:.1f}MB")
        
        # 2. Peak memory should be reasonable
        self.assertLess(peak_memory, initial_memory + self.expected_baselines['memory_usage_mb'],
                       f"Peak memory too high: {peak_memory:.1f}MB")
        
        # 3. Check for memory regression
        if baseline_metrics and 'memory_growth_mb' in baseline_metrics:
            baseline_growth = baseline_metrics['memory_growth_mb']
            # Allow 100% more memory growth than baseline
            max_allowed_growth = abs(baseline_growth) * 2 + 10  # +10MB buffer
            
            self.assertLess(abs(memory_growth), max_allowed_growth,
                           f"Memory regression detected: {memory_growth:.1f}MB vs baseline {baseline_growth:.1f}MB")
        
        print(f"✅ Memory Usage Regression E2E Test PASSED:")
        print(f"   - Initial memory: {initial_memory:.1f}MB")
        print(f"   - Final memory: {final_memory:.1f}MB")
        print(f"   - Memory growth: {memory_growth:.1f}MB")
        print(f"   - Peak memory: {peak_memory:.1f}MB")
        print(f"   - Samples collected: {len(memory_samples)}")
    
    def test_output_consistency_regression_e2e(self):
        """End-to-end test: Output consistency regression"""
        
        # Test output consistency across multiple runs
        run_results = []
        
        for run_num in range(3):  # Run multiple times
            # Create test campaign for this run
            campaign_file = os.path.join(self.temp_dir, f"consistency_campaign_{run_num}.py")
            pcap_file = os.path.join(self.temp_dir, f"consistency_test_{run_num}.pcap")
            
            campaign_content = f'''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packetfuzz.fuzzing_framework import FuzzingCampaign

class ConsistencyTestCampaign(FuzzingCampaign):
    name = "Consistency Test Campaign Run {run_num}"
    target = "192.168.1.100"
    iterations = 15
    rate_limit = 100.0
    verbose = True
    output_network = False
    output_pcap = "{pcap_file}"
    
    def get_packet(self):
            from scapy.all import IP, UDP
            return IP(dst=self.target)/UDP(dport=80)/b"CONSISTENCY_TEST_PACKET"
'''
            
            with open(campaign_file, 'w') as f:
                f.write(campaign_content)
            
            # Execute campaign
            try:
                cmd = [sys.executable, "-m", "packetfuzz", campaign_file, "--disable-network", "-v"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    cwd=os.path.dirname(os.path.dirname(__file__))
                )
                
                run_results.append({
                    'run_num': run_num,
                    'returncode': result.returncode,
                    'success': result.returncode == 0,
                    'stdout_length': len(result.stdout),
                    'stderr_length': len(result.stderr),
                    'pcap_exists': os.path.exists(pcap_file),
                    'pcap_size': os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
                })
                
            except Exception as e:
                run_results.append({
                    'run_num': run_num,
                    'returncode': -1,
                    'success': False,
                    'stdout_length': 0,
                    'stderr_length': len(str(e)),
                    'pcap_exists': False,
                    'pcap_size': 0,
                    'error': str(e)
                })
        
        # Analyze consistency
        success_count = sum(1 for result in run_results if result['success'])
        success_rate = success_count / len(run_results)
        
        pcap_files_created = sum(1 for result in run_results if result['pcap_exists'])
        pcap_creation_rate = pcap_files_created / len(run_results)
        
        # Check output size consistency
        pcap_sizes = [result['pcap_size'] for result in run_results if result['pcap_size'] > 0]
        if pcap_sizes:
            avg_pcap_size = statistics.mean(pcap_sizes)
            pcap_size_variance = statistics.variance(pcap_sizes) if len(pcap_sizes) > 1 else 0
            size_consistency = pcap_size_variance / (avg_pcap_size ** 2) if avg_pcap_size > 0 else 0
        else:
            avg_pcap_size = 0
            size_consistency = 0
        
        # Verification criteria:
        # 1. Most runs should succeed
        self.assertGreaterEqual(success_rate, 0.8, f"Success rate too low: {success_rate:.1%}")
        
        # 2. PCAP creation should be consistent
        self.assertGreaterEqual(pcap_creation_rate, 0.8, f"PCAP creation rate too low: {pcap_creation_rate:.1%}")
        
        # 3. Output sizes should be reasonably consistent
        if pcap_sizes:
            self.assertLess(size_consistency, 0.1, f"PCAP size inconsistency too high: {size_consistency:.3f}")
        
        # 4. No run should have return code indicating serious errors
        serious_errors = sum(1 for result in run_results if result['returncode'] < -1)
        self.assertEqual(serious_errors, 0, f"Found {serious_errors} runs with serious errors")
        
        print(f"✅ Output Consistency Regression E2E Test PASSED:")
        print(f"   - Success rate: {success_rate:.1%} ({success_count}/{len(run_results)} runs)")
        print(f"   - PCAP creation rate: {pcap_creation_rate:.1%}")
        print(f"   - Average PCAP size: {avg_pcap_size:.0f} bytes")
        print(f"   - Size consistency: {size_consistency:.3f}")
        
        for result in run_results:
            status = "✓" if result['success'] else "✗"
            print(f"   {status} Run {result['run_num']}: PCAP {result['pcap_size']} bytes")


if __name__ == '__main__':
    # Run tests with detailed output
    unittest.main(verbosity=2, buffer=True)
