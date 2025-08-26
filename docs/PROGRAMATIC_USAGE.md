# PacketFuzz Programmatic Usage Guide

This guide covers how to use PacketFuzz programmatically in your Python applications.

## Basic Campaign Creation

```python
from packetfuzz.fuzzing_framework import FuzzingCampaign
from scapy.all import IP, TCP, Raw

class MyFuzzCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Campaign"
        self.target = "192.168.1.100"
        self.iterations = 50
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80) / Raw(load=b"test")]

# Execute the campaign
campaign = MyFuzzCampaign()
campaign.execute()
```

## Report Generation Configuration

### Single Report Format

```python
class HTMLReportCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "HTML Report Campaign"
        self.target = "192.168.1.100"
        self.report_formats = ['html']  # Generate HTML report
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
```

### Multiple Report Formats

```python
class MultiFormatCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Multi-Format Report Campaign"
        self.target = "192.168.1.100"
        # Generate multiple report formats
        self.report_formats = ['html', 'json', 'csv', 'sarif']
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
```

### All Report Formats

```python
class ComprehensiveReportCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Comprehensive Report Campaign"
        self.target = "192.168.1.100"
        # Generate all supported formats
        self.report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
```

## PCAP-Based Fuzzing with Reports

```python
from packetfuzz.pcapfuzz import PcapFuzzCampaign

class ReportingPcapCampaign(PcapFuzzCampaign):
    def __init__(self):
        super().__init__()
        self.pcap_folder = "test_data/"
        self.fuzz_mode = "field"
        self.iterations = 25
        self.target = "192.168.1.200"
        
        # Configure comprehensive reporting
        self.report_formats = ['html', 'json', 'sarif']
        self.output_pcap = "fuzzed_output.pcap"
        
# Execute with reporting
campaign = ReportingPcapCampaign()
result = campaign.execute()
```

## Advanced Campaign Configuration

### Security Analysis Campaign

```python
class SecurityAnalysisCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Security Analysis Campaign"
        self.target = "192.168.1.100"
        self.iterations = 100
        
        # SARIF format for security tools integration
        self.report_formats = ['sarif', 'html']
        
        # Enable comprehensive logging
        self.verbose = True
        self.output_pcap = "security_analysis.pcap"
        
        # Rate limiting for production testing
        self.rate_limit = 5  # 5 packets per second
        
    def build_packets(self):
        # Build security-focused test packets
        return [
            IP(dst=self.target) / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n"),
            IP(dst=self.target) / TCP(dport=443) / Raw(load=b"CONNECT"),
            IP(dst=self.target) / TCP(dport=22) / Raw(load=b"SSH-2.0-Test")
        ]
```

### Performance Testing Campaign

```python
class PerformanceTestCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Performance Test Campaign"
        self.target = "192.168.1.100"
        self.iterations = 1000
        
        # CSV format for performance analysis
        self.report_formats = ['csv', 'json']
        
        # High rate for performance testing
        self.rate_limit = 100  # 100 packets per second
        
    def build_packets(self):
        # High-volume test packets
        return [IP(dst=self.target) / TCP(dport=80) / Raw(load=b"x" * 1000)]
```

## Campaign Callbacks with Reporting

```python
class CallbackCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Callback Campaign"
        self.target = "192.168.1.100"
        self.report_formats = ['html', 'json']
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
        
    def pre_send_callback(self, packet, context):
        """Called before each packet is sent"""
        print(f"Sending packet {context.iteration}")
        return True  # Continue with sending
        
    def post_send_callback(self, packet, context):
        """Called after each packet is sent"""
        print(f"Sent packet {context.iteration}")
        
    def crash_callback(self, packet, context, error):
        """Called when a crash or error occurs"""
        print(f"Error with packet {context.iteration}: {error}")
        # Continue fuzzing despite errors
        return True
```

## Environment Integration

```python
import os
from packetfuzz.fuzzing_framework import FuzzingCampaign

class EnvironmentAwareCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Environment Aware Campaign"
        self.target = "192.168.1.100"
        
        # Configure based on environment
        env_formats = os.getenv('PACKETFUZZ_REPORT_FORMATS', 'json')
        self.report_formats = [f.strip() for f in env_formats.split(',')]
        
        # Other environment configurations
        if os.getenv('PACKETFUZZ_VERBOSE') == 'true':
            self.verbose = True
            
        pcap_file = os.getenv('PACKETFUZZ_PCAP_FILE')
        if pcap_file:
            self.output_pcap = pcap_file
            
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
```

## Custom Report Processing

```python
class CustomProcessingCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Custom Processing Campaign"
        self.target = "192.168.1.100"
        self.report_formats = ['json', 'html']
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
        
    def post_execution_callback(self, context):
        """Called after campaign execution completes"""
        # Custom processing of generated reports
        print(f"Campaign completed. Reports generated in formats: {self.report_formats}")
        
        # Could process or upload reports here
        for fmt in self.report_formats:
            report_file = f"report.{fmt}"
            if os.path.exists(report_file):
                print(f"Processing {fmt} report: {report_file}")
                # Custom processing logic here
```

## Integration with CI/CD

```python
class CICDCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "CI/CD Integration Campaign"
        self.target = "localhost"
        self.iterations = 50
        
        # SARIF for CI/CD security scanning integration
        # JSON for automated processing
        # HTML for human review
        self.report_formats = ['sarif', 'json', 'html']
        
        # No network output in CI/CD
        self.output_network = False
        self.output_pcap = "ci_test_results.pcap"
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=8080) / Raw(load=b"CI test")]
        
    def post_execution_callback(self, context):
        """Process results for CI/CD"""
        # Could integrate with CI/CD reporting systems
        print("CI/CD campaign completed")
        
        # Exit with appropriate code based on results
        if context.error_count > 0:
            print(f"Found {context.error_count} errors")
            # Could exit with error code for CI/CD failure
```

## Error Handling

```python
class RobustCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.name = "Robust Campaign"
        self.target = "192.168.1.100"
        self.report_formats = ['json', 'html']
        
    def build_packets(self):
        return [IP(dst=self.target) / TCP(dport=80)]
        
    def execute_with_error_handling(self):
        """Execute campaign with comprehensive error handling"""
        try:
            result = self.execute()
            print(f"Campaign completed successfully: {result}")
            return result
        except Exception as e:
            print(f"Campaign failed: {e}")
            # Still attempt to generate reports with available data
            try:
                # Force report generation even on failure
                # (This would need custom implementation)
                print("Attempting to generate partial reports...")
            except Exception as report_error:
                print(f"Report generation also failed: {report_error}")
            return False

# Usage
campaign = RobustCampaign()
success = campaign.execute_with_error_handling()
```

## Best Practices

### 1. Always Configure Appropriate Report Formats
```python
# For development/debugging
self.report_formats = ['html', 'json']

# For security analysis
self.report_formats = ['sarif', 'html']

# For performance analysis
self.report_formats = ['csv', 'json']

# For comprehensive analysis
self.report_formats = ['html', 'json', 'csv', 'sarif']
```

### 2. Use Environment Variables for Flexibility
```python
# Allow runtime configuration
env_formats = os.getenv('REPORT_FORMATS', 'json')
self.report_formats = [f.strip() for f in env_formats.split(',')]
```

### 3. Combine with PCAP Output for Complete Analysis
```python
self.output_pcap = "campaign_results.pcap"
self.report_formats = ['html', 'json']
```

### 4. Use Rate Limiting in Production
```python
# Don't overwhelm production systems
self.rate_limit = 5  # 5 packets per second
```

### 5. Implement Proper Error Handling
```python
def crash_callback(self, packet, context, error):
    print(f"Error: {error}")
    return True  # Continue despite errors
```