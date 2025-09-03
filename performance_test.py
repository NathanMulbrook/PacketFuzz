#!/usr/bin/env python3
"""
Performance test script to measure the impact of optimization changes.
"""

import time
from examples.basic.01_quick_start import QuickStartCampaign, QuickStartCampaignMultilayer

def run_performance_test():
    """Run performance test with timing measurements."""
    
    # Test both campaigns with reduced iterations for comparison
    campaigns = [
        (QuickStartCampaign, "Quick Start (HTTP only)"),
        (QuickStartCampaignMultilayer, "Quick Start Multilayer (IP/TCP/HTTP)")
    ]
    
    for campaign_class, name in campaigns:
        print(f"\n{'='*60}")
        print(f"Testing: {name}")
        print(f"{'='*60}")
        
        # Create campaign instance with reduced iterations
        campaign = campaign_class()
        campaign.iterations = 10  # Reduced for testing
        campaign.verbose = 2  # Moderate verbosity
        campaign.report_formats = ['json']  # Single format for testing
        
        start_time = time.time()
        
        try:
            success = campaign.execute()
            end_time = time.time()
            
            elapsed = end_time - start_time
            print(f"Result: {'SUCCESS' if success else 'FAILED'}")
            print(f"Duration: {elapsed:.2f} seconds")
            print(f"Rate: {campaign.iterations / elapsed:.2f} iterations/second")
            
        except Exception as e:
            end_time = time.time()
            elapsed = end_time - start_time
            print(f"Result: ERROR - {e}")
            print(f"Duration: {elapsed:.2f} seconds")
    
    print(f"\n{'='*60}")
    print("Performance test complete!")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_performance_test()
