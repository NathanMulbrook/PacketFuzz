#!/usr/bin/env python3
"""
Scapy Fuzzer - Main Entry Point

This script provides a command-line interface for running fuzzing campaigns.
"""

# ===========================
# Standard Library Imports
# ===========================
import argparse
import sys
import importlib.util
from pathlib import Path
from typing import List, Type
import os

# ===========================
# Third-Party Imports
# ===========================
# (None required for CLI)

# ===========================
# Local Imports
# ===========================
from fuzzing_framework import FuzzingCampaign, logger
from mutators.libfuzzer_mutator import LibFuzzerMutator
from dictionary_manager import DictionaryManager


def load_campaigns_from_file(config_file: Path) -> List[Type[FuzzingCampaign]]:
    """
    Load campaign classes from a configuration file.
    
    Args:
        config_file: Path to the campaign configuration file
        
    Returns:
        List of campaign classes to execute
    """
    spec = importlib.util.spec_from_file_location("config", config_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load config from {config_file}")
    
    config_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_module)
    
    # Look for CAMPAIGNS list in the module
    if hasattr(config_module, 'CAMPAIGNS'):
        return config_module.CAMPAIGNS
    else:
        # Look for classes that inherit from FuzzingCampaign
        campaigns = []
        for name in dir(config_module):
            obj = getattr(config_module, name)
            if (isinstance(obj, type) and 
                issubclass(obj, FuzzingCampaign) and 
                obj != FuzzingCampaign):
                campaigns.append(obj)
        return campaigns


def check_components():
    """
    Check if all required components are available.
    
    Returns:
        int: 0 if all components available, 1 if LibFuzzer missing
        
    This function verifies the availability of:
    - LibFuzzer C extension for high-performance mutations
    - Dictionary manager for payload management  
    - FuzzDB dictionary database
    - Native dictionary support integration
    """
    from mutators.libfuzzer_mutator import LibFuzzerMutator
    from dictionary_manager import DictionaryManager
    import os
    
    print("Checking component availability...")
    
    # Check LibFuzzer extension
    try:
        mutator = LibFuzzerMutator()
        libfuzzer_available = mutator.is_libfuzzer_available()
        print(f"LibFuzzer extension: {'Available' if libfuzzer_available else 'Not available'}")
        
        if libfuzzer_available:
            try:
                # Check if native dictionary support works
                mutator.load_dictionaries_for_native_support(['test'])
                print("LibFuzzer native dictionary support: Available")
            except Exception as e:
                print(f"LibFuzzer native dictionary support: Error - {e}")
    except Exception as e:
        libfuzzer_available = False
        print(f"LibFuzzer extension: Not available - {e}")
    
    # Check dictionary manager
    try:
        dict_manager = DictionaryManager()
        print("Dictionary manager: Available")
        
        # Check fuzzdb directory
        fuzzdb_path = os.path.join(os.path.dirname(__file__), 'fuzzdb')
        if os.path.exists(fuzzdb_path):
            print("FuzzDB dictionaries: Available")
        else:
            print("FuzzDB dictionaries: Not found")
            
    except Exception as e:
        print(f"Dictionary manager: Error - {e}")
    
    # Overall status
    if libfuzzer_available:
        print("\nAll core components available - optimal fuzzing performance")
        return 0
    else:
        print("\nLibFuzzer extension not available - compile extension for optimal performance")
        return 1


def apply_cli_overrides(campaign, args):
    """
    Apply CLI flag overrides to a campaign instance.
    
    Args:
        campaign: FuzzingCampaign instance to modify
        args: Parsed CLI arguments from argparse
        
    This function applies command-line flag overrides to campaign attributes,
    allowing CLI flags to override campaign class defaults for network output,
    PCAP output, dictionary configuration, and verbose logging.
    """
    # Network
    if args.enable_network:
        campaign.output_network = True
    elif args.disable_network:
        campaign.output_network = False
    # PCAP
    if args.pcap_file:
        campaign.output_pcap = str(args.pcap_file)
    elif args.enable_pcap:
        if not campaign.output_pcap:
            campaign.output_pcap = f"{campaign.__class__.__name__.lower()}_output.pcap"
    elif args.disable_pcap:
        campaign.output_pcap = None
    # Auto-enable PCAP if network is disabled and no explicit PCAP setting
    if (not getattr(campaign, 'output_network', True) and 
        not getattr(campaign, 'output_pcap', None) and 
        not args.enable_pcap and not args.pcap_file):
        campaign.output_pcap = f"{campaign.__class__.__name__.lower()}_output.pcap"
    # Dictionary
    if args.dictionary_config:
        campaign.dictionary_config_file = str(args.dictionary_config)
    
    # Interface offload control
    if args.disable_offload:
        campaign.disable_interface_offload = True
    elif args.enable_offload:
        campaign.disable_interface_offload = False
    
    # Verbose
    if hasattr(campaign, 'verbose'):
        campaign.verbose = args.verbose


# ===========================
# Argument Parsing and CLI Setup
# ===========================

def main():
    """Main entry point for the packetfuzz CLI."""
    parser = argparse.ArgumentParser(
        description="Scapy Fuzzer - Advanced Network Protocol Fuzzing Framework"
    )
    parser.add_argument(
        "config_file",
        type=Path,
        nargs='?',
        help="Path to campaign configuration file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate campaigns without executing them."
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output."
    )
    parser.add_argument(
        "--list-campaigns",
        action="store_true",
        help="List available campaigns and exit."
    )
    
    # Output control flags (mutually exclusive groups)
    pcap_group = parser.add_mutually_exclusive_group()
    pcap_group.add_argument(
        "--enable-pcap",
        action="store_true",
        help="Enable PCAP output (uses campaign default filename or fuzzing_session.pcap)."
    )
    pcap_group.add_argument(
        "--disable-pcap",
        action="store_true",
        help="Disable PCAP output (overrides campaign configuration)."
    )
    
    network_group = parser.add_mutually_exclusive_group()
    network_group.add_argument(
        "--enable-network",
        action="store_true",
        help="Enable network transmission (overrides campaign configuration)."
    )
    network_group.add_argument(
        "--disable-network",
        action="store_true",
        help="Disable network transmission (overrides campaign configuration)."
    )
    
    output_group = parser.add_argument_group("Output Control")
    output_group.add_argument(
        "--pcap-file",
        type=Path,
        help="PCAP output file path (enables PCAP output if specified)."
    )
    
    parser.add_argument(
        "--check-components",
        action="store_true",
        help="Check if all required components (libFuzzer, dictionaries) are available and exit."
    )
    parser.add_argument(
        "--require-libfuzzer",
        action="store_true",
        help="Require libFuzzer extension to be available (fail if not)."
    )
    parser.add_argument(
        "--dictionary-config",
        type=Path,
        help="Path to user dictionary configuration file (overrides campaign settings)."
    )
    
    # Network interface offload control flags (mutually exclusive group)
    offload_group = parser.add_mutually_exclusive_group()
    offload_group.add_argument(
        "--disable-offload",
        action="store_true",
        help="Disable network interface hardware offload features for malformed packet fuzzing."
    )
    offload_group.add_argument(
        "--enable-offload", 
        action="store_true",
        help="Keep network interface hardware offload features enabled (default)."
    )
    
    args = parser.parse_args()
    
    # Component availability check
    if args.check_components:
        return check_components()
    
    # Require config file for other operations
    if not args.config_file:
        parser.error("config_file is required unless using --check-components")
    
    # Require LibFuzzer if specified
    if args.require_libfuzzer:
        from mutators.libfuzzer_mutator import LibFuzzerMutator
        mutator = LibFuzzerMutator()
        if not mutator.is_libfuzzer_available():
            logger.error("LibFuzzer extension is required but not available. Compile the extension first.")
            return 1
    
    # Load campaigns from config file
    try:
        campaigns = load_campaigns_from_file(args.config_file)
    except Exception as e:
        logger.error(f"Failed to load campaigns from {args.config_file}: {e}")
        return 1
    
    if not campaigns:
        logger.error("No campaigns found in configuration file")
        return 1
    
    # List campaigns if requested
    if args.list_campaigns:
        print(f"Found {len(campaigns)} campaigns in {args.config_file}:")
        for i, campaign_class in enumerate(campaigns, 1):
            instance = campaign_class()
            network_status = "Network: ON" if getattr(instance, 'output_network', False) else "Network: OFF"
            pcap_file = getattr(instance, 'output_pcap', None) or getattr(instance, 'pcap_filename', 'None')
            dict_config = getattr(instance, 'dictionary_config_file', None) or 'Default'
            
            # Show CLI override info if applicable
            if args.dictionary_config:
                dict_config = f"{args.dictionary_config} (CLI override)"
            
            print(f"  {i}. {campaign_class.__name__} ({network_status}, PCAP: {pcap_file}, Dict: {dict_config})")
        return 0
    
    # Execute campaigns
    success_count = 0
    for campaign_class in campaigns:
        try:
            campaign = campaign_class()
            apply_cli_overrides(campaign, args)
            logger.info(f"Processing campaign: {campaign_class.__name__}")
            # Show output configuration
            network_mode = "ENABLED" if getattr(campaign, 'output_network', True) else "DISABLED"
            pcap_file = getattr(campaign, 'output_pcap', None) or getattr(campaign, 'pcap_filename', 'None')
            dict_config = getattr(campaign, 'dictionary_config_file', None) or 'Default mappings'
            if args.verbose:
                logger.info(f"  Network transmission: {network_mode}")
                logger.info(f"  PCAP output: {pcap_file}")
                logger.info(f"  Dictionary config: {dict_config}")
            if args.dry_run:
                if campaign.validate_campaign():
                    logger.info(f"Campaign {campaign_class.__name__} is valid")
                    success_count += 1
                else:
                    logger.error(f"Campaign {campaign_class.__name__} validation failed")
            else:
                if campaign.execute():
                    logger.info(f"Campaign {campaign_class.__name__} completed successfully")
                    success_count += 1
                else:
                    logger.error(f"Campaign {campaign_class.__name__} failed")
        except Exception as e:
            logger.error(f"Campaign {campaign_class.__name__} error: {e}")
    
    # Summary
    total_campaigns = len(campaigns)
    if args.dry_run:
        logger.info(f"Validation complete: {success_count}/{total_campaigns} campaigns valid")
    else:
        logger.info(f"Execution complete: {success_count}/{total_campaigns} campaigns successful")
    
    return 0 if success_count == total_campaigns else 1


if __name__ == "__main__":
    sys.exit(main())
