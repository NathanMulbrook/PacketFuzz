#!/usr/bin/env python3
"""
PacketFuzz - Main Entry Point

This script provides a command-line interface for running fuzzing
campaigns against network protocols and services.

Environment Variable Support:
The CLI supports environment variables for all major configuration options.
Environment variables are applied as defaults when CLI arguments are not provided.
CLI arguments always take precedence over environment variables.

Supported Environment Variables:
- PACKETFUZZ_CONFIG_FILE: Path to campaign configuration file
- PACKETFUZZ_CONSOLE_VERBOSITY: Console verbosity level
- PACKETFUZZ_FILE_VERBOSITY: File verbosity level
- PACKETFUZZ_ENABLE_NETWORK: Set to "true" to enable network transmission
- PACKETFUZZ_DISABLE_NETWORK: Set to "true" to disable network transmission
- PACKETFUZZ_PCAP_FILE: Path to PCAP output file
- PACKETFUZZ_ENABLE_PCAP: Set to "true" to enable PCAP output
- PACKETFUZZ_DISABLE_PCAP: Set to "true" to disable PCAP output
- PACKETFUZZ_REPORT_FORMATS: Comma-separated list of report formats (html,json,csv,sarif,markdown,yaml,all)
- PACKETFUZZ_DICTIONARY_CONFIG: Path to dictionary configuration file
- PACKETFUZZ_DISABLE_OFFLOAD: Set to "true" to disable hardware offload
- PACKETFUZZ_ENABLE_OFFLOAD: Set to "true" to enable hardware offload

Example usage with environment variables:
  export PACKETFUZZ_CONFIG_FILE="campaign.py"
  export PACKETFUZZ_DISABLE_NETWORK="true"
  export PACKETFUZZ_PCAP_FILE="output.pcap"
  export PACKETFUZZ_CONSOLE_VERBOSITY="2"
  packetfuzz
"""

import argparse
import sys
import importlib.util
import logging
import os
from pathlib import Path
from typing import Any, List, Type

from .dictionary_manager import DictionaryManager
from .fuzzing_framework import FuzzingCampaign, logger
from .mutators.libfuzzer_mutator import LibFuzzerMutator


def load_campaigns_from_sources(config_sources: List[str]) -> List[Type[FuzzingCampaign]]:
    """
    Load campaign classes from multiple sources (files or directories).
    
    Args:
        config_sources: List of file paths or directory paths
        
    Returns:
        List of campaign classes to execute
    """
    all_campaigns = []
    
    for source in config_sources:
        config_path = Path(source)
        if not config_path.exists():
            logger.warning(f"Config path does not exist: {config_path}")
            continue
            
        try:
            if config_path.is_file() and config_path.suffix == '.py':
                # Single file
                campaigns = load_campaigns_from_file(config_path)
            elif config_path.is_dir():
                # Directory - load all .py files
                campaigns = []
                for py_file in config_path.glob("*.py"):
                    if py_file.name == "__init__.py":
                        continue
                    campaigns.extend(load_campaigns_from_file(py_file))
            else:
                logger.warning(f"Skipping invalid path: {config_path}")
                continue
                
            if campaigns:
                logger.info(f"Loaded {len(campaigns)} campaigns from {config_path}")
                all_campaigns.extend(campaigns)
            else:
                logger.warning(f"No campaigns found in {config_path}")
                
        except Exception as e:
            logger.error(f"Failed to load campaigns from {config_path}: {e}")
            continue
    
    return all_campaigns


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


def check_components() -> int:
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
    
    print("Checking component availability...")
    
    try:
        mutator = LibFuzzerMutator()
        libfuzzer_available = mutator.is_libfuzzer_available()
        print(f"LibFuzzer extension: {'Available' if libfuzzer_available else 'Not available'}")
        
        if not libfuzzer_available:
            return 1
            
    except ImportError as e:
        print(f"LibFuzzer extension: Not available - {e}")
        return 1
    
    try:
        for name in ['fuzzdb', 'seclists']:
            display = 'FuzzDB' if name == 'fuzzdb' else 'SecLists'
            path = os.path.join(os.path.dirname(__file__), name)
            print(f"{display} dictionaries: {'Available' if os.path.exists(path) else 'Not found'}")
    except (OSError, IOError) as e:
        print(f"Dictionary manager: Error - {e}")
        return 1
    
    print("All components available!")
    return 0


def apply_cli_overrides(campaign: Any, args: Any) -> None:
    """
    Apply command line arguments for network configuration, PCAP recording,
    PCAP output, dictionary configuration, and logging configuration.
    
    Args:
        campaign: FuzzingCampaign instance to modify
        args: Parsed CLI arguments from argparse
        
    This function applies command-line flag overrides to campaign attributes,
    allowing CLI flags to override campaign class defaults for network output,
    PCAP output, dictionary configuration, and logging configuration.
    """
    if args.enable_network:
        campaign.output_network = True
    elif args.disable_network:
        campaign.output_network = False

    if args.pcap_file:
        campaign.output_pcap = str(args.pcap_file)
    elif args.enable_pcap and not campaign.output_pcap:
        campaign.output_pcap = f"{campaign.__class__.__name__.lower()}_output.pcap"
    elif args.disable_pcap:
        campaign.output_pcap = None

    if (not getattr(campaign, 'output_network', True) and 
        not getattr(campaign, 'output_pcap', None) and 
        not args.enable_pcap and not args.pcap_file and not args.disable_pcap):
        campaign.output_pcap = f"{campaign.__class__.__name__.lower()}_output.pcap"

    if args.dictionary_config:
        campaign.dictionary_config_file = str(args.dictionary_config)
    
    if args.max_iterations:
        campaign.iterations = args.max_iterations
    
    if args.disable_offload:
        campaign.disable_interface_offload = True
    elif args.enable_offload:
        campaign.disable_interface_offload = False
    
    # Set campaign verbose attribute based on console verbosity for backwards compatibility
    campaign.verbose = max(
        getattr(args, 'console_verbosity', 0) or 0,
        getattr(args, 'file_verbosity', 0) or 0,
        getattr(args, 'log_verbosity', 0) or 0
    )
    
    if args.report_formats:
        if 'all' in args.report_formats:
            campaign.report_formats = ['html', 'json', 'csv', 'sarif', 'markdown', 'yaml']
        else:
            campaign.report_formats = args.report_formats

    if args.report_level:
        campaign.report_level = args.report_level


## Logging Configuration
    if args.console_verbosity:
        console_verbosity = args.console_verbosity
    else:
        console_verbosity = 0

    if args.file_verbosity:
        file_verbosity = args.file_verbosity
    elif args.log_verbosity and args.log_verbosity > 0:
        file_verbosity = args.log_verbosity
    else:
        file_verbosity = 0
    
    # Convert verbosity to log levels (inline to avoid tiny helper)
    console_level = logging.DEBUG if console_verbosity >= 2 else logging.INFO if console_verbosity >= 1 else logging.WARNING
    file_level = logging.DEBUG if file_verbosity >= 2 else logging.INFO if file_verbosity >= 1 else logging.WARNING
    
    root_logger = logging.getLogger()
    root_logger.setLevel(min(console_level, file_level))
    
    console_handler = next((h for h in root_logger.handlers 
                           if isinstance(h, logging.StreamHandler) and h.stream.name in ['<stdout>', '<stderr>']), None)
    if console_handler:
        console_handler.setLevel(console_level)
    else:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        root_logger.addHandler(console_handler)
    
    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            handler.setLevel(file_level)
    
    if max(console_verbosity, file_verbosity) >= 2:
        logger.debug(f"Logging configured - Console: {logging.getLevelName(console_level)}, "
                    f"File: {logging.getLevelName(file_level)} "
                    f"(console verbosity: {console_verbosity}, file verbosity: {file_verbosity})")
    elif max(console_verbosity, file_verbosity) >= 1:
        logger.info(f"Logging enabled - Console: {logging.getLevelName(console_level)}, "
                   f"File: {logging.getLevelName(file_level)}")


# ===========================
# Argument Parsing and CLI Setup
# ===========================

def main() -> int:
    """Main entry point for the packetfuzz CLI."""
    # Environment variable defaults
    env_defaults = {
        'config_file': os.getenv('PACKETFUZZ_CONFIG_FILE'),
        'log_verbosity': int(os.getenv('PACKETFUZZ_LOG_VERBOSITY', '0')),
        'console_verbosity': int(os.getenv('PACKETFUZZ_CONSOLE_VERBOSITY', '0')) if os.getenv('PACKETFUZZ_CONSOLE_VERBOSITY') else None,
        'file_verbosity': int(os.getenv('PACKETFUZZ_FILE_VERBOSITY', '0')) if os.getenv('PACKETFUZZ_FILE_VERBOSITY') else None,
        'pcap_file': os.getenv('PACKETFUZZ_PCAP_FILE'),
        'dictionary_config': os.getenv('PACKETFUZZ_DICTIONARY_CONFIG'),
        'report_formats': [f.strip() for f in os.getenv('PACKETFUZZ_REPORT_FORMATS', 'json').split(',') if f.strip()],
        'enable_network': os.getenv('PACKETFUZZ_ENABLE_NETWORK') == 'true',
        'disable_network': os.getenv('PACKETFUZZ_DISABLE_NETWORK') == 'true',
        'enable_pcap': os.getenv('PACKETFUZZ_ENABLE_PCAP') == 'true',
        'disable_pcap': os.getenv('PACKETFUZZ_DISABLE_PCAP') == 'true',
        'disable_offload': os.getenv('PACKETFUZZ_DISABLE_OFFLOAD') == 'true',
    }
    
    parser = argparse.ArgumentParser(
        description="PacketFuzzer - Advanced Network Protocol Fuzzing Framework",
        epilog="Environment variables (PACKETFUZZ_*) can be used as defaults for all options. "
               "CLI arguments take precedence over environment variables.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "config_file",
        type=str,
        nargs='*',
        help="Path(s) to campaign configuration file(s) or directory(ies). "
             "Supports single files, multiple files, directories, or packages. "
             "Environment variable: PACKETFUZZ_CONFIG_FILE"
    )
    parser.add_argument(
        "-l",
        action="count",
        default=env_defaults['log_verbosity'],
        dest="log_verbosity",
        help="Increase log file verbosity: -l (INFO), -ll (DEBUG), -lll+ (more detailed)."
    )
    parser.add_argument(
        "--console-verbosity",
        type=int,
        choices=range(0, 6),
        metavar="0-5",
        default=env_defaults['console_verbosity'],
        help="Set console verbosity level (0=WARNING, 1=INFO, 2+=DEBUG). "
             "Can also set PACKETFUZZ_CONSOLE_VERBOSITY"
    )
    parser.add_argument(
        "--file-verbosity", 
        type=int,
        choices=range(0, 6),
        metavar="0-5",
        default=env_defaults['file_verbosity'],
        help="Set file verbosity level (0=WARNING, 1=INFO, 2+=DEBUG). "
             "Can also set PACKETFUZZ_FILE_VERBOSITY"
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
        help="Enable network transmission (overrides campaign configuration). "
             "Can also set PACKETFUZZ_ENABLE_NETWORK=true"
    )
    network_group.add_argument(
        "--disable-network",
        action="store_true",
        help="Disable network transmission (overrides campaign configuration). "
             "Can also set PACKETFUZZ_DISABLE_NETWORK=true"
    )
    
    output_group = parser.add_argument_group("Output Control")
    output_group.add_argument(
        "--pcap-file",
        type=Path,
        default=env_defaults['pcap_file'],
        help="PCAP output file path (enables PCAP output if specified). "
             "Can also set PACKETFUZZ_PCAP_FILE"
    )
    output_group.add_argument(
        "--report-formats",
        nargs='+',
        choices=['html', 'json', 'csv', 'sarif', 'markdown', 'yaml', 'all'],
    default=env_defaults['report_formats'],
        help="Report output formats (can specify multiple). Use 'all' for all formats. "
             "Can also set PACKETFUZZ_REPORT_FORMATS as comma-separated list (default: json)"
    )
    output_group.add_argument(
        "--report-level",
        choices=['executive', 'technical', 'forensics', 'advanced'],
        default='advanced',
        help="Report detail level: executive (high-level overview), technical (security analysis), "
             "forensics (deep packet analysis), advanced (fuzzing performance metrics)"
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
        default=env_defaults['dictionary_config'],
        help="Path to user dictionary configuration file (overrides campaign settings)."
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Override the number of fuzzing iterations for the campaign (overrides campaign configuration)."
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
    
    # Apply environment variable defaults for boolean flags (only if not set by CLI)
    if not args.enable_network and not args.disable_network and env_defaults['enable_network']:
        args.enable_network = True
    if not args.enable_network and not args.disable_network and env_defaults['disable_network']:
        args.disable_network = True
    if not args.enable_pcap and not args.disable_pcap and env_defaults['enable_pcap']:
        args.enable_pcap = True
    if not args.enable_pcap and not args.disable_pcap and env_defaults['disable_pcap']:
        args.disable_pcap = True
    if not args.disable_offload and env_defaults['disable_offload']:
        args.disable_offload = True
    
    # Component availability check
    if args.check_components:
        return check_components()
    
    # Handle config file arguments (environment variable or positional args)
    config_sources = []
    if args.config_file:
        config_sources = args.config_file
    elif env_defaults['config_file']:
        config_sources = [env_defaults['config_file']]
    
    # Require config file for other operations
    if not config_sources:
        parser.error("config_file is required unless using --check-components")
    
    # Require LibFuzzer if specified
    if args.require_libfuzzer:
        mutator = LibFuzzerMutator()
        if not mutator.is_libfuzzer_available():
            logger.error("LibFuzzer extension is required but not available. Compile the extension first.")
            return 1
    
    # Load campaigns from all config sources
    campaigns = load_campaigns_from_sources(config_sources)
    
    if not campaigns:
        logger.error("No campaigns found in any configuration source")
        return 1
    
    # List campaigns if requested
    if args.list_campaigns:
        print(f"Found {len(campaigns)} campaigns from {len(config_sources)} source(s):")
        for i, campaign_class in enumerate(campaigns, 1):
            instance = campaign_class()
            network_status = "Network: ON" if getattr(instance, 'output_network', False) else "Network: OFF"
            pcap_file = getattr(instance, 'output_pcap', None) or getattr(instance, 'pcap_filename', 'None')
            dict_config = getattr(instance, 'dictionary_config_file', None) or 'Default'
            
            if args.dictionary_config:
                dict_config = f"{args.dictionary_config} (CLI override)"
            
            print(f"  {i}. {campaign_class.__name__} ({network_status}, PCAP: {pcap_file}, Dict: {dict_config})")
        return 0
    
    success_count = 0
    total_campaigns = len(campaigns)
    for campaign_class in campaigns:
        campaign = campaign_class()
        apply_cli_overrides(campaign, args)
        # Determine verbosity for output (use campaign.verbose as proxy for overall verbosity)
        current_verbosity = getattr(campaign, 'verbose', 0)
        
        # Level 0: Basic progress via print (always shown)
        if current_verbosity == 0:
            print(f"Processing campaign: {campaign_class.__name__}")
        else:
            logger.info(f"Processing campaign: {campaign_class.__name__}")
            
        network_mode = "ENABLED" if getattr(campaign, 'output_network', True) else "DISABLED"
        pcap_file = getattr(campaign, 'output_pcap', None) or getattr(campaign, 'pcap_filename', 'None')
        dict_config = getattr(campaign, 'dictionary_config_file', None) or 'Default mappings'
        
        # Verbosity level 1: Show campaign configuration details
        if current_verbosity >= 1:
            logger.info(f"  Network transmission: {network_mode}")
            logger.info(f"  PCAP output: {pcap_file}")
            logger.info(f"  Dictionary config: {dict_config}")
        
        # Verbosity level 2+: Show additional campaign details
        if current_verbosity >= 2:
            logger.debug(f"  Campaign class: {campaign_class}")
            logger.debug(f"  Packets to fuzz: {getattr(campaign, 'packets_to_fuzz', 'Unknown')}")
            logger.debug(f"  Mutator: {getattr(campaign, 'mutator_manager', 'Default')}")
            logger.debug(f"  Verbose mode: {getattr(campaign, 'verbose', False)}")
        
        # Always execute campaign, but if --disable-network is set, output_network will be False
        if campaign.execute():
            if current_verbosity == 0:
                print(f"Campaign {campaign_class.__name__} completed successfully")
            else:
                logger.info(f"Campaign {campaign_class.__name__} completed successfully")
            success_count += 1
        else:
            if args.console_verbosity == 0:
                print(f"Campaign {campaign_class.__name__} failed")
            else:
                logger.error(f"Campaign {campaign_class.__name__} failed")
    
    # Summary
    if args.console_verbosity == 0:
        print(f"Execution complete: {success_count}/{total_campaigns} campaigns successful")
    else:
        logger.info(f"Execution complete: {success_count}/{total_campaigns} campaigns successful")
    
    return 0 if success_count == total_campaigns else 1


if __name__ == "__main__":
    sys.exit(main())
