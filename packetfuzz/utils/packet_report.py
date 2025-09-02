#!/usr/bin/env python3
"""
Advanced Reporting System for PacketFuzz Framework

Provides modular, multi-tier reporting capabilities leveraging enhanced
FuzzHistoryEntry data and Scapy protocol intelligence for enterprise-grade
vulnerability analysis and campaign reporting.

Features:
- Executive summary reports with actionable insights
- Technical analysis with protocol-specific intelligence
- Deep forensics with packet-level analysis
- Multiple export formats (HTML, JSON, CSV, SARIF)
- Real-time campaign monitoring
- Scapy-enhanced protocol coverage analysis
"""
# Standard library imports
import base64
import json
import logging
import os
import threading
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

# Third-party imports
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration Constants
# ============================================================================

# Report generation settings
DEFAULT_MAX_FINDINGS = 100
DEFAULT_TOP_MUTATORS_COUNT = 10
DEFAULT_TOP_FIELDS_COUNT = 10
MAX_PROTOCOL_ANALYSIS_DEPTH = 50
VULNERABILITY_CONFIDENCE_THRESHOLD = 0.7

# Performance settings
METRICS_CALCULATION_TIMEOUT = 30  # seconds
PROTOCOL_ANALYSIS_TIMEOUT = 60   # seconds

# Export format settings
MAX_REPORT_SIZE_MB = 50
DEFAULT_HTML_TEMPLATE_TIMEOUT = 10  # seconds


# ============================================================================
# Report Data Structures
# ============================================================================

class ReportLevel(Enum):
    """Report detail levels for different audiences"""
    EXECUTIVE = "executive"      # High-level overview for management
    TECHNICAL = "technical"      # Mid-level analysis for security teams
    FORENSICS = "forensics"      # Deep packet analysis for researchers
    ADVANCED = "advanced"        # Detailed fuzzing performance and mutator analysis


@dataclass
class ReportMetrics:
    """Core metrics calculated from campaign history"""
    total_packets: int = 0
    successful_packets: int = 0
    failed_packets: int = 0
    serialization_failures: int = 0
    crash_count: int = 0
    unique_targets: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    error_categories: Dict[str, int] = field(default_factory=dict)
    mutation_effectiveness: Dict[str, int] = field(default_factory=dict)
    
    # Time-based metrics
    campaign_duration: Optional[timedelta] = None
    packets_per_second: float = 0.0
    
    # Protocol analysis
    port_coverage: Set[int] = field(default_factory=set)
    payload_sizes: List[int] = field(default_factory=list)
    network_layers: Set[str] = field(default_factory=set)
    
    # Fuzzed field tracking
    fuzzed_field_distribution: Dict[str, int] = field(default_factory=dict)  # field_name -> count
    packets_with_fuzzed_fields: int = 0
    packets_without_fuzzed_fields: int = 0
    most_fuzzed_fields: List[str] = field(default_factory=list)  # Top fuzzed fields
    
    # Enhanced field metadata tracking - direct access to FieldMetadata objects
    detailed_field_metadata: Dict[str, Any] = field(default_factory=dict)  # field_name -> FieldMetadata dict
    
    # Mutator usage tracking
    mutator_usage: Dict[str, int] = field(default_factory=dict)  # mutator_name -> usage_count
    total_mutations_applied: int = 0
    most_used_mutators: List[str] = field(default_factory=list)  # Top mutators by usage


@dataclass
class VulnerabilityFinding:
    """
    Represents an anomaly or pattern of interest discovered during fuzzing.
    
    Note: These are not confirmed vulnerabilities - they are observations
    that warrant further investigation by security researchers.
    """
    finding_id: str
    severity: str  # "info", "low", "medium", "high" (based on observable impact only)
    category: str  # "serialization_failure", "application_crash", "response_anomaly", etc.
    description: str
    affected_packet: Optional[Packet] = None
    reproduction_data: Optional[bytes] = None
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: str = field(default="low")  # "low", "medium", "high" - how certain we are


@dataclass
class ProtocolAnalysis:
    """Protocol-specific analysis results"""
    protocol_name: str
    packet_count: int
    unique_ports: Set[int]
    payload_variations: int
    error_patterns: Dict[str, int]
    potential_vulnerabilities: List[VulnerabilityFinding]
    scapy_layer_coverage: Set[str]


# ============================================================================
# Core Interfaces for Modularity
# ============================================================================

class ReportGeneratorInterface:
    """Interface for report content generators"""
    
    def generate(
        self,
        campaign: Any,
        metrics: ReportMetrics,
        protocol_analysis: Dict[str, ProtocolAnalysis],
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """Generate report content"""
        raise NotImplementedError("Subclasses must implement generate()")


class ExporterInterface:
    """Interface for report exporters"""
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        """Export content to specified format and path"""
        raise NotImplementedError("Subclasses must implement export()")
    
    def get_file_extension(self) -> str:
        """Return the file extension for this export format"""
        raise NotImplementedError("Subclasses must implement get_file_extension()")


# ============================================================================
# Core Reporting Engine Components
# ============================================================================

class MetricsCalculator:
    """Handles calculation of various metrics from campaign data"""
    
    @staticmethod
    def calculate_basic_metrics(history_entries: List[Any]) -> Dict[str, Any]:
        """Calculate basic packet and timing metrics"""
        if not history_entries:
            return {
                'total_packets': 0,
                'successful_packets': 0,
                'failed_packets': 0,
                'serialization_failures': 0,
                'crash_count': 0
            }
        
        return {
            'total_packets': len(history_entries),
            'successful_packets': len([h for h in history_entries if not h.serialization_failed]),
            'failed_packets': len([h for h in history_entries if h.serialization_failed]),
            'serialization_failures': len([h for h in history_entries if h.serialization_failed]),
            'crash_count': len([h for h in history_entries if h.crashed])
        }
    
    @staticmethod
    def calculate_field_metrics(history_entries: List[Any]) -> Dict[str, Any]:
        """Calculate field-level fuzzing metrics"""
        try:
            field_distribution = {}
            packets_with_fields = 0
            packets_without_fields = 0
            
            for entry in history_entries:
                if hasattr(entry, 'fuzzed_fields') and entry.fuzzed_fields:
                    packets_with_fields += 1
                    for field_name in entry.fuzzed_fields:
                        field_distribution[field_name] = field_distribution.get(field_name, 0) + 1
                else:
                    packets_without_fields += 1
            
            # Get top most fuzzed fields using configuration constant
            sorted_fields = sorted(field_distribution.items(), key=lambda x: x[1], reverse=True)
            most_fuzzed_fields = [field for field, count in sorted_fields[:DEFAULT_TOP_FIELDS_COUNT]]
            
            return {
                'fuzzed_field_distribution': field_distribution,
                'packets_with_fuzzed_fields': packets_with_fields,
                'packets_without_fuzzed_fields': packets_without_fields,
                'most_fuzzed_fields': most_fuzzed_fields
            }
        except Exception as e:
            logger.error(f"Failed to calculate field metrics: {e}")
            return {
                'fuzzed_field_distribution': {},
                'packets_with_fuzzed_fields': 0,
                'packets_without_fuzzed_fields': len(history_entries) if history_entries else 0,
                'most_fuzzed_fields': []
            }
    
    @staticmethod
    def calculate_protocol_metrics(history_entries: List[Any]) -> Dict[str, Any]:
        """Calculate protocol and network-level metrics"""
        protocol_distribution = {}
        port_coverage = set()
        payload_sizes = []
        
        for entry in history_entries:
            if entry.protocol:
                protocol_distribution[entry.protocol] = protocol_distribution.get(entry.protocol, 0) + 1
            if entry.target_port:
                port_coverage.add(entry.target_port)
            if entry.payload_size:
                payload_sizes.append(entry.payload_size)
        
        unique_targets = len(set(h.target_host for h in history_entries if h.target_host))
        
        return {
            'protocol_distribution': protocol_distribution,
            'port_coverage': port_coverage,
            'payload_sizes': payload_sizes,
            'unique_targets': unique_targets
        }
    
    @staticmethod
    def calculate_timing_metrics(history_entries: List[Any]) -> Dict[str, Any]:
        """Calculate timing and performance metrics"""
        timestamps = [h.timestamp_sent for h in history_entries if h.timestamp_sent]
        
        if len(timestamps) < 2:
            return {
                'campaign_duration': None,
                'packets_per_second': 0.0
            }
        
        duration = max(timestamps) - min(timestamps)
        packets_per_second = len(history_entries) / duration.total_seconds() if duration.total_seconds() > 0 else 0.0
        
        return {
            'campaign_duration': duration,
            'packets_per_second': packets_per_second
        }


class MutatorAnalyzer:
    """Handles analysis of mutator usage and effectiveness"""
    
    @staticmethod
    def extract_mutator_metrics(mutator_data: Any) -> Dict[str, Any]:
        """Extract comprehensive mutator metrics from MutatorManagerData"""
        if not mutator_data:
            logger.info("No mutator data available for enhanced metrics")
            return {
                'mutator_usage': {},
                'total_mutations_applied': 0,
                'most_used_mutators': [],
                'detailed_field_metadata': {}
            }
        
        try:
            mutator_usage = {}
            total_mutations = 0
            detailed_field_metadata = {}
            
            # Get mutator usage summary
            if hasattr(mutator_data, 'get_mutator_usage_summary'):
                mutator_usage = mutator_data.get_mutator_usage_summary()
                total_mutations = sum(mutator_usage.values())
            
            # Calculate most used mutators using configuration constant
            sorted_mutators = sorted(mutator_usage.items(), key=lambda x: x[1], reverse=True)
            most_used_mutators = [mutator for mutator, count in sorted_mutators[:DEFAULT_TOP_MUTATORS_COUNT]]
            
            # Extract detailed field metadata from all fuzzable fields
            if hasattr(mutator_data, 'get_all_fuzzable_fields'):
                try:
                    fuzzable_fields = mutator_data.get_all_fuzzable_fields()
                    for field_metadata in fuzzable_fields:
                        # Convert FieldMetadata to a JSON-serializable dict
                        field_dict = {
                            'field_key': field_metadata.field_key,
                            'layer_name': field_metadata.layer_name,
                            'field_name': field_metadata.field_name,
                            'layer_index': field_metadata.layer_index,
                            'packet_index': field_metadata.packet_index,
                            'field_type': field_metadata.field_type,
                            'field_kind': field_metadata.field_kind,
                            'current_value': str(field_metadata.current_value) if field_metadata.current_value is not None else None,
                            'fuzz_weight': field_metadata.fuzz_weight,
                            'base_weight': field_metadata.base_weight,
                            'final_scaling_factor': field_metadata.final_scaling_factor,
                            'dictionary_paths': field_metadata.dictionary_paths.copy() if field_metadata.dictionary_paths else [],
                            'mutator_preferences': field_metadata.mutator_preferences.copy() if field_metadata.mutator_preferences else [],
                            'min_value': field_metadata.min_value,
                            'max_value': field_metadata.max_value,
                            'max_length': field_metadata.max_length,
                            'enum_values': field_metadata.enum_values.copy() if field_metadata.enum_values else None,
                            'is_signed': field_metadata.is_signed,
                            'is_fuzzable': field_metadata.is_fuzzable,
                            'exclusion_reason': field_metadata.exclusion_reason,
                            'config_source': field_metadata.config_source,
                            'mutation_count': field_metadata.mutation_count,
                            'successful_mutations': field_metadata.successful_mutations,
                            'failed_mutations': field_metadata.failed_mutations,
                            'last_mutated': field_metadata.last_mutated.isoformat() if field_metadata.last_mutated else None,
                        }
                        detailed_field_metadata[field_metadata.field_key] = field_dict
                    logger.debug(f"Extracted detailed metadata for {len(detailed_field_metadata)} fields")
                except Exception as e:
                    logger.warning(f"Failed to extract field metadata: {e}")
            
            # Log additional processing info if available
            if hasattr(mutator_data, 'get_processing_summary'):
                processing_summary = mutator_data.get_processing_summary()
                logger.debug(f"Mutator processing summary: {processing_summary}")
            
            return {
                'mutator_usage': mutator_usage,
                'total_mutations_applied': total_mutations,
                'most_used_mutators': most_used_mutators,
                'detailed_field_metadata': detailed_field_metadata
            }
            
        except Exception as e:
            logger.warning(f"Failed to extract mutator metrics - this could indicate mutator manager issues: {e}")
            # TODO: Consider propagating specific mutator failures to help with debugging mutator manager issues
            return {
                'mutator_usage': {},
                'total_mutations_applied': 0,
                'most_used_mutators': [],
                'detailed_field_metadata': {}
            }


# ============================================================================
# Core Reporting Engine
# ============================================================================

class ReportingEngine:
    """Central reporting engine with pluggable generators and exporters"""
    
    def __init__(self):
        self.generators = {
            ReportLevel.EXECUTIVE: ExecutiveSummaryGenerator(),
            ReportLevel.TECHNICAL: TechnicalAnalysisGenerator(),
            ReportLevel.FORENSICS: ForensicsGenerator(),
            ReportLevel.ADVANCED: AdvancedPerformanceGenerator()
        }
        self.exporters = {
            'html': HTMLExporter(),
            'json': JSONExporter(),
            'csv': CSVExporter(),
            'sarif': SARIFExporter(),
            'markdown': MarkdownExporter(),
            'yaml': YAMLExporter()
        }
        self.protocol_analyzer = ProtocolIntelligenceAnalyzer()
    
    def register_exporter(self, format_name: str, exporter: ExporterInterface) -> None:
        """Register a new export format"""
        self.exporters[format_name] = exporter
        logger.info(f"Registered new export format: {format_name}")
    
    def register_generator(self, level: ReportLevel, generator: ReportGeneratorInterface) -> None:
        """Register a new report generator"""
        self.generators[level] = generator
        logger.info(f"Registered new report generator for level: {level.value}")
    
    def get_available_formats(self) -> List[str]:
        """Get list of available export formats"""
        return list(self.exporters.keys())
    
    def get_available_levels(self) -> List[str]:
        """Get list of available report levels"""
        return [level.value for level in self.generators.keys()]
    
    def generate_report(
        self,
        campaign: Any,
        campaign_context: Any,
        history_entries: List[Any],
        level: ReportLevel = ReportLevel.TECHNICAL,
        output_format: str = 'html',
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate comprehensive report for campaign
        
        Args:
            campaign: The fuzzing campaign instance
            campaign_context: Campaign context containing mutator data and runtime info
            history_entries: List of FuzzHistoryEntry objects from the campaign
            level: Report detail level (executive, technical, forensics)
            output_format: Export format (html, json, csv, etc.)
            output_path: Optional custom output path
            
        Returns:
            Path to the generated report file
        """
        # Validate inputs
        if level not in self.generators:
            raise ValueError(f"Unsupported report level: {level}. Available: {self.get_available_levels()}")
        
        if output_format not in self.exporters:
            raise ValueError(f"Unsupported output format: {output_format}. Available: {self.get_available_formats()}")
        
        # Calculate core metrics with campaign context
        metrics = self._calculate_metrics(history_entries, campaign_context)
        
        # Perform protocol analysis
        protocol_analysis = self.protocol_analyzer.analyze_campaign(history_entries)
        
        # Generate findings
        findings = self._detect_vulnerabilities(history_entries, protocol_analysis)
        
        # Generate report content
        generator = self.generators[level]
        content = generator.generate(campaign, metrics, protocol_analysis, findings)
        
        # Export in requested format
        exporter = self.exporters[output_format]
        if not output_path:
            extension = exporter.get_file_extension()
            output_path = self._generate_output_path(campaign, level, extension)
        
        return exporter.export(content, output_path)
    
    def _calculate_metrics(self, history_entries: List[Any], campaign_context: Any) -> ReportMetrics:
        """
        Calculate comprehensive metrics from history entries and campaign context
        
        Args:
            history_entries: List of FuzzHistoryEntry objects
            campaign_context: CampaignContext containing mutator data and runtime info
            
        Returns:
            ReportMetrics object with comprehensive campaign analytics
        """
        metrics = ReportMetrics()
        
        if not history_entries:
            return metrics
        
        # Calculate metrics using modular utility classes
        basic_metrics = MetricsCalculator.calculate_basic_metrics(history_entries)
        field_metrics = MetricsCalculator.calculate_field_metrics(history_entries)
        protocol_metrics = MetricsCalculator.calculate_protocol_metrics(history_entries)
        timing_metrics = MetricsCalculator.calculate_timing_metrics(history_entries)
        
        # Extract mutator data for enhanced analytics
        mutator_data = getattr(campaign_context, 'mutator_data', None)
        mutator_metrics = MutatorAnalyzer.extract_mutator_metrics(mutator_data)
        
        # Populate ReportMetrics object
        self._populate_metrics(metrics, basic_metrics, field_metrics, protocol_metrics, timing_metrics, mutator_metrics)
        
        return metrics
    
    def _populate_metrics(self, metrics: ReportMetrics, basic: Dict, field: Dict, protocol: Dict, timing: Dict, mutator: Dict) -> None:
        """Populate ReportMetrics object from calculated metric dictionaries"""
        # Basic metrics
        metrics.total_packets = basic['total_packets']
        metrics.successful_packets = basic['successful_packets']
        metrics.failed_packets = basic['failed_packets']
        metrics.serialization_failures = basic['serialization_failures']
        metrics.crash_count = basic['crash_count']
        
        # Field metrics
        metrics.fuzzed_field_distribution = field['fuzzed_field_distribution']
        metrics.packets_with_fuzzed_fields = field['packets_with_fuzzed_fields']
        metrics.packets_without_fuzzed_fields = field['packets_without_fuzzed_fields']
        metrics.most_fuzzed_fields = field['most_fuzzed_fields']
        
        # Protocol metrics
        metrics.protocol_distribution = protocol['protocol_distribution']
        metrics.port_coverage = protocol['port_coverage']
        metrics.payload_sizes = protocol['payload_sizes']
        metrics.unique_targets = protocol['unique_targets']
        
        # Timing metrics
        metrics.campaign_duration = timing['campaign_duration']
        metrics.packets_per_second = timing['packets_per_second']
        
        # Mutator metrics
        metrics.mutator_usage = mutator['mutator_usage']
        metrics.total_mutations_applied = mutator['total_mutations_applied']
        metrics.most_used_mutators = mutator['most_used_mutators']
        
        # Enhanced field metadata
        metrics.detailed_field_metadata = mutator.get('detailed_field_metadata', {})
    
    def _detect_vulnerabilities(
        self, 
        history_entries: List[Any], 
        protocol_analysis: Dict[str, ProtocolAnalysis]
    ) -> List[VulnerabilityFinding]:
        """
        Detect anomalies and interesting patterns from campaign data.
        
        Note: These are not true vulnerability detections - we can't determine
        actual vulnerabilities without target system access. Instead, we identify
        patterns that warrant further investigation.
        """
        findings = []
        
        # Pattern 1: Serialization failures (interesting for investigation)
        for entry in history_entries:
            if entry.serialization_failed and entry.serialization_error:
                finding = VulnerabilityFinding(
                    finding_id=f"ANOMALY_{entry.iteration}",
                    severity="info",  # Realistic severity - we don't know impact
                    category="serialization_failure",
                    description=f"Packet serialization failed during fuzzing - may indicate format sensitivity",
                    error_message=entry.serialization_error,
                    reproduction_data=entry.packet_bytes
                )
                findings.append(finding)
        
        # Pattern 2: Application crashes (potential DoS or worse)
        for entry in history_entries:
            if entry.crashed and entry.crash_info:
                # This is the only case where we can be more confident about severity
                finding = VulnerabilityFinding(
                    finding_id=f"CRASH_{entry.iteration}",
                    severity="high",  # Crashes are serious but we don't know exploitability
                    category="application_crash",
                    description=f"Fuzzing caused application crash - investigate for DoS or memory corruption",
                    affected_packet=entry.packet,
                    error_message=str(entry.crash_info.exception) if entry.crash_info.exception else None
                )
                findings.append(finding)
        
        # Pattern 3: Unusual response patterns (if responses are captured)
        response_patterns = self._analyze_response_patterns(history_entries)
        findings.extend(response_patterns)
        
        return findings
    
    def _analyze_response_patterns(self, history_entries: List[Any]) -> List[VulnerabilityFinding]:
        """Analyze response patterns for anomalies (if responses were captured)"""
        findings = []
        
        # Look for response size anomalies
        response_sizes = [entry.response_size for entry in history_entries 
                         if entry.response_size is not None]
        
        if len(response_sizes) > 10:  # Need enough data for statistics
            avg_size = sum(response_sizes) / len(response_sizes)
            
            for entry in history_entries:
                if (entry.response_size is not None and 
                    entry.response_size > avg_size * 3):  # 3x larger than average
                    finding = VulnerabilityFinding(
                        finding_id=f"RESPONSE_ANOMALY_{entry.iteration}",
                        severity="info",
                        category="response_anomaly",
                        description=f"Unusually large response ({entry.response_size} bytes vs avg {avg_size:.0f}) - may indicate verbose error disclosure",
                        affected_packet=entry.packet
                    )
                    findings.append(finding)
        
        return findings
    
    def _generate_output_path(self, campaign: Any, level: ReportLevel, extension: str) -> str:
        """Generate standardized output path"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        campaign_name = getattr(campaign, "name", campaign.__class__.__name__).lower().replace(" ", "_")
        return f"artifacts/reports/{campaign_name}_{level.value}_{timestamp}.{extension}"


# ============================================================================
# Protocol Intelligence Analyzer
# ============================================================================

class ProtocolIntelligenceAnalyzer:
    """Generic packet analysis using Scapy's protocol knowledge"""
    
    def __init__(self):
        # Remove protocol-specific handlers - make it generic
        pass
    
    def analyze_campaign(self, history_entries: List[Any]) -> Dict[str, ProtocolAnalysis]:
        """Perform generic analysis on campaign data grouped by protocol"""
        protocol_groups = defaultdict(list)
        
        # Group entries by protocol (or 'unknown' if not available)
        for entry in history_entries:
            protocol = entry.protocol or 'unknown'
            protocol_groups[protocol].append(entry)
        
        # Analyze each protocol group generically
        analysis_results = {}
        for protocol, entries in protocol_groups.items():
            analysis_results[protocol] = self._analyze_protocol_group(protocol, entries)
        
        return analysis_results
    
    def _analyze_protocol_group(self, protocol: str, entries: List[Any]) -> ProtocolAnalysis:
        """Generic analysis of a group of entries - no protocol assumptions"""
        # TODO: Consider adding configurable analysis depth and timeout controls for large datasets
        unique_ports = set()
        payload_variations = 0
        error_patterns = Counter()
        scapy_layers = set()
        
        for entry in entries:
            # Collect port information if available
            if entry.target_port:
                unique_ports.add(entry.target_port)
            
            # Categorize errors generically
            if entry.serialization_error:
                error_type = self._categorize_error_generic(entry.serialization_error)
                error_patterns[error_type] += 1
            
            # Extract Scapy layer information if packet bytes available
            if entry.packet_bytes:
                try:
                    packet = Packet(entry.packet_bytes)
                    scapy_layers.update(layer.__name__ for layer in packet.layers())
                except Exception:
                    # If packet reconstruction fails, just note it
                    scapy_layers.add('reconstruction_failed')
        
        # Count unique payloads based on hashes
        payload_hashes = set(entry.payload_hash for entry in entries if entry.payload_hash)
        payload_variations = len(payload_hashes)
        
        return ProtocolAnalysis(
            protocol_name=protocol,
            packet_count=len(entries),
            unique_ports=unique_ports,
            payload_variations=payload_variations,
            error_patterns=dict(error_patterns),
            potential_vulnerabilities=[],  # Populated by main vulnerability detection
            scapy_layer_coverage=scapy_layers
        )
    
    def _categorize_error_generic(self, error_message: str) -> str:
        """Categorize error messages generically without assuming vulnerability types"""
        error_lower = error_message.lower()
        
        # Focus on what we can actually observe, not what we assume
        if any(keyword in error_lower for keyword in ['serialize', 'marshal', 'encode']):
            return "serialization_error"
        elif any(keyword in error_lower for keyword in ['length', 'size', 'bounds', 'range']):
            return "size_constraint_error"
        elif any(keyword in error_lower for keyword in ['format', 'parse', 'decode', 'invalid']):
            return "format_error"
        elif any(keyword in error_lower for keyword in ['timeout', 'connect', 'network']):
            return "network_error"
        elif any(keyword in error_lower for keyword in ['permission', 'access', 'auth']):
            return "access_error"
        else:
            return "other_error"


# ============================================================================
# Report Generators
# ============================================================================

class ExecutiveSummaryGenerator(ReportGeneratorInterface):
    """Generate executive-level summary reports"""
    
    def generate(
        self, 
        campaign: Any, 
        metrics: ReportMetrics, 
        protocol_analysis: Dict[str, ProtocolAnalysis], 
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """Generate executive summary content"""
        critical_findings = [f for f in findings if f.severity == "critical"]
        high_findings = [f for f in findings if f.severity == "high"]
        
        return {
            "report_type": "executive_summary",
            "campaign_name": getattr(campaign, "name", campaign.__class__.__name__),
            "target": getattr(campaign, "target", "unknown"),
            "timestamp": datetime.now().isoformat(),
            
            "executive_summary": {
                "total_packets_tested": metrics.total_packets,
                "success_rate": f"{(metrics.successful_packets/metrics.total_packets*100):.1f}%" if metrics.total_packets > 0 else "0%",
                "critical_vulnerabilities": len(critical_findings),
                "high_vulnerabilities": len(high_findings),
                "protocols_tested": len(protocol_analysis),
                "campaign_duration": str(metrics.campaign_duration) if metrics.campaign_duration else "unknown",
                "packets_with_fuzzed_fields": metrics.packets_with_fuzzed_fields,
                "packets_without_fuzzed_fields": metrics.packets_without_fuzzed_fields,
                "unique_fields_fuzzed": len(metrics.fuzzed_field_distribution),
                "most_fuzzed_fields": metrics.most_fuzzed_fields[:5]  # Top 5 for executive summary
            },
            
            "risk_assessment": {
                "overall_risk": self._calculate_overall_risk(findings),
                "priority_findings": [asdict(f) for f in critical_findings + high_findings],
                "recommended_actions": self._generate_recommendations(findings, protocol_analysis)
            },
            
            "testing_coverage": {
                "protocols": list(protocol_analysis.keys()),
                "ports_tested": list(metrics.port_coverage),
                "packets_per_second": metrics.packets_per_second,
                "fuzzed_field_distribution": dict(metrics.fuzzed_field_distribution),
                "field_fuzzing_rate": f"{(metrics.packets_with_fuzzed_fields/metrics.total_packets*100):.1f}%" if metrics.total_packets > 0 else "0%",
                "detailed_field_metadata": metrics.detailed_field_metadata,  # Already in dict format
                "mutator_usage": dict(metrics.mutator_usage),
                "total_mutations_applied": metrics.total_mutations_applied,
                "most_used_mutators": metrics.most_used_mutators
            }
        }
    
    def _calculate_overall_risk(self, findings: List[VulnerabilityFinding]) -> str:
        """Calculate overall risk level based on observable impact only"""
        if any(f.category == "application_crash" for f in findings):
            return "MEDIUM"  # Crashes are concerning but we don't know exploitability
        elif any(f.severity == "high" for f in findings):
            return "LOW-MEDIUM"
        elif len(findings) > 10:
            return "LOW"  # Many anomalies worth investigating
        else:
            return "MINIMAL"
    
    def _generate_recommendations(
        self, 
        findings: List[VulnerabilityFinding], 
        protocol_analysis: Dict[str, ProtocolAnalysis]
    ) -> List[str]:
        """Generate realistic, actionable recommendations based on observations"""
        recommendations = []
        
        crash_findings = [f for f in findings if f.category == "application_crash"]
        if crash_findings:
            recommendations.append(f"Investigate {len(crash_findings)} application crashes for potential DoS vulnerabilities")
        
        serialization_failures = [f for f in findings if f.category == "serialization_failure"]
        if serialization_failures:
            recommendations.append(f"Review {len(serialization_failures)} packet serialization failures - may indicate input validation issues")
        
        response_anomalies = [f for f in findings if f.category == "response_anomaly"]
        if response_anomalies:
            recommendations.append(f"Analyze {len(response_anomalies)} unusual response patterns - may indicate error disclosure")
        
        if len(protocol_analysis) > 1:
            recommendations.append("Multi-protocol exposure detected - ensure consistent security controls across all protocols")
        
        # Generic recommendations based on what we can actually observe
        total_protocols = len(protocol_analysis)
        total_packets = sum(analysis.packet_count for analysis in protocol_analysis.values())
        
        if total_packets > 1000:
            recommendations.append("Large-scale testing completed - perform manual review of high-frequency error patterns")
        
        if total_protocols == 1:
            protocol_name = list(protocol_analysis.keys())[0]
            recommendations.append(f"Single protocol ({protocol_name}) testing - consider expanding to related protocols")
        
        return recommendations


class TechnicalAnalysisGenerator(ReportGeneratorInterface):
    """Generate technical analysis reports"""
    
    def generate(
        self, 
        campaign: Any, 
        metrics: ReportMetrics, 
        protocol_analysis: Dict[str, ProtocolAnalysis], 
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """Generate technical analysis content"""
        return {
            "report_type": "technical_analysis",
            "campaign_details": {
                "name": getattr(campaign, "name", campaign.__class__.__name__),
                "target": getattr(campaign, "target", "unknown"),
                "iterations": getattr(campaign, "iterations", 0),
                "verbose": getattr(campaign, "verbose", False)
            },
            
            "performance_metrics": asdict(metrics),
            
            "protocol_analysis": {
                proto: asdict(analysis) for proto, analysis in protocol_analysis.items()
            },
            
            "vulnerability_analysis": {
                "total_findings": len(findings),
                "by_severity": dict(Counter(f.severity for f in findings)),
                "by_category": dict(Counter(f.category for f in findings)),
                "detailed_findings": [asdict(f) for f in findings]
            },
            
            "coverage_analysis": {
                "protocol_coverage": dict(metrics.protocol_distribution),
                "port_coverage": list(metrics.port_coverage),
                "payload_size_distribution": {
                    "min": min(metrics.payload_sizes) if metrics.payload_sizes else 0,
                    "max": max(metrics.payload_sizes) if metrics.payload_sizes else 0,
                    "avg": sum(metrics.payload_sizes) / len(metrics.payload_sizes) if metrics.payload_sizes else 0
                }
            }
        }


class ForensicsGenerator(ReportGeneratorInterface):
    """Generate deep forensics reports"""
    
    def generate(
        self, 
        campaign: Any, 
        metrics: ReportMetrics, 
        protocol_analysis: Dict[str, ProtocolAnalysis], 
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """Generate forensics-level content"""
        return {
            "report_type": "forensics_analysis",
            "detailed_metrics": asdict(metrics),
            "protocol_forensics": {
                proto: self._generate_protocol_forensics(analysis) 
                for proto, analysis in protocol_analysis.items()
            },
            "packet_analysis": self._generate_packet_analysis(findings),
            "reproduction_data": self._generate_reproduction_data(findings)
        }
    
    def _generate_protocol_forensics(self, analysis: ProtocolAnalysis) -> Dict[str, Any]:
        """Generate protocol-specific forensics data"""
        return {
            "scapy_layer_analysis": list(analysis.scapy_layer_coverage),
            "error_pattern_analysis": analysis.error_patterns,
            "port_distribution": list(analysis.unique_ports),
            "payload_variation_count": analysis.payload_variations
        }
    
    def _generate_packet_analysis(self, findings: List[VulnerabilityFinding]) -> List[Dict[str, Any]]:
        """Generate detailed packet analysis for findings"""
        packet_analysis = []
        
        for finding in findings:
            analysis = {
                "finding_id": finding.finding_id,
                "packet_available": finding.affected_packet is not None,
                "reproduction_data_available": finding.reproduction_data is not None
            }
            
            if finding.affected_packet:
                try:
                    analysis["packet_layers"] = [layer.__name__ for layer in finding.affected_packet.layers()]
                    analysis["packet_summary"] = finding.affected_packet.summary()
                except Exception as e:
                    analysis["packet_analysis_error"] = str(e)
            
            packet_analysis.append(analysis)
        
        return packet_analysis
    
    def _generate_reproduction_data(self, findings: List[VulnerabilityFinding]) -> Dict[str, str]:
        """Generate base64-encoded reproduction data"""
        # TODO: Consider adding compression for large reproduction datasets and size limits
        reproduction_data = {}
        
        for finding in findings:
            if finding.reproduction_data:
                reproduction_data[finding.finding_id] = base64.b64encode(finding.reproduction_data).decode()
        
        return reproduction_data


class AdvancedPerformanceGenerator(ReportGeneratorInterface):
    """Generate advanced fuzzing performance and mutator analysis reports"""
    
    def generate(
        self, 
        campaign: Any, 
        metrics: ReportMetrics, 
        protocol_analysis: Dict[str, ProtocolAnalysis], 
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """Generate advanced performance analysis content"""
        
        # Extract mutator data from campaign context
        mutator_data = None
        if hasattr(campaign, 'get_mutator_data'):
            mutator_data = campaign.get_mutator_data()
        elif hasattr(campaign, 'context') and hasattr(campaign.context, 'mutator_data'):
            mutator_data = campaign.context.mutator_data
        
        performance_data = {
            "report_type": "advanced_performance",
            "campaign_name": getattr(campaign, "name", campaign.__class__.__name__),
            "target": getattr(campaign, "target", "unknown"),
            "timestamp": datetime.now().isoformat(),
            
            # Core performance metrics
            "performance_summary": self._generate_performance_summary(metrics, mutator_data),
            
            # Detailed mutator analysis
            "mutator_analysis": self._generate_mutator_analysis(mutator_data),
            
            # Field performance metrics
            "field_performance": self._generate_field_performance(mutator_data),
            
            # Weight scaling analysis
            "weight_analysis": self._generate_weight_analysis(mutator_data),
            
            # Campaign configuration analysis
            "campaign_config": self._generate_campaign_config(mutator_data),
            
            # Mutation effectiveness metrics
            "mutation_effectiveness": self._generate_mutation_effectiveness(mutator_data, metrics),
            
            # Dictionary utilization
            "dictionary_analysis": self._generate_dictionary_analysis(mutator_data),
            
            # Performance recommendations
            "recommendations": self._generate_performance_recommendations(mutator_data, metrics)
        }
        
        return performance_data
    
    def _generate_performance_summary(self, metrics: ReportMetrics, mutator_data: Any) -> Dict[str, Any]:
        """Generate high-level performance summary"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            summary = {
                "total_fields": mutator_data.total_fields,
                "fuzzable_fields": mutator_data.fuzzable_field_count,
                "fuzzable_percentage": round((mutator_data.fuzzable_field_count / mutator_data.total_fields * 100), 2) if mutator_data.total_fields > 0 else 0,
                "packets_processed": mutator_data.total_packets,
                "average_fields_per_packet": round(mutator_data.total_fields / mutator_data.total_packets, 2) if mutator_data.total_packets > 0 else 0,
                "mutation_attempts": sum(getattr(field, 'mutation_count', 0) for field in mutator_data.get_all_fuzzable_fields()),
                "successful_mutations": sum(getattr(field, 'successful_mutations', 0) for field in mutator_data.get_all_fuzzable_fields()),
                "failed_mutations": sum(getattr(field, 'failed_mutations', 0) for field in mutator_data.get_all_fuzzable_fields())
            }
            
            if summary["mutation_attempts"] > 0:
                summary["mutation_success_rate"] = round((summary["successful_mutations"] / summary["mutation_attempts"] * 100), 2)
            else:
                summary["mutation_success_rate"] = 0
                
            return summary
        except Exception as e:
            return {"error": f"Failed to generate performance summary: {str(e)}"}
    
    def _generate_mutator_analysis(self, mutator_data: Any) -> Dict[str, Any]:
        """Analyze mutator usage and effectiveness"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            # Get mutator usage summary
            mutator_usage = mutator_data.get_mutator_usage_summary()
            
            analysis = {
                "mutator_usage_distribution": mutator_usage,
                "most_used_mutator": max(mutator_usage.items(), key=lambda x: x[1]) if mutator_usage else None,
                "total_mutator_invocations": sum(mutator_usage.values()),
                "unique_mutators_used": len(mutator_usage)
            }
            
            # Analyze mutator preferences
            field_mutator_prefs = {}
            for field in mutator_data.get_all_fuzzable_fields():
                if hasattr(field, 'mutator_preferences') and field.mutator_preferences:
                    for mutator in field.mutator_preferences:
                        if mutator not in field_mutator_prefs:
                            field_mutator_prefs[mutator] = 0
                        field_mutator_prefs[mutator] += 1
            
            analysis["mutator_preferences_distribution"] = field_mutator_prefs
            
            return analysis
        except Exception as e:
            return {"error": f"Failed to generate mutator analysis: {str(e)}"}
    
    def _generate_field_performance(self, mutator_data: Any) -> Dict[str, Any]:
        """Analyze individual field performance metrics"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            field_stats = []
            
            for field in mutator_data.get_all_fuzzable_fields():
                field_info = {
                    "field_key": field.field_key,
                    "field_name": field.field_name,
                    "field_kind": field.field_kind,
                    "layer_name": field.layer_name,
                    "base_weight": getattr(field, 'base_weight', field.fuzz_weight),
                    "final_weight": field.fuzz_weight,
                    "scaling_factor": getattr(field, 'final_scaling_factor', 1.0),
                    "mutation_count": getattr(field, 'mutation_count', 0),
                    "successful_mutations": getattr(field, 'successful_mutations', 0),
                    "failed_mutations": getattr(field, 'failed_mutations', 0),
                    "dictionary_count": len(field.dictionary_paths),
                    "default_values_count": len(field.default_values),
                    "mutator_preferences": field.mutator_preferences,
                    "config_source": field.config_source,
                    "last_mutated": getattr(field, 'last_mutated', None)
                }
                
                # Calculate success rate
                if field_info["mutation_count"] > 0:
                    field_info["success_rate"] = round((field_info["successful_mutations"] / field_info["mutation_count"] * 100), 2)
                else:
                    field_info["success_rate"] = 0
                
                field_stats.append(field_info)
            
            # Sort by mutation count (most active fields first)
            field_stats.sort(key=lambda x: x["mutation_count"], reverse=True)
            
            return {
                "total_fields_analyzed": len(field_stats),
                "field_details": field_stats,
                "top_performing_fields": field_stats[:10],  # Top 10 by mutation count
                "field_config_sources": Counter([f["config_source"] for f in field_stats]),
                "weight_scaling_impact": self._analyze_weight_scaling_impact(field_stats)
            }
        except Exception as e:
            return {"error": f"Failed to generate field performance: {str(e)}"}
    
    def _generate_weight_analysis(self, mutator_data: Any) -> Dict[str, Any]:
        """Analyze weight scaling and its impact"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            weight_data = []
            
            for field in mutator_data.get_all_fuzzable_fields():
                weight_info = {
                    "field_key": field.field_key,
                    "base_weight": getattr(field, 'base_weight', field.fuzz_weight),
                    "layer_scaled_weight": getattr(field, 'layer_scaled_weight', field.fuzz_weight),
                    "campaign_scaled_weight": getattr(field, 'campaign_scaled_weight', field.fuzz_weight),
                    "final_weight": field.fuzz_weight,
                    "layer_scaling_factor": getattr(field, 'layer_scaling_factor', 1.0),
                    "campaign_scaling_factor": getattr(field, 'campaign_scaling_factor', 1.0),
                    "final_scaling_factor": getattr(field, 'final_scaling_factor', 1.0)
                }
                weight_data.append(weight_info)
            
            # Calculate scaling statistics
            layer_scalings = [w["layer_scaling_factor"] for w in weight_data if w["layer_scaling_factor"] != 1.0]
            campaign_scalings = [w["campaign_scaling_factor"] for w in weight_data if w["campaign_scaling_factor"] != 1.0]
            
            analysis = {
                "total_fields_with_scaling": len([w for w in weight_data if w["final_scaling_factor"] != 1.0]),
                "average_layer_scaling": round(sum(layer_scalings) / len(layer_scalings), 3) if layer_scalings else 1.0,
                "average_campaign_scaling": round(sum(campaign_scalings) / len(campaign_scalings), 3) if campaign_scalings else 1.0,
                "weight_distribution": {
                    "min_final_weight": min([w["final_weight"] for w in weight_data]) if weight_data else 0,
                    "max_final_weight": max([w["final_weight"] for w in weight_data]) if weight_data else 0,
                    "avg_final_weight": round(sum([w["final_weight"] for w in weight_data]) / len(weight_data), 3) if weight_data else 0
                },
                "scaling_effectiveness": self._calculate_scaling_effectiveness(weight_data)
            }
            
            return analysis
        except Exception as e:
            return {"error": f"Failed to generate weight analysis: {str(e)}"}
    
    def _generate_campaign_config(self, mutator_data: Any) -> Dict[str, Any]:
        """Analyze campaign-level configuration"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            config = mutator_data.fuzz_config
            
            campaign_info = {
                "fuzz_mode": config.mode.value if hasattr(config.mode, 'value') else str(config.mode),
                "max_mutations": config.max_mutations,
                "use_dictionaries": config.use_dictionaries,
                "global_fuzz_weight": config.fuzz_weight,
                "fuzz_weight_scale": config.fuzz_weight_scale,
                "layer_weight_scaling_enabled": config.enable_layer_weight_scaling,
                "layer_weight_scaling_factor": config.layer_weight_scaling,
                "mutator_preferences": config.mutator_preference,
                "single_packet_mode": getattr(mutator_data, 'is_single_packet', None),
                "total_iterations": config.iterations
            }
            
            # Additional configuration analysis
            if config.iterations:
                campaign_info["estimated_total_mutations"] = config.iterations * len(mutator_data.get_all_fuzzable_fields())
            else:
                campaign_info["estimated_total_mutations"] = "Unknown (iterations not set)"
            campaign_info["dictionary_usage_enabled"] = config.use_dictionaries
            
            return campaign_info
        except Exception as e:
            return {"error": f"Failed to generate campaign config: {str(e)}"}
    
    def _generate_mutation_effectiveness(self, mutator_data: Any, metrics: ReportMetrics) -> Dict[str, Any]:
        """Analyze mutation effectiveness and coverage"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            effectiveness = {
                "field_coverage": {
                    "total_available_fields": mutator_data.total_fields,
                    "fuzzable_fields": mutator_data.fuzzable_field_count,
                    "actually_fuzzed_fields": len([f for f in mutator_data.get_all_fuzzable_fields() if getattr(f, 'mutation_count', 0) > 0]),
                    "coverage_percentage": 0
                },
                "mutation_distribution": {},
                "effectiveness_score": 0
            }
            
            # Calculate coverage percentage
            if mutator_data.fuzzable_field_count > 0:
                effectiveness["field_coverage"]["coverage_percentage"] = round(
                    (effectiveness["field_coverage"]["actually_fuzzed_fields"] / mutator_data.fuzzable_field_count * 100), 2
                )
            
            # Analyze mutation distribution by field type
            field_type_mutations = {}
            for field in mutator_data.get_all_fuzzable_fields():
                field_kind = field.field_kind
                mutation_count = getattr(field, 'mutation_count', 0)
                
                if field_kind not in field_type_mutations:
                    field_type_mutations[field_kind] = {"count": 0, "mutations": 0}
                
                field_type_mutations[field_kind]["count"] += 1
                field_type_mutations[field_kind]["mutations"] += mutation_count
            
            effectiveness["mutation_distribution"] = field_type_mutations
            
            # Calculate basic effectiveness score (0-100)
            coverage_score = effectiveness["field_coverage"]["coverage_percentage"]
            mutation_score = min(100, sum([info["mutations"] for info in field_type_mutations.values()]) / 10)  # Scale mutations
            effectiveness["effectiveness_score"] = round((coverage_score + mutation_score) / 2, 2)
            
            return effectiveness
        except Exception as e:
            return {"error": f"Failed to generate mutation effectiveness: {str(e)}"}
    
    def _generate_dictionary_analysis(self, mutator_data: Any) -> Dict[str, Any]:
        """Analyze dictionary usage and effectiveness"""
        if not mutator_data:
            return {"error": "No mutator data available"}
        
        try:
            dictionary_stats = {
                "fields_with_dictionaries": 0,
                "total_dictionary_files": set(),
                "dictionary_distribution": {},
                "most_common_dictionaries": []
            }
            
            for field in mutator_data.get_all_fuzzable_fields():
                if field.dictionary_paths:
                    dictionary_stats["fields_with_dictionaries"] += 1
                    dictionary_stats["total_dictionary_files"].update(field.dictionary_paths)
                    
                    for dict_path in field.dictionary_paths:
                        if dict_path not in dictionary_stats["dictionary_distribution"]:
                            dictionary_stats["dictionary_distribution"][dict_path] = 0
                        dictionary_stats["dictionary_distribution"][dict_path] += 1
            
            # Convert set to count
            dictionary_stats["total_dictionary_files"] = len(dictionary_stats["total_dictionary_files"])
            
            # Get most common dictionaries
            if dictionary_stats["dictionary_distribution"]:
                dictionary_stats["most_common_dictionaries"] = sorted(
                    dictionary_stats["dictionary_distribution"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            
            return dictionary_stats
        except Exception as e:
            return {"error": f"Failed to generate dictionary analysis: {str(e)}"}
    
    def _generate_performance_recommendations(self, mutator_data: Any, metrics: ReportMetrics) -> List[str]:
        """Generate performance improvement recommendations"""
        recommendations = []
        
        if not mutator_data:
            recommendations.append("No mutator data available for analysis")
            return recommendations
        
        try:
            # Analyze field coverage
            fuzzable_fields = mutator_data.get_all_fuzzable_fields()
            actually_fuzzed = [f for f in fuzzable_fields if getattr(f, 'mutation_count', 0) > 0]
            
            if len(actually_fuzzed) < len(fuzzable_fields) * 0.5:
                recommendations.append("Consider increasing iteration count or fuzz weights - only {:.1f}% of fuzzable fields were actually mutated".format(
                    len(actually_fuzzed) / len(fuzzable_fields) * 100 if fuzzable_fields else 0
                ))
            
            # Analyze mutation failures
            total_mutations = sum([getattr(f, 'mutation_count', 0) for f in fuzzable_fields])
            failed_mutations = sum([getattr(f, 'failed_mutations', 0) for f in fuzzable_fields])
            
            if total_mutations > 0 and failed_mutations / total_mutations > 0.2:
                recommendations.append("High mutation failure rate ({:.1f}%) - check field constraints and mutator compatibility".format(
                    failed_mutations / total_mutations * 100
                ))
            
            # Analyze weight scaling impact
            fields_with_scaling = [f for f in fuzzable_fields if getattr(f, 'final_scaling_factor', 1.0) != 1.0]
            if len(fields_with_scaling) > 0:
                avg_scaling = sum([getattr(f, 'final_scaling_factor', 1.0) for f in fields_with_scaling]) / len(fields_with_scaling)
                if avg_scaling < 0.5:
                    recommendations.append("Weight scaling is significantly reducing fuzz weights (avg factor: {:.2f}) - consider adjusting scaling parameters".format(avg_scaling))
            
            # Analyze dictionary usage
            fields_with_dicts = [f for f in fuzzable_fields if f.dictionary_paths]
            if len(fields_with_dicts) < len(fuzzable_fields) * 0.3:
                recommendations.append("Low dictionary utilization ({:.1f}%) - consider adding more field-specific dictionaries".format(
                    len(fields_with_dicts) / len(fuzzable_fields) * 100 if fuzzable_fields else 0
                ))
            
            # Check mutator preferences diversity
            mutator_usage = mutator_data.get_mutator_usage_summary()
            if len(mutator_usage) == 1:
                recommendations.append("Only one mutator type used - consider enabling multiple mutators for better coverage")
            
            if not recommendations:
                recommendations.append("Campaign performance looks good - no specific recommendations at this time")
                
        except Exception as e:
            recommendations.append(f"Failed to generate recommendations: {str(e)}")
        
        return recommendations
    
    def _analyze_weight_scaling_impact(self, field_stats: List[Dict]) -> Dict[str, Any]:
        """Analyze the impact of weight scaling on field selection"""
        impact_analysis = {
            "fields_affected_by_scaling": 0,
            "average_scaling_reduction": 0,
            "highly_scaled_fields": []
        }
        
        scaling_factors = []
        for field in field_stats:
            scaling_factor = field.get("scaling_factor", 1.0)
            if scaling_factor != 1.0:
                impact_analysis["fields_affected_by_scaling"] += 1
                scaling_factors.append(scaling_factor)
                
                if scaling_factor < 0.3:  # Highly scaled down
                    impact_analysis["highly_scaled_fields"].append({
                        "field_key": field["field_key"],
                        "scaling_factor": scaling_factor,
                        "original_weight": field["base_weight"],
                        "final_weight": field["final_weight"]
                    })
        
        if scaling_factors:
            impact_analysis["average_scaling_reduction"] = round(1 - (sum(scaling_factors) / len(scaling_factors)), 3)
        
        return impact_analysis
    
    def _calculate_scaling_effectiveness(self, weight_data: List[Dict]) -> Dict[str, Any]:
        """Calculate how effective the weight scaling is"""
        effectiveness = {
            "scaling_distribution": {
                "no_scaling": 0,
                "light_scaling": 0,  # 0.7-1.0
                "moderate_scaling": 0,  # 0.3-0.7
                "heavy_scaling": 0   # 0.0-0.3
            },
            "scaling_impact_score": 0
        }
        
        for weight in weight_data:
            factor = weight["final_scaling_factor"]
            if factor >= 1.0:
                effectiveness["scaling_distribution"]["no_scaling"] += 1
            elif factor >= 0.7:
                effectiveness["scaling_distribution"]["light_scaling"] += 1
            elif factor >= 0.3:
                effectiveness["scaling_distribution"]["moderate_scaling"] += 1
            else:
                effectiveness["scaling_distribution"]["heavy_scaling"] += 1
        
        # Calculate impact score (0-100, higher means more diverse scaling)
        total_fields = len(weight_data)
        if total_fields > 0:
            diversity_score = (
                effectiveness["scaling_distribution"]["light_scaling"] * 0.3 +
                effectiveness["scaling_distribution"]["moderate_scaling"] * 0.7 +
                effectiveness["scaling_distribution"]["heavy_scaling"] * 1.0
            ) / total_fields * 100
            effectiveness["scaling_impact_score"] = round(diversity_score, 2)
        
        return effectiveness


# ============================================================================
# Export Formatters
# ============================================================================

class HTMLExporter(ExporterInterface):
    """Export reports as HTML"""
    
    def get_file_extension(self) -> str:
        """Return the file extension for HTML files"""
        return "html"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        """Export content as HTML report"""
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        html_content = self._generate_html(content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report exported to {output_path}")
        return output_path
    
    def _generate_html(self, content: Dict[str, Any]) -> str:
        """Generate HTML content"""
        report_type = content.get("report_type", "unknown")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PacketFuzz {report_type.replace('_', ' ').title()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .metric {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .finding {{ background: #ffe6e6; padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; }}
        .success {{ background: #e6ffe6; border-left: 4px solid #27ae60; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PacketFuzz Report: {report_type.replace('_', ' ').title()}</h1>
        <p><strong>Generated:</strong> {content.get('timestamp', 'unknown')}</p>
"""
        
        if report_type == "executive_summary":
            html += self._generate_executive_html(content)
        elif report_type == "technical_analysis":
            html += self._generate_technical_html(content)
        elif report_type == "forensics_analysis":
            html += self._generate_forensics_html(content)
        
        html += """
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_executive_html(self, content: Dict[str, Any]) -> str:
        """Generate executive summary HTML"""
        summary = content.get("executive_summary", {})
        risk = content.get("risk_assessment", {})
        
        return f"""
        <h2>Executive Summary</h2>
        <div class="metric">
            <h3>Campaign Overview</h3>
            <p><strong>Target:</strong> {content.get('target', 'unknown')}</p>
            <p><strong>Packets Tested:</strong> {summary.get('total_packets_tested', 0)}</p>
            <p><strong>Success Rate:</strong> {summary.get('success_rate', '0%')}</p>
            <p><strong>Duration:</strong> {summary.get('campaign_duration', 'unknown')}</p>
        </div>
        
        <div class="metric">
            <h3>Field Fuzzing Analysis</h3>
            <p><strong>Packets with Fuzzed Fields:</strong> {summary.get('packets_with_fuzzed_fields', 0)}</p>
            <p><strong>Packets without Fuzzed Fields:</strong> {summary.get('packets_without_fuzzed_fields', 0)}</p>
            <p><strong>Unique Fields Fuzzed:</strong> {summary.get('unique_fields_fuzzed', 0)}</p>
            <p><strong>Most Fuzzed Fields:</strong> {', '.join(summary.get('most_fuzzed_fields', []))}</p>
        </div>
        
        <div class="finding">
            <h3>Risk Assessment: {risk.get('overall_risk', 'UNKNOWN')}</h3>
            <p><strong>Critical Vulnerabilities:</strong> {summary.get('critical_vulnerabilities', 0)}</p>
            <p><strong>High Vulnerabilities:</strong> {summary.get('high_vulnerabilities', 0)}</p>
        </div>
        
        <h3>Recommended Actions</h3>
        <ul>
        """ + "".join(f"<li>{rec}</li>" for rec in risk.get('recommended_actions', [])) + """
        </ul>
        """
    
    def _generate_technical_html(self, content: Dict[str, Any]) -> str:
        """Generate technical analysis HTML"""
        metrics = content.get("performance_metrics", {})
        protocols = content.get("protocol_analysis", {})
        
        return f"""
        <h2>Technical Analysis</h2>
        <div class="metric">
            <h3>Performance Metrics</h3>
            <p><strong>Total Packets:</strong> {metrics.get('total_packets', 0)}</p>
            <p><strong>Successful:</strong> {metrics.get('successful_packets', 0)}</p>
            <p><strong>Failed:</strong> {metrics.get('failed_packets', 0)}</p>
            <p><strong>Packets/Second:</strong> {metrics.get('packets_per_second', 0):.2f}</p>
        </div>
        
        <h3>Protocol Analysis</h3>
        <table>
            <tr><th>Protocol</th><th>Packets</th><th>Unique Ports</th><th>Errors</th></tr>
        """ + "".join(f"""
            <tr>
                <td>{proto}</td>
                <td>{data.get('packet_count', 0)}</td>
                <td>{len(data.get('unique_ports', []))}</td>
                <td>{sum(data.get('error_patterns', {}).values())}</td>
            </tr>
        """ for proto, data in protocols.items()) + """
        </table>
        """
    
    def _generate_forensics_html(self, content: Dict[str, Any]) -> str:
        """Generate forensics analysis HTML"""
        return """
        <h2>Forensics Analysis</h2>
        <p>Detailed forensics data available in JSON export format.</p>
        """


class JSONExporter(ExporterInterface):
    """Export reports as JSON"""
    
    def get_file_extension(self) -> str:
        """Return the file extension for JSON files"""
        return "json"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        """Export content as JSON"""
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Convert sets to lists for JSON serialization
        serializable_content = self._make_serializable(content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_content, f, indent=2, default=str)
        
        logger.info(f"JSON report exported to {output_path}")
        return output_path
    
    def _make_serializable(self, obj: Any) -> Any:
        """Convert object to JSON-serializable format"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, (datetime, timedelta)):
            return str(obj)
        else:
            return obj


class CSVExporter(ExporterInterface):
    """Export reports as CSV"""
    
    def get_file_extension(self) -> str:
        """Return the file extension for CSV files"""
        return "csv"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        """Export content as CSV"""
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        csv_content = self._generate_csv(content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(csv_content)
        
        logger.info(f"CSV report exported to {output_path}")
        return output_path
    
    def _generate_csv(self, content: Dict[str, Any]) -> str:
        """Generate CSV content"""
        lines = ["Field,Value"]
        
        def flatten_dict(d: Dict[str, Any], prefix: str = "") -> None:
            for k, v in d.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    flatten_dict(v, key)
                elif isinstance(v, (list, set)):
                    lines.append(f"{key},{len(v)} items")
                else:
                    lines.append(f"{key},{v}")
        
        flatten_dict(content)
        return "\n".join(lines)


class SARIFExporter(ExporterInterface):
    """Export reports as SARIF format for CI/CD integration"""
    
    def get_file_extension(self) -> str:
        """Return the file extension for SARIF files"""
        return "sarif"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        """Export content as SARIF"""
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        sarif_content = self._generate_sarif(content)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_content, f, indent=2)
        
        logger.info(f"SARIF report exported to {output_path}")
        return output_path
    
    def _generate_sarif(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SARIF format content"""
        findings = content.get("vulnerability_analysis", {}).get("detailed_findings", [])
        
        results = []
        for finding in findings:
            result = {
                "ruleId": finding.get("category", "unknown"),
                "level": self._map_severity_to_sarif(finding.get("severity", "info")),
                "message": {"text": finding.get("description", "No description")},
                "locations": [{
                    "logicalLocations": [{
                        "name": finding.get("finding_id", "unknown"),
                        "kind": "packet"
                    }]
                }]
            }
            results.append(result)
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PacketFuzz",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/NathanMulbrook/PacketFuzz"
                    }
                },
                "results": results
            }]
        }
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map observation severity to SARIF levels (realistic mapping)"""
        mapping = {
            "high": "warning",      # High observable impact, but not confirmed exploitable
            "medium": "note",       # Medium observable impact  
            "low": "note",          # Low observable impact
            "info": "note"          # Informational observation
        }
        return mapping.get(severity, "note")


class MarkdownExporter(ExporterInterface):
    """Export reports as Markdown for documentation"""
    
    def get_file_extension(self) -> str:
        return "md"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        markdown_content = self._generate_markdown(content)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report exported to {output_path}")
        return output_path
    
    def _generate_markdown(self, content: Dict[str, Any]) -> str:
        """Generate Markdown content"""
        report_type = content.get("report_type", "unknown")
        
        md = f"# PacketFuzz {report_type.replace('_', ' ').title()}\n\n"
        md += f"**Generated:** {content.get('timestamp', 'unknown')}\n\n"
        
        # Handle advanced performance reports
        if report_type == "advanced_performance":
            md += self._generate_advanced_performance_markdown(content)
        
        # Handle executive summary reports  
        elif "executive_summary" in content:
            summary = content["executive_summary"]
            md += "## Executive Summary\n\n"
            md += f"- **Target:** {content.get('target', 'unknown')}\n"
            md += f"- **Packets Tested:** {summary.get('total_packets_tested', 0)}\n"
            md += f"- **Success Rate:** {summary.get('success_rate', '0%')}\n"
            md += f"- **Packets with Fuzzed Fields:** {summary.get('packets_with_fuzzed_fields', 0)}\n"
            md += f"- **Packets without Fuzzed Fields:** {summary.get('packets_without_fuzzed_fields', 0)}\n"
            md += f"- **Unique Fields Fuzzed:** {summary.get('unique_fields_fuzzed', 0)}\n"
            if summary.get('most_fuzzed_fields'):
                md += f"- **Most Fuzzed Fields:** {', '.join(summary.get('most_fuzzed_fields', []))}\n"
            md += "\n"
            # Add fuzzed field distribution table if available
            fuzzed_field_dist = content.get('testing_coverage', {}).get('fuzzed_field_distribution', {})
            if fuzzed_field_dist:
                md += "### Fuzzed Field Distribution\n\n"
                md += "| Field Name | Times Fuzzed |\n|---|---|\n"
                for field, count in sorted(fuzzed_field_dist.items(), key=lambda x: x[1], reverse=True):
                    md += f"| {field} | {count} |\n"
                md += "\n"
        
        if "performance_metrics" in content:
            metrics = content["performance_metrics"]
            md += "## Performance Metrics\n\n"
            md += f"- **Total Packets:** {metrics.get('total_packets', 0)}\n"
            md += f"- **Successful:** {metrics.get('successful_packets', 0)}\n"
            md += f"- **Failed:** {metrics.get('failed_packets', 0)}\n\n"
        
        return md
    
    def _generate_advanced_performance_markdown(self, content: Dict[str, Any]) -> str:
        """Generate markdown content for advanced performance reports"""
        md = ""
        
        # Campaign info
        md += f"**Campaign:** {content.get('campaign_name', 'Unknown')}\n"
        md += f"**Target:** {content.get('target', 'Unknown')}\n\n"
        
        # Performance Summary
        if "performance_summary" in content:
            summary = content["performance_summary"]
            md += "## Performance Summary\n\n"
            md += f"- **Total Fields:** {summary.get('total_fields', 0)}\n"
            md += f"- **Fuzzable Fields:** {summary.get('fuzzable_fields', 0)}\n"
            md += f"- **Fuzzable Percentage:** {summary.get('fuzzable_percentage', 0)}%\n"
            md += f"- **Packets Processed:** {summary.get('packets_processed', 0)}\n"
            md += f"- **Average Fields per Packet:** {summary.get('average_fields_per_packet', 0)}\n"
            md += f"- **Mutation Attempts:** {summary.get('mutation_attempts', 0)}\n"
            md += f"- **Successful Mutations:** {summary.get('successful_mutations', 0)}\n"
            md += f"- **Failed Mutations:** {summary.get('failed_mutations', 0)}\n"
            md += f"- **Mutation Success Rate:** {summary.get('mutation_success_rate', 0)}%\n\n"
        
        # Mutator Analysis
        if "mutator_analysis" in content:
            analysis = content["mutator_analysis"]
            md += "## Mutator Analysis\n\n"
            if analysis.get("mutator_usage_distribution"):
                md += "### Mutator Usage Distribution\n\n"
                md += "| Mutator | Usage Count |\n|---|---|\n"
                for mutator, count in sorted(analysis["mutator_usage_distribution"].items(), key=lambda x: x[1], reverse=True):
                    md += f"| {mutator} | {count} |\n"
                md += "\n"
            
            md += f"- **Total Mutator Invocations:** {analysis.get('total_mutator_invocations', 0)}\n"
            md += f"- **Unique Mutators Used:** {analysis.get('unique_mutators_used', 0)}\n"
            if analysis.get('most_used_mutator'):
                mutator, count = analysis['most_used_mutator']
                md += f"- **Most Used Mutator:** {mutator} ({count} times)\n"
            md += "\n"
        
        # Weight Analysis
        if "weight_analysis" in content:
            weights = content["weight_analysis"]
            md += "## Weight Analysis\n\n"
            md += f"- **Fields with Scaling:** {weights.get('total_fields_with_scaling', 0)}\n"
            md += f"- **Average Layer Scaling:** {weights.get('average_layer_scaling', 1.0)}\n"
            md += f"- **Average Campaign Scaling:** {weights.get('average_campaign_scaling', 1.0)}\n"
            
            if "weight_distribution" in weights:
                dist = weights["weight_distribution"]
                md += f"- **Weight Range:** {dist.get('min_final_weight', 0)} - {dist.get('max_final_weight', 0)}\n"
                md += f"- **Average Final Weight:** {dist.get('avg_final_weight', 0)}\n"
            md += "\n"
        
        # Campaign Configuration
        if "campaign_config" in content:
            config = content["campaign_config"]
            md += "## Campaign Configuration\n\n"
            md += f"- **Fuzz Mode:** {config.get('fuzz_mode', 'unknown')}\n"
            md += f"- **Max Mutations:** {config.get('max_mutations', 0)}\n"
            md += f"- **Use Dictionaries:** {config.get('use_dictionaries', False)}\n"
            md += f"- **Global Fuzz Weight:** {config.get('global_fuzz_weight', 0)}\n"
            md += f"- **Fuzz Weight Scale:** {config.get('fuzz_weight_scale', 1.0)}\n"
            md += f"- **Layer Weight Scaling Enabled:** {config.get('layer_weight_scaling_enabled', False)}\n"
            md += f"- **Single Packet Mode:** {config.get('single_packet_mode', False)}\n"
            md += f"- **Total Iterations:** {config.get('total_iterations', 0)}\n"
            md += f"- **Estimated Total Mutations:** {config.get('estimated_total_mutations', 0)}\n"
            if config.get('mutator_preferences'):
                md += f"- **Mutator Preferences:** {', '.join(config['mutator_preferences'])}\n"
            md += "\n"
        
        # Mutation Effectiveness
        if "mutation_effectiveness" in content:
            effectiveness = content["mutation_effectiveness"]
            md += "## Mutation Effectiveness\n\n"
            
            if "field_coverage" in effectiveness:
                coverage = effectiveness["field_coverage"]
                md += f"- **Field Coverage:** {coverage.get('coverage_percentage', 0)}%\n"
                md += f"- **Actually Fuzzed Fields:** {coverage.get('actually_fuzzed_fields', 0)} / {coverage.get('fuzzable_fields', 0)}\n"
            
            md += f"- **Effectiveness Score:** {effectiveness.get('effectiveness_score', 0)}/100\n"
            
            if "mutation_distribution" in effectiveness:
                md += "\n### Mutation Distribution by Field Type\n\n"
                md += "| Field Type | Field Count | Total Mutations |\n|---|---|---|\n"
                for field_type, info in effectiveness["mutation_distribution"].items():
                    md += f"| {field_type} | {info.get('count', 0)} | {info.get('mutations', 0)} |\n"
            md += "\n"
        
        # Dictionary Analysis
        if "dictionary_analysis" in content:
            dicts = content["dictionary_analysis"]
            md += "## Dictionary Analysis\n\n"
            md += f"- **Fields with Dictionaries:** {dicts.get('fields_with_dictionaries', 0)}\n"
            md += f"- **Total Dictionary Files:** {dicts.get('total_dictionary_files', 0)}\n"
            
            if dicts.get('most_common_dictionaries'):
                md += "\n### Most Common Dictionaries\n\n"
                md += "| Dictionary | Usage Count |\n|---|---|\n"
                for dict_path, count in dicts['most_common_dictionaries'][:10]:
                    md += f"| {dict_path} | {count} |\n"
            md += "\n"
        
        # Performance Recommendations
        if "recommendations" in content:
            recommendations = content["recommendations"]
            md += "## Performance Recommendations\n\n"
            for i, recommendation in enumerate(recommendations, 1):
                md += f"{i}. {recommendation}\n"
            md += "\n"
        
        # Top Performing Fields (from field_performance)
        if "field_performance" in content:
            field_perf = content["field_performance"]
            if field_perf.get("top_performing_fields"):
                md += "## Top Performing Fields (by mutation count)\n\n"
                md += "| Field | Layer | Mutations | Success Rate | Final Weight |\n|---|---|---|---|---|\n"
                for field in field_perf["top_performing_fields"][:10]:
                    md += f"| {field.get('field_name', 'unknown')} | {field.get('layer_name', 'unknown')} | {field.get('mutation_count', 0)} | {field.get('success_rate', 0)}% | {field.get('final_weight', 0)} |\n"
                md += "\n"
        
        return md


class YAMLExporter(ExporterInterface):
    """Export reports as YAML for configuration management"""
    
    def get_file_extension(self) -> str:
        return "yaml"
    
    def export(self, content: Dict[str, Any], output_path: str) -> str:
        # Create directory if path includes one
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        yaml_content = self._generate_yaml(content)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        logger.info(f"YAML report exported to {output_path}")
        return output_path
    
    def _generate_yaml(self, content: Dict[str, Any]) -> str:
        """Generate YAML content"""
        # Simple YAML generation without external dependencies
        yaml_lines = []
        
        def dict_to_yaml(d: Dict[str, Any], indent: int = 0) -> None:
            for k, v in d.items():
                if isinstance(v, dict):
                    yaml_lines.append("  " * indent + f"{k}:")
                    dict_to_yaml(v, indent + 1)
                elif isinstance(v, list):
                    yaml_lines.append("  " * indent + f"{k}:")
                    for item in v:
                        if isinstance(item, dict):
                            yaml_lines.append("  " * (indent + 1) + "-")
                            dict_to_yaml(item, indent + 2)
                        else:
                            yaml_lines.append("  " * (indent + 1) + f"- {item}")
                else:
                    yaml_lines.append("  " * indent + f"{k}: {v}")
        
        dict_to_yaml(content)
        return "\n".join(yaml_lines)


# ============================================================================
# Enhanced Reporting API
# ============================================================================

def register_custom_exporters(engine: ReportingEngine) -> None:
    """Register additional export formats with the reporting engine"""
    engine.register_exporter('markdown', MarkdownExporter())
    engine.register_exporter('yaml', YAMLExporter())
    logger.info("Registered custom exporters: markdown, yaml")


def generate_campaign_report(
    campaign: Any,
    campaign_context: Any,
    level: str = "technical",
    output_format: str = "html",
    output_path: Optional[str] = None
) -> str:
    """
    Generate enhanced campaign report using new reporting engine.
    
    Args:
        campaign: FuzzingCampaign instance
        campaign_context: CampaignContext with fuzz_history
        level: Report level ("executive", "technical", "forensics")
        output_format: Export format ("html", "json", "csv", "sarif", "markdown", "yaml")
        output_path: Optional output path (auto-generated if not provided)
    
    Returns:
        Path to generated report file
    """
    engine = ReportingEngine()
    register_custom_exporters(engine)  # Register markdown and yaml exporters
    
    # Get history entries from campaign context
    history_entries = getattr(campaign_context, 'fuzz_history', [])
    
    # Map string level to enum
    level_map = {
        "executive": ReportLevel.EXECUTIVE,
        "technical": ReportLevel.TECHNICAL,
        "forensics": ReportLevel.FORENSICS,
        "advanced": ReportLevel.ADVANCED
    }
    report_level = level_map.get(level, ReportLevel.TECHNICAL)
    
    return engine.generate_report(
        campaign=campaign,
        campaign_context=campaign_context,
        history_entries=history_entries,
        level=report_level,
        output_format=output_format,
        output_path=output_path
    )


def generate_campaign_reports(
    campaign: Any,
    campaign_context: Any,
    level: str = "executive",
    output_formats: Optional[List[str]] = None,
    output_directory: Optional[str] = None
) -> List[str]:
    """
    Generate campaign reports in multiple formats.
    
    Args:
        campaign: FuzzingCampaign instance
        campaign_context: CampaignContext with fuzz_history
        level: Report level ("executive", "technical", "forensics")
        output_formats: List of export formats to generate (defaults to campaign.report_formats or ["json"])
        output_directory: Directory for reports (defaults to "artifacts/reports")
        
    Returns:
        List of paths to generated report files
    """
    # Determine output formats
    if output_formats is None:
        output_formats = getattr(campaign, 'report_formats', ['json'])
    
    # Debug logging
    logger.info(f"Campaign: {getattr(campaign, 'name', 'Unknown')}")
    logger.info(f"Requested output formats: {output_formats}")
    
    # Ensure we have a valid list
    if not output_formats:
        output_formats = ['json']
    
    # Handle 'all' format
    if 'all' in output_formats:
        engine = ReportingEngine()
        register_custom_exporters(engine)  # Add markdown and yaml
        output_formats = list(engine.get_available_formats())
    
    # Ensure output directory exists
    if output_directory is None:
        output_directory = "artifacts/reports"
    os.makedirs(output_directory, exist_ok=True)
    
    generated_reports = []
    
    for format_name in output_formats:
        try:
            # Generate auto-path for this format
            campaign_name = getattr(campaign, 'name', 'campaign') or 'campaign'
            safe_name = str(campaign_name).lower().replace(' ', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{output_directory}/{safe_name}_{level}_{timestamp}.{format_name}"
            
            # Generate the report
            report_path = generate_campaign_report(
                campaign=campaign,
                campaign_context=campaign_context,
                level=level,
                output_format=format_name,
                output_path=output_path
            )
            
            generated_reports.append(report_path)
            logger.info(f"Generated {format_name.upper()} report: {report_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate {format_name} report: {e}")
            # Continue with other formats
    
    return generated_reports


def generate_vulnerability_report(
    campaign: Any,
    campaign_context: Any,
    output_format: str = "sarif"
) -> str:
    """
    Generate vulnerability-focused report for CI/CD integration.
    
    Args:
        campaign: FuzzingCampaign instance
        campaign_context: CampaignContext with fuzz_history
        output_format: Export format ("sarif", "json")
    
    Returns:
        Path to generated vulnerability report
    """
    return generate_campaign_report(
        campaign=campaign,
        campaign_context=campaign_context,
        level="technical",
        output_format=output_format
    )


def monitor_campaign_progress(
    campaign: Any,
    campaign_context: Any,
    update_interval: int = 10
) -> Optional[threading.Thread]:
    """
    Real-time campaign monitoring with periodic report updates.
    
    Args:
        campaign: FuzzingCampaign instance
        campaign_context: CampaignContext to monitor
        update_interval: Update interval in seconds
        
    Returns:
        Monitor thread or None if monitoring failed to start
    """
    def monitor_loop():
        while getattr(campaign, 'running', False):
            try:
                generate_campaign_report(
                    campaign=campaign,
                    campaign_context=campaign_context,
                    level="technical",
                    output_format="json",
                    output_path="artifacts/reports/live_report.json"
                )
                time.sleep(update_interval)
            except Exception as e:
                logger.error(f"Monitor update failed: {e}")
                break
    
    try:
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return None


# ============================================================================
# Utility Functions
# ============================================================================

def analyze_protocol_coverage(history_entries: List[Any]) -> Dict[str, Any]:
    """Analyze protocol coverage from history entries"""
    analyzer = ProtocolIntelligenceAnalyzer()
    return analyzer.analyze_campaign(history_entries)


def export_findings_to_sarif(findings: List[VulnerabilityFinding], output_path: str) -> str:
    """Export vulnerability findings to SARIF format"""
    exporter = SARIFExporter()
    content = {"vulnerability_analysis": {"detailed_findings": [asdict(f) for f in findings]}}
    return exporter.export(content, output_path)


def calculate_campaign_metrics(history_entries: List[Any], campaign_context: Any) -> ReportMetrics:
    """
    Calculate comprehensive campaign metrics
    
    Args:
        history_entries: List of FuzzHistoryEntry objects
        campaign_context: CampaignContext containing mutator data
        
    Returns:
        ReportMetrics with comprehensive analytics
    """
    engine = ReportingEngine()
    return engine._calculate_metrics(history_entries, campaign_context)


def write_crash_report(
    packet: Any,
    file_path: str,
    metadata: Optional[Dict[str, Any]] = None,
    campaign_context: Optional[Any] = None,
    crash_info: Optional[Any] = None,
    pcap_path: Optional[str] = None
) -> None:
    """
    Write a crash report for a single packet.
    
    This is a focused function for crash reporting that replaces the legacy 
    write_packet_report for crash scenarios.
    """
    
    with open(file_path, 'w') as f:
        f.write("# PacketFuzz Crash Report\n\n")
        
        # Write metadata section
        if metadata:
            f.write("## Crash Metadata\n")
            for k, v in metadata.items():
                f.write(f"- **{k}**: {v}\n")
            f.write("\n")
        
        # Write campaign context if provided
        if campaign_context:
            f.write("## Campaign Context\n")
            f.write(f"- Campaign: {getattr(campaign_context, 'campaign', 'Unknown')}\n")
            stats = getattr(campaign_context, 'stats', {})
            if stats:
                f.write(f"- Packets sent: {stats.get('packets_sent', 0)}\n")
                f.write(f"- Failures: {stats.get('serialize_failure_count', 0)}\n")
            f.write("\n")
        
        # Write crash info if provided
        if crash_info:
            f.write("## Crash Details\n")
            for k in ["crash_id", "crash_source", "exception", "timestamp"]:
                v = getattr(crash_info, k, None)
                if v is not None:
                    f.write(f"- **{k}**: {v}\n")
            f.write("\n")
        
        # Write packet information
        if packet:
            try:
                f.write("## Packet Summary\n")
                f.write(f"```\n{packet.summary()}\n```\n\n")
            except Exception as e:
                f.write(f"Packet summary failed: {e}\n\n")
            
            try:
                f.write("## Packet Details\n")
                f.write("```\n")
                f.write(packet.show(dump=True) or "")
                f.write("\n```\n\n")
            except Exception as e:
                f.write(f"Packet details failed: {e}\n\n")
            
            try:
                f.write("## Raw Packet Data (Base64)\n")
                f.write("```\n")
                f.write(base64.b64encode(bytes(packet)).decode())
                f.write("\n```\n")
            except Exception as e:
                f.write(f"Packet serialization failed: {e}\n")
        
        # Write PCAP info if provided
        if pcap_path:
            f.write(f"\n## Associated PCAP\n")
            f.write(f"PCAP file: {pcap_path}\n")


def write_debug_packet_log(
    packets: Union[Any, List[Any]],
    file_path: str,
    title: str = "Debug Packet Log"
) -> None:
    """
    Write a simple debug log for packets.
    
    This replaces write_packet_report for debug logging scenarios.
    """
    
    if not isinstance(packets, (list, tuple)):
        packets = [packets]
    
    try:
        with open(file_path, 'w') as f:
            f.write(f"# {title}\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total packets: {len(packets)}\n\n")
            
            for i, packet in enumerate(packets):
                f.write(f"## Packet {i+1}\n")
                try:
                    f.write(f"Summary: {packet.summary()}\n")
                    f.write(f"Raw bytes (base64): {base64.b64encode(bytes(packet)).decode()}\n")
                except Exception as e:
                    f.write(f"Error processing packet: {e}\n")
                f.write("\n")
                    
    except Exception as e:
        logger.error(f"Failed to write debug packet log: {e}")


def write_fuzz_history_dump(
    fuzz_history: List[Any],
    file_path: str,
    verbose_level: int = 2,
    title: str = "Fuzz History Dump"
) -> None:
    """
    Write a detailed dump of the fuzz history for very verbose runs.
    
    This function provides comprehensive packet logging for debugging and analysis,
    including full packet details, timestamps, mutations, and responses.
    
    Args:
        fuzz_history: List of FuzzHistoryEntry objects from campaign context
        file_path: Path to write the history dump
        verbose_level: Level of verbosity (1=basic, 2=detailed, 3+=full dump)
        title: Title for the log file
    """
    if not fuzz_history:
        logger.debug("No fuzz history to dump")
        return
        
    try:
        with open(file_path, 'w') as f:
            f.write(f"# {title}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total entries: {len(fuzz_history)}\n")
            f.write(f"# Verbose level: {verbose_level}\n\n")
            
            for i, entry in enumerate(fuzz_history):
                f.write(f"{'='*80}\n")
                f.write(f"ENTRY {i+1:04d}\n")
                f.write(f"{'='*80}\n\n")
                
                # Basic entry info
                f.write(f"Iteration: {getattr(entry, 'iteration', 'N/A')}\n")
                f.write(f"Timestamp Sent: {getattr(entry, 'timestamp_sent', 'N/A')}\n")
                f.write(f"Timestamp Received: {getattr(entry, 'timestamp_received', 'N/A')}\n")
                f.write(f"Crashed: {getattr(entry, 'crashed', False)}\n")
                
                # Network details
                if hasattr(entry, 'target_host') and entry.target_host:
                    f.write(f"Target Host: {entry.target_host}\n")
                if hasattr(entry, 'target_port') and entry.target_port:
                    f.write(f"Target Port: {entry.target_port}\n")
                if hasattr(entry, 'protocol') and entry.protocol:
                    f.write(f"Protocol: {entry.protocol}\n")
                
                # Mutation details
                if hasattr(entry, 'mutation_applied') and entry.mutation_applied:
                    f.write(f"Mutation Applied: {entry.mutation_applied}\n")
                if hasattr(entry, 'payload_size') and entry.payload_size:
                    f.write(f"Payload Size: {entry.payload_size}\n")
                if hasattr(entry, 'payload_hash') and entry.payload_hash:
                    f.write(f"Payload Hash: {entry.payload_hash}\n")
                
                # Fuzzed fields information
                if hasattr(entry, 'fuzzed_fields') and entry.fuzzed_fields:
                    # If we have detailed mutator info, show field -> mutator mapping
                    if hasattr(entry, 'field_mutators') and entry.field_mutators:
                        # Create formatted list showing field and its mutator
                        field_mutator_pairs = []
                        for field in entry.fuzzed_fields:
                            mutator = entry.field_mutators.get(field, 'unknown')
                            field_mutator_pairs.append(f"{field}({mutator})")
                        f.write(f"Fuzzed Fields: {', '.join(field_mutator_pairs)}\n")
                    else:
                        # Fallback to simple field list if no mutator info
                        f.write(f"Fuzzed Fields: {', '.join(entry.fuzzed_fields)}\n")
                elif hasattr(entry, 'fuzzed_fields'):  # Empty list case
                    f.write(f"Fuzzed Fields: None\n")
                
                f.write("\n")
                
                # Packet details (if verbose enough)
                if verbose_level >= 2 and hasattr(entry, 'packet') and entry.packet:
                    try:
                        f.write("PACKET DETAILS:\n")
                        f.write("-" * 40 + "\n")
                        # Use Scapy's show method for detailed packet info
                        packet_summary = entry.packet.show(dump=True) if hasattr(entry.packet, 'show') else str(entry.packet)
                        f.write(packet_summary or "No packet details available\n")
                        f.write("\n")
                        
                        # Raw packet bytes (for highest verbosity)
                        if verbose_level >= 3:
                            try:
                                packet_bytes = bytes(entry.packet)
                                f.write(f"Raw Packet (base64): {base64.b64encode(packet_bytes).decode()}\n")
                                f.write(f"Raw Packet (hex): {packet_bytes.hex()}\n\n")
                            except Exception as e:
                                f.write(f"Could not serialize packet to bytes: {e}\n\n")
                                
                    except Exception as e:
                        f.write(f"Error displaying packet details: {e}\n\n")
                
                # Response details (if available)
                if verbose_level >= 2 and hasattr(entry, 'response') and entry.response:
                    try:
                        f.write("RESPONSE DETAILS:\n")
                        f.write("-" * 40 + "\n")
                        if hasattr(entry.response, 'show'):
                            response_summary = entry.response.show(dump=True)
                            f.write(response_summary or "No response details available\n")
                        else:
                            f.write(str(entry.response) + "\n")
                        f.write("\n")
                        
                        if hasattr(entry, 'response_size') and entry.response_size:
                            f.write(f"Response Size: {entry.response_size}\n")
                            
                    except Exception as e:
                        f.write(f"Error displaying response details: {e}\n\n")
                
                # Crash details (if crashed)
                if getattr(entry, 'crashed', False) and hasattr(entry, 'crash_info') and entry.crash_info:
                    f.write("CRASH INFORMATION:\n")
                    f.write("-" * 40 + "\n")
                    try:
                        crash_info = entry.crash_info
                        if hasattr(crash_info, 'timestamp'):
                            f.write(f"Crash Timestamp: {crash_info.timestamp}\n")
                        if hasattr(crash_info, 'exception_type'):
                            f.write(f"Exception Type: {crash_info.exception_type}\n")
                        if hasattr(crash_info, 'message'):
                            f.write(f"Exception Message: {crash_info.message}\n")
                        if hasattr(crash_info, 'traceback'):
                            f.write(f"Traceback:\n{crash_info.traceback}\n")
                    except Exception as e:
                        f.write(f"Error displaying crash info: {e}\n")
                    f.write("\n")
                
                # Serialization issues (if any)
                if hasattr(entry, 'serialization_failed') and entry.serialization_failed:
                    f.write("SERIALIZATION ISSUES:\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Serialization Failed: {entry.serialization_failed}\n")
                    if hasattr(entry, 'serialization_error') and entry.serialization_error:
                        f.write(f"Serialization Error: {entry.serialization_error}\n")
                    f.write("\n")
                
                f.write("\n")
            
            # Summary at the end
            f.write(f"{'='*80}\n")
            f.write("SUMMARY\n")
            f.write(f"{'='*80}\n\n")
            
            crashed_count = sum(1 for entry in fuzz_history if getattr(entry, 'crashed', False))
            serialization_failed_count = sum(1 for entry in fuzz_history if getattr(entry, 'serialization_failed', False))
            
            f.write(f"Total Entries: {len(fuzz_history)}\n")
            f.write(f"Crashed Entries: {crashed_count}\n")
            f.write(f"Serialization Failures: {serialization_failed_count}\n")
            
            # Protocol breakdown
            protocols = {}
            for entry in fuzz_history:
                protocol = getattr(entry, 'protocol', 'Unknown')
                protocols[protocol] = protocols.get(protocol, 0) + 1
            
            if protocols:
                f.write("\nProtocol Breakdown:\n")
                for protocol, count in sorted(protocols.items()):
                    f.write(f"  {protocol}: {count}\n")
            
            f.write(f"\n# End of fuzz history dump\n")
            
        logger.info(f"Fuzz history dump written to: {file_path}")
        
    except Exception as e:
        logger.error(f"Failed to write fuzz history dump to {file_path}: {e}")
