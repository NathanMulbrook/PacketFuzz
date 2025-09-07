"""
Mutator Manager Data Storage System

Provides comprehensive data storage and management for the life of a mutator manager.
This module implements a self-contained data system that processes
packet metadata, field configurations, and mutation state management.

Design Principles:
- Self-contained: All data provided at instantiation
- No external dependencies: Doesn't access campaign contexts or global state
- Direct storage: Simple field metadata with complete configuration data
- Layer collision detection: Auto-indexed field keys for duplicate layer names
"""

# Standard library imports
from __future__ import annotations
import copy
import fnmatch
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Tuple, Tuple
from pathlib import Path

# Third-party imports
from scapy.packet import Packet, NoPayload
from scapy.fields import Field

# Constants for defaults
DEFAULT_MAX_MUTATIONS = 1000
DEFAULT_FUZZ_WEIGHT = 0.7

# Configure logging
logger = logging.getLogger(__name__)


class FuzzMode(Enum):
    """Fuzzing mode selection"""
    PACKET_LEVEL = "packet"
    FIELD_LEVEL = "field"
    BOTH = "both"




@dataclass
class FuzzConfig:
    """Campaign-level fuzzing configuration.
    
    This represents the campaign settings - clear defaults with Optional only where None is meaningful.
    """
    # Core fuzzing parameters - always have defaults
    max_mutations: int = DEFAULT_MAX_MUTATIONS
    use_dictionaries: bool = True
    fuzz_weight: float = DEFAULT_FUZZ_WEIGHT
    fuzz_weight_scale: float = 1.0  # Global scaling factor
    enable_layer_weight_scaling: bool = True
    
    # Optional parameters - None has meaning
    mode: Optional[FuzzMode] = None  # None = auto-detect
    layer_weight_scaling: Optional[float] = None  # None = use default constant
    mutator_preference: Optional[Union[List[str], Dict[str, float]]] = None
    global_dict_config_path: Optional[str] = None
    rng: Optional[random.Random] = None
    
    # Required for processing - not Optional
    packets: Union[Packet, List[Packet]] = None  # Must be provided
    iterations: Optional[int] = None  # None = use max_mutations
    
    # Campaign-level field overrides
    advanced_field_mapping_overrides: Optional[List[Dict[str, Any]]] = None

# =========================
# Field and Packet Metadata Classes  
# =========================

@dataclass
class FieldMetadata:
    """
    Complete metadata for a single field with resolved configuration.
    """
    # Core identification
    field_key: str  # Format: "Layer[index].field" (e.g., "TCP[0].dport", "TCP[1].sport")
    layer_name: str  # Original layer class name (e.g., "TCP")
    field_name: str  # Field name (e.g., "dport")
    layer_index: int  # Index for collision detection (0 for first occurrence)
    packet_index: int  # Index of packet in list 
    
    # Field properties
    field_type: str  # Scapy field type (e.g., "ShortField", "StrField")
    field_kind: str  # Categorized type (e.g., "numeric", "string", "enum")
    current_value: Any  # Current field value

    # Resolved fuzzing configuration
    fuzz_weight: float = DEFAULT_FUZZ_WEIGHT
    dictionary_paths: List[str] = field(default_factory=list)
    default_values: List[Any] = field(default_factory=list)
    mutator_preferences: List[str] = field(default_factory=list)  # Legacy
    mutator_weights: Dict[str, float] = field(default_factory=dict)
    
    # Advanced fuzzing configuration
    scapy_fuzz_weight: float = 0.1  # Weight for Scapy's fuzz() method
    dictionary_only_weight: float = 0.2  # Weight for dictionary-only mutations
    use_scapy_fuzz: bool = True  # Whether to use Scapy's built-in fuzz
    
    # Field constraints (extracted from Scapy field descriptors)
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    enum_values: Optional[Dict[str, Any]] = None
    is_signed: bool = False
    
    # Processing metadata
    is_fuzzable: bool = True
    exclusion_reason: Optional[str] = None
    config_source: str = "default"
    
    # Statistics tracking
    mutation_count: int = 0
    successful_mutations: int = 0
    failed_mutations: int = 0
    last_mutated: Optional[datetime] = None


@dataclass  
class PacketData:
    """
    Metadata for a single packet including all its fields and layer information.
    Handles layer collision detection and field organization.
    """
    # Core packet information
    packet_index: int  # Position in packet list (0-based)
    packet: Packet  # Reference to original packet
    packet_summary: str  # Human-readable packet description
    
    # Layer organization
    layer_names: List[str] = field(default_factory=list)  # All layer names in order
    layer_collision_map: Dict[str, int] = field(default_factory=dict)  # Layer name -> count
    layer_indexes: Dict[str, List[int]] = field(default_factory=dict)  # Layer name -> [indexes]
    
    # Field collections
    fields: Dict[str, FieldMetadata] = field(default_factory=dict)  # field_key -> metadata
    fuzzable_fields: List[str] = field(default_factory=list)  # Keys of fuzzable fields
    excluded_fields: List[str] = field(default_factory=list)  # Keys of excluded fields
    
    # Processing statistics
    total_fields: int = 0
    successful_extractions: int = 0
    failed_extractions: int = 0
    
    def get_field_by_layer(self, layer_name: str) -> List[FieldMetadata]:
        """Get all fields belonging to a specific layer type."""
        return [field for field in self.fields.values() 
                if field.layer_name == layer_name]
    
    def has_layer_collisions(self) -> bool:
        """Check if packet has any layer name collisions (multiple instances)."""
        return any(count > 1 for count in self.layer_collision_map.values())


@dataclass
class ConfigurationSources:
    """
    Container for the 3 configuration sources: FuzzField → Campaign → Defaults.
    Clean separation with no embedded config complexity.
    """
    # Default configuration (lowest priority)
    default_weight: float = DEFAULT_FUZZ_WEIGHT
    default_dictionaries: List[str] = field(default_factory=list)
    default_values: List[Any] = field(default_factory=list)
    default_mutator_weights: Dict[str, float] = field(default_factory=dict)
    
    # Campaign configuration (middle priority)
    campaign_weight: Optional[float] = None
    campaign_dictionaries: List[str] = field(default_factory=list)
    campaign_values: List[Any] = field(default_factory=list)
    campaign_mutator_weights: Dict[str, float] = field(default_factory=dict)
    
    # FuzzField configuration (highest priority)
    fuzzfield_weight: Optional[float] = None
    fuzzfield_dictionaries: List[str] = field(default_factory=list)
    fuzzfield_values: List[Any] = field(default_factory=list)
    fuzzfield_mutator_weights: Dict[str, float] = field(default_factory=dict)
    fuzzfield_scapy_weight: Optional[float] = None
    fuzzfield_dictionary_only_weight: Optional[float] = None
    fuzzfield_use_scapy_fuzz: Optional[bool] = None
    fuzzfield_object: Optional[Any] = None  # For materialization
    
    # Collection metadata
    collection_errors: List[str] = field(default_factory=list)


class MutatorManagerData:

    def get_field_dictionaries(self, field_metadata: 'FieldMetadata') -> list:
        """
        Public API to get all dictionary paths for a field.
        Args:
            field_metadata: The FieldMetadata object for the field.
        Returns:
            List of dictionary paths (strings) for the field.
        """
        return getattr(field_metadata, 'dictionary_paths', [])
    """
    Self-contained data tracking system for MutatorManager operations.
    
    This class implements a clean separation between data processing (preprocessing)
    and data access (runtime queries). All data is processed up-front during
    initialization to enable fast, efficient access during fuzzing operations.
    
    Architecture:
    - Data Processing: Heavy computation during preprocessing phase
    - Data Access: Fast, indexed queries during fuzzing operations
    - Configuration Resolution: Multi-priority system with FuzzField override support
    
    Processing Flow:
    1. Packet Analysis: Deep copy packets, discover layers and fields
    2. Metadata Creation: Extract field properties and constraints  
    3. Configuration Resolution: Three-phase priority-based system
       - Phase 1: Collection (pure data gathering from all sources)
       - Phase 2: Calculation (priority-based resolution logic)
       - Phase 3: Application (config application + side effects)
    4. Index Building: Create cross-packet indexes for efficient access
    
    Configuration Priority (highest to lowest):
    1. FuzzField configuration (inline packet field config)
    2. Embedded packet field configuration (field_fuzz())
    3. Campaign-level advanced field mapping (via dictionary manager)
    4. Global dictionary manager defaults
    5. FuzzConfig fallback defaults
    
    Design: All required data is provided at instantiation - no external dependencies.
    """
    
    def __init__(self, fuzz_config: FuzzConfig):
        """
        Initialize tracking system with complete fuzzing configuration.
        
        Args:
            fuzz_config: Enhanced FuzzConfig containing packets, iterations, and configuration
            
        Raises:
            ValueError: If required configuration is missing or invalid
        """
        self.fuzz_config = fuzz_config
        self.creation_time = datetime.now()

        self.iterations = fuzz_config.iterations or fuzz_config.max_mutations

        # Extract packet information - validate packets are provided
        if fuzz_config.packets is None:
            raise ValueError("FuzzConfig.packets must be provided")
        self.original_packets = fuzz_config.packets
        self.fuzzed_packets: List[Packet] = []  # Will be populated during preprocessing
        
        # Initialize data structures
        self.packet_data: List[PacketData] = []
        self.global_field_index: Dict[str, List[Tuple[int, str]]] = {}  # field_key -> [(packet_idx, field_key)]
        
        # Mutator tracking per iteration
        self.iteration_mutator_usage: Dict[int, Dict[str, str]] = {}  # iteration -> {field_key: mutator_name}
        
        # Processing statistics - will be updated during preprocessing
        self.total_packets = 0  # Will be set during preprocessing
        self.total_fields = 0
        self.fuzzable_field_count = 0
        self.excluded_field_count = 0
        self.layer_collision_count = 0
        
        # Processing state
        self.is_preprocessed = False
        self.preprocessing_errors: List[str] = []

    def __str__(self) -> str:
        """String representation of MutatorManagerData."""
        return (f"MutatorManagerData({self.total_packets} packets, "
                f"{self.total_fields} fields, {self.fuzzable_field_count} fuzzable)")
    
    def __repr__(self) -> str:
        """Detailed representation of MutatorManagerData."""
        return (f"MutatorManagerData(packets={self.total_packets}, "
                f"fields={self.total_fields}, fuzzable={self.fuzzable_field_count}, "
                f"iterations={self.iterations}, preprocessed={self.is_preprocessed})")
    
# ===========================
# PROCESSING & COMPUTATION
# ===========================
# Complex preprocessing, configuration resolution, and field analysis logic

    def preprocess_packets(self, dictionary_manager: Optional[Any] = None) -> None:
        """
        Analyze all packets and build complete field metadata.
        
        This method discovers all fields, resolves configurations, handles layer collisions,
        processes FuzzFields, creates deep copies, and builds the complete tracking data structure.
        
        Args:
            dictionary_manager: DictionaryManager instance for configuration resolution
        """
        if self.is_preprocessed:
            logger.warning("Packets already preprocessed - skipping")
            return
        
        logger.info(f"Preprocessing {self.total_packets} packets...")
        start_time = datetime.now()
    
        # CRITICAL: Create deep copies with iteration logic during preprocessing
        # USER REQUIREMENT: ITERATION MULTIPLICATION MUST HAPPEN DURING PREPROCESSING
        # DO NOT MOVE THIS LOGIC TO A LATER PHASE!
        self._create_packet_copies()
        
        # Process each packet to extract field metadata
        for packet_idx, packet in enumerate(self.fuzzed_packets):
            packet_data = self._process_single_packet(packet, packet_idx, dictionary_manager)
            self.packet_data.append(packet_data)
            
            # Update global statistics
            self.total_fields += packet_data.total_fields
            self.fuzzable_field_count += len(packet_data.fuzzable_fields)
            self.excluded_field_count += len(packet_data.excluded_fields)
            
            if packet_data.has_layer_collisions():
                self.layer_collision_count += 1
        
        # Build global field index for cross-packet analysis
        self._build_global_field_index()
        
        # Finalize preprocessing
        self._finalize_preprocessing()
        

    
    def _finalize_preprocessing(self) -> None:
        """
        Complete preprocessing and generate summary statistics.
        """
        # Mark as complete
        self.is_preprocessed = True
        processing_time = (datetime.now() - self.creation_time).total_seconds()
        
        # Generate summary
        logger.info(f"Preprocessing complete: {self.total_fields} total fields, "
                   f"{self.fuzzable_field_count} fuzzable, {self.excluded_field_count} excluded, "
                   f"{self.layer_collision_count} packets with collisions, "
                   f"processed in {processing_time:.2f}s")
    
    def _create_packet_copies(self) -> None:
        """
        Create deep copies of packets with proper iteration logic during preprocessing.
        """
        # Normalize packets from config to a list
        if isinstance(self.original_packets, list):
            packets_list = list(self.original_packets)
        else:
            packets_list = [self.original_packets]
        
        self.fuzzed_packets = []
        num_original = len(packets_list)
        
        for i in range(self.iterations):
            # Cycle through original packets using modulo
            packet_index = i % num_original
            self.fuzzed_packets.append(copy.deepcopy(packets_list[packet_index]))
        
        logger.debug(f"PREPROCESSING: Created {len(self.fuzzed_packets)} packet copies for {self.iterations} iterations "
                    f"(cycling through {num_original} original packets)")
        
        # Update total_packets now that we have the final count
        self.total_packets = len(self.fuzzed_packets)

    def _process_single_packet(self, packet: Packet, packet_idx: int,
                              dictionary_manager: Optional[Any]) -> PacketData:
        """
        Process a single packet to extract all field metadata.
        
        Args:
            packet: Scapy packet to process
            packet_idx: Index of packet in list
            dictionary_manager: DictionaryManager for configuration resolution
            
        Returns:
            PacketData with complete field metadata
        """
        packet_data = PacketData(
            packet_index=packet_idx,
            packet=packet,
            packet_summary=packet.summary()
        )
        
        # Discover all layers and handle collisions
        layer_counts: Dict[str, int] = {}
        layers = packet.layers()
        
        for layer_class in layers:
            layer_name = layer_class.__name__
            layer_counts[layer_name] = layer_counts.get(layer_name, 0) + 1
            packet_data.layer_names.append(layer_name)
        
        # Build collision map
        packet_data.layer_collision_map = layer_counts.copy()
        
        # Build layer index mapping for collision resolution
        layer_instance_counts: Dict[str, int] = {}
        for layer_class in layers:
            layer_name = layer_class.__name__
            current_index = layer_instance_counts.get(layer_name, 0)
            
            if layer_name not in packet_data.layer_indexes:
                packet_data.layer_indexes[layer_name] = []
            packet_data.layer_indexes[layer_name].append(current_index)
            
            # Process all fields in this layer instance
            if current_index == 0:
                # For first occurrence, try without index first, then with index
                layer = packet.getlayer(layer_class) or packet.getlayer(layer_class, current_index)
            else:
                # For subsequent occurrences, must use index
                layer = packet.getlayer(layer_class, current_index)
                
            if layer is not None:
                self._process_layer_fields(layer, layer_name, current_index, 
                                         packet_data, packet_idx, dictionary_manager)
            
            layer_instance_counts[layer_name] = current_index + 1
        
        # Finalize packet statistics
        packet_data.total_fields = len(packet_data.fields)
        packet_data.successful_extractions = len([f for f in packet_data.fields.values() 
                                                 if f.is_fuzzable])
        packet_data.failed_extractions = packet_data.total_fields - packet_data.successful_extractions
        
        return packet_data
    
    def _process_layer_fields(self, layer: Packet, layer_name: str, layer_index: int,
                             packet_data: PacketData, packet_index: int, 
                             dictionary_manager: Optional[Any]) -> None:
        """
        Process all fields in a single layer instance.
        
        Args:
            layer: Scapy layer instance
            layer_name: Layer class name
            layer_index: Index for collision resolution
            packet_data: PacketData to populate
            packet_index: Index of packet in the list
            dictionary_manager: DictionaryManager for configuration resolution
        """
        for field_desc in layer.fields_desc:
            field_name = field_desc.name
            
            # Create field metadata
            field_metadata = self._create_field_metadata(
                layer, field_desc, layer_name, layer_index, packet_index, dictionary_manager
            )
            
            # Add to packet data
            packet_data.fields[field_metadata.field_key] = field_metadata
            
            if field_metadata.is_fuzzable:
                packet_data.fuzzable_fields.append(field_metadata.field_key)
            else:
                packet_data.excluded_fields.append(field_metadata.field_key)
                    

    def _create_field_metadata(self, layer: Packet, field_desc: Field, 
                              layer_name: str, layer_index: int, packet_index: int,
                              dictionary_manager: Optional[Any]) -> FieldMetadata:
        """
        Create complete field metadata with resolved configuration.
        
        Args:
            layer: Scapy layer containing the field
            field_desc: Scapy field descriptor
            layer_name: Layer class name
            layer_index: Index for collision resolution
            packet_index: Index of packet in the list
            dictionary_manager: DictionaryManager for configuration resolution
            
        Returns:
            FieldMetadata with complete configuration
        """
        field_name = field_desc.name
        field_key = self._generate_field_key(layer_name, field_name, layer_index)
        
        # Get current field value
        current_value = getattr(layer, field_name, None)
        
        # Determine field type and kind
        field_type = type(field_desc).__name__
        field_kind = self._categorize_field_type(layer, field_name)
        
        # Extract field constraints
        constraints = self._extract_field_constraints(layer, field_desc, layer_name, field_name)
        
        # Create base metadata
        field_metadata = FieldMetadata(
            field_key=field_key,
            layer_name=layer_name,
            field_name=field_name,
            layer_index=layer_index,
            packet_index=packet_index,
            field_type=field_type,
            field_kind=field_kind,
            current_value=current_value,
            **constraints
        )
        
        # Resolve fuzzing configuration
        self._resolve_field_configuration(field_metadata, layer, dictionary_manager)
        
        return field_metadata
    
    def _generate_field_key(self, layer_name: str, field_name: str, layer_index: int) -> str:
        """
        Generate unique field key with collision resolution.
        
        Format: "Layer[index].field" (e.g., "TCP[0].dport", "TCP[1].sport")
        
        Args:
            layer_name: Layer class name
            field_name: Field name
            layer_index: Index for collision resolution
            
        Returns:
            Unique field key string
        """
        return f"{layer_name}[{layer_index}].{field_name}"
    
    def _categorize_field_type(self, layer: Packet, field_name: str) -> str:
        """
        Categorize Scapy field into fuzzing-relevant types.
        
        Uses consolidated field_utils for enhanced type resolution with fallback
        to maintain consistency with MutatorManager.
        
        Args:
            layer: Packet layer containing the field
            field_name: Name of the field to categorize
            
        Returns:
            Categorized field type
        """
        from packetfuzz.utils.field_utils import get_field_type_chain
        
        # Special case: IP address fields should be treated as strings, not numeric
        layer_name = layer.__class__.__name__
        if layer_name == "IP" and field_name in ("src", "dst"):
            return "string"
        
        # Get detailed type chain
        type_chain = get_field_type_chain(layer, field_name)
        
        if type_chain:
            # Check the entire inheritance chain, not just the primary type
            for type_name in type_chain:
                # Categorize based on type hierarchy
                if any(typ in type_name for typ in ['Int', 'Byte', 'Short', 'Bit']):
                    return "numeric"
                elif any(typ in type_name for typ in ['Str', 'String']):
                    return "string"
                elif any(typ in type_name for typ in ['Enum']):
                    return "enum"
                elif any(typ in type_name for typ in ['Flag']):
                    return "flags"
            
            # If no match found in inheritance chain, return unknown
            return "unknown"
        
        return "unknown"
    
    def _extract_field_constraints(self, layer: Packet, field_desc: Field, layer_name: str, field_name: str) -> Dict[str, Any]:
        """
        Extract field constraints using field utilities for consistency.
        
        Args:
            layer: Scapy layer containing the field
            field_desc: Scapy field descriptor
            layer_name: Name of the layer (e.g., 'HTTPRequest')
            field_name: Name of the field (e.g., 'Method')
            
        Returns:
            Dictionary of constraint information
        """
        # Use field_utils for robust property extraction
        from .utils.field_utils import extract_field_properties
        properties = extract_field_properties(layer, field_desc.name)
        
        # Convert properties to constraints format
        constraints = {
            'min_value': None,
            'max_value': None,
            'min_length': None,
            'max_length': None,
            'enum_values': None,
            'is_signed': False
        }
        
        # Map properties to constraints with fuzzing-friendly adjustments
        if 'length' in properties:
            constraints['max_length'] = properties['length']
        if 'size' in properties:
            constraints['max_length'] = properties['size']
        
        # Fix overly restrictive size constraints for HTTP header values
        # Scapy's _HTTPHeaderField uses sz=2 (for header indexes), but for fuzzing
        # header values we need realistic limits
        if layer_name in ['HTTPRequest', 'HTTPResponse']:
            if field_name == 'Method':
                constraints['max_length'] = 32  # HTTP methods: GET, POST, etc.
                constraints['min_length'] = 3   # Minimum realistic method length
            elif field_name in ['Path']:
                constraints['max_length'] = 8192  # URLs can be long
                constraints['min_length'] = 1    # At least "/"
            elif field_name in ['Host']:
                constraints['max_length'] = 253  # DNS hostname limit
                constraints['min_length'] = 3    # Minimum realistic hostname
            elif field_name in ['User_Agent']:
                constraints['max_length'] = 2048  # User agents can be long
                constraints['min_length'] = 20   # Encourage realistic UA strings
            elif field_name in ['Authorization', 'Cookie', 'Set_Cookie']:
                constraints['max_length'] = 4096  # Auth/cookie data can be very long
                constraints['min_length'] = 10   # Encourage substantial content
            elif field_name in ['Content_Type', 'Accept', 'Accept_Encoding', 'Accept_Language']:
                constraints['max_length'] = 512  # Content negotiation headers
                constraints['min_length'] = 8    # Encourage realistic MIME types
            # For other HTTP fields, if size is unreasonably small, use a reasonable default
            elif constraints.get('max_length') and constraints['max_length'] < 128:
                constraints['max_length'] = 1024  # General reasonable default
                constraints['min_length'] = 4     # Encourage non-trivial content
                
        # Add field-specific constraints using MutatorManager logic
        from scapy.fields import EnumField, IntEnumField, StrField
        
        # Enum field constraints
        if isinstance(field_desc, (EnumField, IntEnumField)):
            enum_dict = getattr(field_desc, 'enum', {})
            if enum_dict:
                constraints['enum_values'] = dict(enum_dict)
        
        # String field constraints
        if isinstance(field_desc, StrField):
            max_len = getattr(field_desc, 'max_len', None)
            if max_len:
                constraints['max_length'] = max_len
        
        return constraints
    
    def _resolve_field_configuration(self, field_metadata: FieldMetadata, 
                                    layer: Packet, dictionary_manager: Optional[Any]) -> None:
        """
        Simple 3-level configuration resolution: FuzzField → Campaign → Defaults.
        Clean merge approach with no complex priority system.
        """
        # Collect sources
        sources = self._collect_configuration_sources(field_metadata, layer, dictionary_manager)
        
        # Merge in priority order (later overwrites earlier)
        config = self._merge_configurations(sources, layer)
        
        # Apply to field metadata
        self._apply_merged_configuration(field_metadata, layer, config, sources)
    
    def _collect_configuration_sources(self, field_metadata: FieldMetadata, 
                                      layer: Packet, dictionary_manager: Optional[Any]) -> ConfigurationSources:
        """
        Collect the 3 configuration sources: Defaults → Campaign → FuzzField.
        Simple data collection with no complex logic.
        """
        sources = ConfigurationSources()
        
        # 1. Default configuration (always available)
        sources.default_weight = self.fuzz_config.fuzz_weight
        if dictionary_manager:
            sources.default_dictionaries, sources.default_values = self._get_default_config(
                field_metadata, dictionary_manager)
            sources.default_mutator_weights = self._get_default_mutator_weights(field_metadata)
        
        # 2. Campaign configuration (from FuzzConfig + overrides)
        if self.fuzz_config.advanced_field_mapping_overrides:
            campaign_config = self._get_campaign_config(field_metadata)
            sources.campaign_weight = campaign_config.get('weight')
            sources.campaign_dictionaries = campaign_config.get('dictionaries', [])
            sources.campaign_values = campaign_config.get('values', [])
        
        # 3. FuzzField configuration (highest priority)
        field_value = getattr(layer, field_metadata.field_name, None)
        fuzzfield_config = self._extract_fuzzfield_configuration(field_value)
        if fuzzfield_config['is_fuzzfield']:
            sources.fuzzfield_weight = fuzzfield_config.get('fuzz_weight')
            sources.fuzzfield_dictionaries = fuzzfield_config.get('dictionaries', [])
            sources.fuzzfield_values = fuzzfield_config.get('values', [])
            sources.fuzzfield_mutator_weights = fuzzfield_config.get('mutator_weights', {})
            sources.fuzzfield_scapy_weight = fuzzfield_config.get('scapy_fuzz_weight')
            sources.fuzzfield_dictionary_only_weight = fuzzfield_config.get('dictionary_only_weight')
            sources.fuzzfield_use_scapy_fuzz = fuzzfield_config.get('use_scapy_fuzz')
            sources.fuzzfield_object = field_value
        
        return sources
    
    def _merge_configurations(self, sources: ConfigurationSources, layer: Packet) -> Dict[str, Any]:
        """
        Simple merge: Defaults → Campaign → FuzzField (later wins).
        Apply layer scaling at the end.
        """
        # Start with defaults
        config = {
            'weight': sources.default_weight,
            'dictionaries': sources.default_dictionaries.copy(),
            'values': sources.default_values.copy(),
            'mutator_weights': sources.default_mutator_weights.copy(),
            'scapy_fuzz_weight': 0.1,
            'dictionary_only_weight': 0.2,
            'use_scapy_fuzz': True,
            'config_source': 'default'
        }
        
        # Merge campaign (overwrites defaults)
        if sources.campaign_weight is not None:
            config['weight'] = sources.campaign_weight
            config['config_source'] = 'campaign'
        if sources.campaign_dictionaries:
            config['dictionaries'].extend(sources.campaign_dictionaries)
        if sources.campaign_values:
            config['values'].extend(sources.campaign_values)
        if sources.campaign_mutator_weights:
            config['mutator_weights'].update(sources.campaign_mutator_weights)
        
        # Merge FuzzField (overwrites everything)
        if sources.fuzzfield_weight is not None:
            config['weight'] = sources.fuzzfield_weight
            config['config_source'] = 'fuzzfield'
        if sources.fuzzfield_dictionaries:
            config['dictionaries'] = sources.fuzzfield_dictionaries  # Replace, don't extend
        if sources.fuzzfield_values:
            config['values'] = sources.fuzzfield_values  # Replace, don't extend
        if sources.fuzzfield_mutator_weights:
            config['mutator_weights'] = sources.fuzzfield_mutator_weights
        if sources.fuzzfield_scapy_weight is not None:
            config['scapy_fuzz_weight'] = sources.fuzzfield_scapy_weight
        if sources.fuzzfield_dictionary_only_weight is not None:
            config['dictionary_only_weight'] = sources.fuzzfield_dictionary_only_weight
        if sources.fuzzfield_use_scapy_fuzz is not None:
            config['use_scapy_fuzz'] = sources.fuzzfield_use_scapy_fuzz
        
        # Apply layer weight scaling
        if self.fuzz_config.enable_layer_weight_scaling:
            config['weight'] *= self._calculate_layer_scaling_factor(layer)
        
        # Apply campaign global scaling
        config['weight'] *= self.fuzz_config.fuzz_weight_scale
        
        return config
    
    def _apply_merged_configuration(self, field_metadata: FieldMetadata, layer: Packet, 
                                   config: Dict[str, Any], sources: ConfigurationSources) -> None:
        """
        Apply merged configuration to field metadata and handle FuzzField materialization.
        """
        field_metadata.fuzz_weight = config['weight']
        field_metadata.dictionary_paths = config['dictionaries']
        field_metadata.default_values = config['values']
        field_metadata.mutator_weights = config['mutator_weights']
        field_metadata.scapy_fuzz_weight = config['scapy_fuzz_weight']
        field_metadata.dictionary_only_weight = config['dictionary_only_weight']
        field_metadata.use_scapy_fuzz = config['use_scapy_fuzz']
        field_metadata.config_source = config['config_source']
        
        # Handle FuzzField materialization
        if sources.fuzzfield_object is not None:
            self._materialize_fuzzfield_in_packet(layer, field_metadata.field_name, sources.fuzzfield_object)
        
        # Determine if field is fuzzable
        field_metadata.is_fuzzable = (
            field_metadata.fuzz_weight > 0 and 
            field_metadata.field_kind != "unknown"
        )
        
        if not field_metadata.is_fuzzable:
            if field_metadata.fuzz_weight <= 0:
                field_metadata.exclusion_reason = "Zero fuzz weight"
            elif field_metadata.field_kind == "unknown":
                field_metadata.exclusion_reason = "Unknown field type"
    
    def _get_default_config(self, field_metadata: FieldMetadata, 
                           dictionary_manager: Any) -> Tuple[List[str], List[Any]]:
        """Get default dictionaries and values for a field."""
        from .default_mappings import (FIELD_NAME_DICTIONARIES, FIELD_TYPE_DICTIONARIES)
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        
        dictionary_paths = []
        
        # Name-based dictionaries
        if key in FIELD_NAME_DICTIONARIES:
            for d in FIELD_NAME_DICTIONARIES[key]:
                dictionary_paths.extend(dictionary_manager.expand_macro(d))
        
        # Type-based dictionaries
        if field_type in FIELD_TYPE_DICTIONARIES:
            for d in FIELD_TYPE_DICTIONARIES[field_type]:
                dictionary_paths.extend(dictionary_manager.expand_macro(d))
        
        # Remove duplicates and resolve paths
        unique_paths = list(dict.fromkeys(dictionary_paths))
        resolved_paths = [dictionary_manager._resolve_path(path) for path in unique_paths]
        
        # Load dictionary values
        values = []
        if resolved_paths:
            dict_entries = dictionary_manager.get_dictionary_entries(unique_paths)
            values = [entry.decode('utf-8', errors='ignore') for entry in dict_entries]
        
        return resolved_paths, values
    
    def _get_default_mutator_weights(self, field_metadata: FieldMetadata) -> Dict[str, float]:
        """Get default mutator weights for a field."""
        from .default_mappings import (FIELD_TYPE_MUTATOR_WEIGHTS, FIELD_NAME_MUTATOR_WEIGHTS)
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        
        # Name-based weights (higher priority)
        if key in FIELD_NAME_MUTATOR_WEIGHTS:
            return FIELD_NAME_MUTATOR_WEIGHTS[key].copy()
        
        # Type-based weights
        if field_type in FIELD_TYPE_MUTATOR_WEIGHTS:
            return FIELD_TYPE_MUTATOR_WEIGHTS[field_type].copy()
        
        # Fallback
        return {"libfuzzer": 1.0}
    
    def _get_campaign_config(self, field_metadata: FieldMetadata) -> Dict[str, Any]:
        """Get campaign-level overrides for a field with enhanced pattern matching."""
        if not self.fuzz_config.advanced_field_mapping_overrides:
            return {}
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        
        for override in self.fuzz_config.advanced_field_mapping_overrides:
            # Direct match: Layer.field
            if (override.get('layer') == layer_name and 
                override.get('field') == field_name):
                return override
            
            # Wildcard match: *.field  
            elif (override.get('field') == field_name and 
                  'layer' not in override):
                return override
            
            # Layer wildcard: Layer.*
            elif (override.get('layer') == layer_name and 
                  'field' not in override):
                return override
            
            # Enhanced wildcard patterns
            elif 'pattern' in override and 'pattern_type' in override:
                if self._matches_enhanced_pattern(layer_name, field_name, override):
                    return override
        
        return {}
    
    def _calculate_layer_scaling_factor(self, layer: Packet) -> float:
        """Calculate layer weight scaling factor."""
        if not self.fuzz_config.enable_layer_weight_scaling:
            return 1.0
        
        depth_below = self._calculate_layer_depth(layer)
        
        if self.fuzz_config.layer_weight_scaling is not None:
            scaling_factor = self.fuzz_config.layer_weight_scaling
        else:
            from .default_mappings import LAYER_WEIGHT_SCALING
            scaling_factor = LAYER_WEIGHT_SCALING
        
        return scaling_factor ** depth_below
    
    def _extract_fuzzfield_configuration(self, field_value: Any) -> Dict[str, Any]:
        """
        Extract configuration from a FuzzField object if present.
        Returns a dictionary with FuzzField configuration or indicates not a FuzzField.
        """
        # Import FuzzField
        from .fuzzing_framework import FuzzField
        
        if not isinstance(field_value, FuzzField):
            return {'is_fuzzfield': False}
        
        # Extract configuration from FuzzField
        config: Dict[str, Any] = {'is_fuzzfield': True}
        
        # Get basic properties safely
        if hasattr(field_value, 'fuzz_weight'):
            config['fuzz_weight'] = field_value.fuzz_weight
        if hasattr(field_value, 'dictionaries'):
            config['dictionaries'] = field_value.dictionaries or []
        if hasattr(field_value, 'values'):
            config['values'] = field_value.values or []
        
        # Use getattr for optional attributes that may not exist
        mutator_weights = getattr(field_value, 'mutator_weights', None)
        if mutator_weights:
            config['mutator_weights'] = mutator_weights
            
        scapy_fuzz_weight = getattr(field_value, 'scapy_fuzz_weight', None)
        if scapy_fuzz_weight is not None:
            config['scapy_fuzz_weight'] = scapy_fuzz_weight
            
        dictionary_only_weight = getattr(field_value, 'dictionary_only_weight', None)
        if dictionary_only_weight is not None:
            config['dictionary_only_weight'] = dictionary_only_weight
            
        use_scapy_fuzz = getattr(field_value, 'use_scapy_fuzz', None)
        if use_scapy_fuzz is not None:
            config['use_scapy_fuzz'] = use_scapy_fuzz
        
        return config

    def _materialize_fuzzfield_in_packet(self, layer: Packet, field_name: str, fuzzfield_object: Any) -> None:
        """
        Replace FuzzField with a chosen value in the packet layer.
        """
        chosen_value = fuzzfield_object.choose_value()
        if chosen_value is not None:
            setattr(layer, field_name, chosen_value)
            logger.debug(f"Materialized FuzzField {field_name} to value: {chosen_value}")
        else:
            # If no value chosen, remove the attribute to let Scapy resolve defaults
            if hasattr(layer, field_name):
                delattr(layer, field_name)
                logger.debug(f"Removed FuzzField {field_name} attribute (no value chosen)")


    def _calculate_layer_depth(self, layer):
        """
        Calculate the depth of a layer from the innermost layer.
        """
        from packetfuzz.utils.field_utils import calculate_layer_depth_below
        return calculate_layer_depth_below(layer)

    def _build_global_field_index(self) -> None:
        """
        Build global field index for cross-packet analysis and mutation targeting.
        
        This method creates a comprehensive mapping of field keys to packet locations,
        enabling efficient field lookups and cross-packet field analysis.
        """
        try:
            logger.debug("Building global field index for cross-packet analysis")
            self.global_field_index.clear()
            
            for packet_data in self.packet_data:
                self._build_field_index(packet_data)
                
            logger.debug(f"Built global field index with {len(self.global_field_index)} unique field keys")
            
        except Exception as e:
            error_msg = f"Failed to build global field index: {e}"
            self.preprocessing_errors.append(error_msg)
            logger.error(error_msg)
            raise

    def _build_field_index(self, packet_data: 'PacketData') -> None:
        """
        Builds an index of all packet fields for efficient field lookups.
        """
        try:
            for field_key in packet_data.fields:
                if field_key not in self.global_field_index:
                    self.global_field_index[field_key] = []
                self.global_field_index[field_key].append(
                    (packet_data.packet_index, field_key)
                )
        except Exception as e:
            raise

        
    def _matches_enhanced_pattern(self, layer_name: str, field_name: str, override: Dict[str, Any]) -> bool:
        """
        Check if a layer.field matches an enhanced wildcard pattern.
        
        Supports pattern types:
        - layer_field_wildcard: Both layer and field have wildcards (e.g., HTTP*.port*)
        - layer_wildcard: Only layer has wildcards (e.g., HTTP*.dport)
        - field_wildcard: Only field has wildcards (e.g., TCP.port*)
        
        Args:
            layer_name: Name of the layer (e.g., "HTTP", "TCP")
            field_name: Name of the field (e.g., "dport", "version")
            override: Override entry with pattern information
            
        Returns:
            True if the layer.field matches the pattern
        """
        import fnmatch
        
        pattern = override.get('pattern', '')
        pattern_type = override.get('pattern_type', '')
        
        if pattern_type == 'layer_field_wildcard':
            # Pattern like "HTTP*.port*" - both layer and field have wildcards
            if '.' in pattern:
                pattern_layer, pattern_field = pattern.split('.', 1)
                layer_match = fnmatch.fnmatch(layer_name, pattern_layer)
                field_match = fnmatch.fnmatch(field_name, pattern_field)
                return layer_match and field_match
            else:
                # Fallback to simple field matching
                return fnmatch.fnmatch(field_name, pattern)
        
        elif pattern_type == 'layer_wildcard':
            # Pattern like "HTTP*" with specific field
            pattern_layer = pattern.split('.')[0] if '.' in pattern else pattern
            specific_field = override.get('field', '')
            layer_match = fnmatch.fnmatch(layer_name, pattern_layer)
            field_match = (field_name == specific_field)
            return layer_match and field_match
        
        elif pattern_type == 'field_wildcard':
            # Pattern like "port*" with specific layer
            specific_layer = override.get('layer', '')
            pattern_field = pattern.split('.')[1] if '.' in pattern else pattern
            layer_match = (layer_name == specific_layer)
            field_match = fnmatch.fnmatch(field_name, pattern_field)
            return layer_match and field_match
        
        # Fallback: try to match the full pattern against layer.field
        full_field_name = f"{layer_name}.{field_name}"
        return fnmatch.fnmatch(full_field_name, pattern)

    
    # =========================
    # Public Query Interface
    # =========================
    def validate_and_assign(self, field, packet_index: int = 0, value: Any = None) -> bool:
        """
        Validate, normalize, and assign a field value with basic constraints and a quick serialize smoke-check.
        Accepts either a field key (str) or a FieldMetadata object.
        Args:
            field: Field key (str) or FieldMetadata object
            packet_index: Index of the packet (if field is a key)
            value: Value to assign (if None, uses field_metadata.current_value)
        Returns:
            True if assignment succeeded, False otherwise
        """
        # Resolve FieldMetadata
        if isinstance(field, str):
            field_metadata = self.get_field_by_key(field, packet_index)
            if not field_metadata:
                logger.debug(f"validate_and_assign: Field key {field} not found in packet {packet_index}")
                return False
        else:
            field_metadata = field
        # Get layer and field name
        packet_data = self.packet_data[field_metadata.packet_index]
        # Scapy uses 1-based indexing for getlayer, but our layer_index is 0-based
        layer = packet_data.packet.getlayer(field_metadata.layer_name, field_metadata.layer_index + 1)
        fname = field_metadata.field_name
        # Use provided value or current_value
        assign_value = value if value is not None else field_metadata.current_value
        kind = field_metadata.field_kind
        min_value = field_metadata.min_value
        max_value = field_metadata.max_value
        enum_map = field_metadata.enum_values
        max_len = field_metadata.max_length
        # Debug logging for validation attempts
        logger.debug(f"validate_and_assign: field={fname}, kind={kind}, value={repr(assign_value)}, layer={field_metadata.layer_name}")
        def _coerce_int(v: Any) -> Optional[int]:
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, int):
                return v
            s: Optional[str] = None
            if isinstance(v, (bytes, bytearray)):
                s = v.decode('utf-8', errors='ignore').strip()
            elif isinstance(v, str):
                s = v.strip()
            if s is None or s == "":
                return None
            if s.lower().startswith(("0x", "+0x", "-0x")):
                return int(s, 16)
            return int(s, 10)
        def _clamp(v: int, mn: Optional[int], mx: Optional[int]) -> int:
            if mn is not None and v < mn:
                v = mn
            if mx is not None and v > mx:
                v = mx
            return v
        try:
            normalized = assign_value
            if kind in ('options', 'list'):
                if assign_value is None:
                    normalized = []
            else:
                if kind in ('numeric', 'flags', 'enum'):
                    ival = _coerce_int(assign_value)
                    if ival is None:
                        logger.debug(f"validate_and_assign: Failed to coerce {repr(assign_value)} to int for {fname}")
                        return False
                    if kind in ('numeric', 'flags'):
                        ival = _clamp(ival, min_value, max_value)
                        normalized = ival
                    elif kind == 'enum':
                        if enum_map and ival not in enum_map.keys():
                            logger.debug(f"validate_and_assign: Value {ival} not in enum_map for {fname}")
                            return False
                        normalized = ival
            if kind == 'string':
                logger.debug(f"validate_and_assign: String field {fname}, normalized={repr(normalized)}")
            # Quick serialize smoke-check on a cloned layer to avoid side effects
            try:
                layer_clone = copy.deepcopy(layer)
                logger.debug(f"validate_and_assign: Testing assignment of {repr(normalized)} to {fname}")
                setattr(layer_clone, fname, normalized)
                logger.debug(f"validate_and_assign: Assignment successful, testing serialization")
                _ = bytes(layer_clone)
                logger.debug(f"validate_and_assign: Serialization successful")
            except Exception as e:
                logger.debug(f"validate_and_assign: Serialize test failed for {fname}: {e}")
                return False
            # Apply to the real layer now that validation passed
            try:
                setattr(layer, fname, normalized)
                field_metadata.current_value = normalized
                logger.debug(f"validate_and_assign: Final assignment successful for {fname}")
            except Exception as e:
                logger.debug(f"validate_and_assign: Final assignment failed for {fname}: {e}")
                return False
            return True
        except Exception as e:
            logger.debug(f"validate_and_assign: Exception during validation of {fname}: {e}")
            return False
        
    def get_field_metadata(self, field_key: str, packet_index: int) -> Optional[FieldMetadata]:
        """Get metadata for a specific field in a specific packet."""
        if 0 <= packet_index < len(self.packet_data):
            return self.packet_data[packet_index].fields.get(field_key)
        return None
    
    def get_field_value(self, field_key: str, packet_index: int) -> Any:
        """Get current value of a specific field in a specific packet."""
        field_metadata = self.get_field_metadata(field_key, packet_index)
        if field_metadata:
            return field_metadata.current_value
        return None

    def get_unfuzzed_packets(self) -> List[int]:
        """Get list of packet indexes that have no fuzzed fields."""
        unfuzzed_packets = []
        for packet_data in self.packet_data:
            if all(field_metadata.mutation_count == 0 
                   for field_metadata in packet_data.fields.values()):
                unfuzzed_packets.append(packet_data.packet_index)
        return unfuzzed_packets

    def get_field_mutation_failures(self, field_key: str) -> Dict[Tuple[str, str], int]:
        """
        Get mutation failure counts for a specific field across all packets.
        
        Args:
            field_key: Field identifier (e.g., "IP[0].dst")
            
        Returns:
            Dictionary mapping (packet_summary, field_key) to failure count
        """
        failures = {}
        for packet_data in self.packet_data:
            field_metadata = packet_data.fields.get(field_key)
            if field_metadata and field_metadata.failed_mutations > 0:
                failures[(packet_data.packet_summary, field_key)] = field_metadata.failed_mutations
        return failures

    def get_mutator_usage_summary(self) -> Dict[str, int]:
        """Get summary of mutator usage across all fields."""
        mutator_usage: Dict[str, int] = {}
        for packet_data in self.packet_data:
            for field_metadata in packet_data.fields.values():
                for mutator in field_metadata.mutator_preferences:
                    mutator_usage[mutator] = mutator_usage.get(mutator, 0) + field_metadata.mutation_count
        return mutator_usage

    def get_all_fuzzed_fields(self) -> List[str]:
        """
        Get list of all field keys that are fuzzed across all packets.
        
        Note: Currently returns fields that have been mutated globally across
        all iterations due to architectural limitations.
        """
        fuzzed_fields = set()
        for packet_data in self.packet_data:
            # Only check fields marked as fuzzable during preprocessing
            for field_key in packet_data.fuzzable_fields:
                field_metadata = packet_data.fields.get(field_key)
                if field_metadata and field_metadata.mutation_count > 0:
                    fuzzed_fields.add(field_key)
        return list(fuzzed_fields)
    
    def get_fuzzed_fields_for_packet(self, packet_index: int) -> List[str]:
        """
        Get list of field keys that were actually mutated for a specific packet iteration.
        
        Note: This method currently has an architectural limitation - the MutatorManager
        processes all field types globally rather than per-iteration, so this will
        return fields that have been mutated across all iterations for now.
        
        TODO: Implement proper per-iteration field tracking
        """
        if 0 <= packet_index < len(self.packet_data):
            packet_data = self.packet_data[packet_index]
            fuzzed_fields = set()
            # For now, only check fields marked as fuzzable during preprocessing
            # until we implement proper per-iteration tracking
            for field_key in packet_data.fuzzable_fields:
                field_metadata = packet_data.fields.get(field_key)
                if field_metadata and field_metadata.mutation_count > 0:
                    fuzzed_fields.add(field_key)
            return list(fuzzed_fields)
        return []
    
    def record_mutator_usage(self, iteration: int, field_key: str, mutator_name: str) -> None:
        """
        Record which mutator was used for a specific field in a specific iteration.
        
        Args:
            iteration: The iteration number (packet index)
            field_key: The field key (e.g., "HTTPRequest[0].Method")
            mutator_name: The name of the mutator used (e.g., "libfuzzer", "dictionary_only")
        """
        if iteration not in self.iteration_mutator_usage:
            self.iteration_mutator_usage[iteration] = {}
        self.iteration_mutator_usage[iteration][field_key] = mutator_name
    
    def get_mutators_for_packet(self, packet_index: int) -> Dict[str, str]:
        """
        Get mapping of field_key -> mutator_name for a specific packet iteration.
        
        Args:
            packet_index: The packet iteration index
            
        Returns:
            Dictionary mapping field keys to mutator names used in that iteration
        """
        return self.iteration_mutator_usage.get(packet_index, {})
    
    def get_fuzzed_fields_with_mutators_for_packet(self, packet_index: int) -> List[Tuple[str, str]]:
        """
        Get list of (field_key, mutator_name) tuples for a specific packet iteration.
        
        Args:
            packet_index: The packet iteration index
            
        Returns:
            List of tuples containing (field_key, mutator_name) for fuzzed fields
        """
        mutator_usage = self.get_mutators_for_packet(packet_index)
        return [(field_key, mutator_name) for field_key, mutator_name in mutator_usage.items()]
    
    def get_all_fuzzable_fields(self) -> List[FieldMetadata]:
        """Get all fuzzable fields across all packets."""
        fields = []
        for packet_data in self.packet_data:
            for field_key in packet_data.fuzzable_fields:
                fields.append(packet_data.fields[field_key])
        return fields
    
    def get_fuzzable_field_keys(self) -> List[str]:
        """Get all fuzzable field keys across all packets."""
        field_keys = []
        for packet_data in self.packet_data:
            field_keys.extend(packet_data.fuzzable_fields)
        return field_keys
    
    def get_all_fieldtypes(self) -> List[str]:
        """Get list of all unique field types across all packets."""
        field_types = set()
        for packet_data in self.packet_data:
            for field_metadata in packet_data.fields.values():
                field_types.add(field_metadata.field_type)
        return list(field_types)
    
    def get_all_layer_types(self) -> List[str]:
        """Get list of all unique layer types across all packets."""
        layer_types = set()
        for packet_data in self.packet_data:
            pkt = getattr(packet_data, 'packet', None)
            while pkt:
                layer_types.add(type(pkt).__name__)
                if hasattr(pkt, 'payload') and pkt.payload and pkt.payload != pkt:
                    pkt = pkt.payload
                else:
                    break
        return sorted(layer_types)
    
    def get_fields_by_layer(self, layer_name: str) -> List[FieldMetadata]:
        """Get all fields belonging to a specific layer type."""
        fields = []
        for packet_data in self.packet_data:
            fields.extend(packet_data.get_field_by_layer(layer_name))
        return fields
    
    def get_field_by_key(self, field_key: str, packet_index: int = 0) -> Optional[FieldMetadata]:
        """Get specific field metadata by key and packet index."""
        if 0 <= packet_index < len(self.packet_data):
            return self.packet_data[packet_index].fields.get(field_key)
        return None
    
    def get_all_fields_of_type(self, field_type: str) -> List[FieldMetadata]:
        """Get all fields of a specific Scapy field type across all packets."""
        fields = []
        for packet_data in self.packet_data:
            for field_metadata in packet_data.fields.values():
                if field_metadata.field_type == field_type:
                    fields.append(field_metadata)
        return fields
    
    def get_collision_summary(self) -> Dict[str, int]:
        """Get summary of layer name collisions across all packets."""
        collision_summary = {}
        for packet_data in self.packet_data:
            for layer_name, count in packet_data.layer_collision_map.items():
                if count > 1:
                    collision_summary[layer_name] = max(
                        collision_summary.get(layer_name, 0), count
                    )
        return collision_summary
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """Get comprehensive processing summary."""
        return {
            'total_packets': self.total_packets,
            'total_fields': self.total_fields,
            'fuzzable_fields': self.fuzzable_field_count,
            'excluded_fields': self.excluded_field_count,
            'layer_collisions': self.layer_collision_count,
            'is_preprocessed': self.is_preprocessed,
            'preprocessing_errors': len(self.preprocessing_errors),
            'iterations': self.iterations,
            'creation_time': self.creation_time.isoformat()
        }
    
    def record_field_mutation(self, field_key: str, packet_index: int, 
                             success: bool, mutator_name: str = "unknown") -> None:
        """
        Record a field mutation for statistics tracking.
        
        Args:
            field_key: Field identifier
            packet_index: Index of packet that was mutated
            success: Whether mutation was successful
            mutator_name: Name of mutator used
        """
        field_metadata = self.get_field_by_key(field_key, packet_index)
        if field_metadata:
            field_metadata.mutation_count += 1
            if success:
                field_metadata.successful_mutations += 1
                # Record mutator usage for this successful mutation
                self.record_mutator_usage(packet_index, field_key, mutator_name)
            else:
                field_metadata.failed_mutations += 1
            field_metadata.last_mutated = datetime.now()
    