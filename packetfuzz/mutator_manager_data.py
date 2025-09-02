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
    """Configuration for fuzzing operations
    mutator_preference can be a list of strings or dict of {mutator: weight}.
    
    Extended to include packet and iteration information for complete fuzzing configuration.
    This creates a single source of truth for all fuzzing parameters.
    """
    mode: FuzzMode = FuzzMode.BOTH
    max_mutations: int = DEFAULT_MAX_MUTATIONS
    use_dictionaries: bool = True
    fuzz_weight: float = DEFAULT_FUZZ_WEIGHT  # Probability of fuzzing a field
    simple_field_fuzz_weight: Optional[float] = None  # Probability of fuzzing simple fields
    fuzz_weight_scale: float = 1.0  # Global scaling factor for fuzz probabilities
    # Layer-based scaling configuration (multiplier per layer distance from innermost)
    layer_weight_scaling: Optional[float] = None  # None = use default mapping constant
    enable_layer_weight_scaling: bool = True
    mutator_preference: Union[List[str], Dict[str, float]] = field(default_factory=lambda: {"libfuzzer": 1.0})
    global_dict_config_path: Optional[str] = None  # Path to global dictionary configuration #TODO make sure this is never none
    rng: Optional[random.Random] = None  # Optional random generator for reproducibility
    
    # Packet and iteration configuration (for complete fuzzing setup)
    packets: Optional[Union[Packet, List[Packet]]] = None  # Packet(s) to fuzz
    iterations: Optional[int] = None  # Number of fuzzing iterations

    def __str__(self) -> str:
        packet_info = ""
        if self.packets is not None:
            if isinstance(self.packets, list):
                packet_info = f", packets={len(self.packets)} packets"
            else:
                packet_info = f", packets=1 packet"
        iter_info = f", iterations={self.iterations}" if self.iterations else ""
        return f"FuzzConfig(mode={self.mode.value}, max_mutations={self.max_mutations}{packet_info}{iter_info})"

    def __repr__(self) -> str:
        return (f"FuzzConfig(mode={self.mode}, max_mutations={self.max_mutations}, "
                f"use_dictionaries={self.use_dictionaries}, mutator_preference={self.mutator_preference}, "
                f"packets={type(self.packets).__name__ if self.packets else None}, "
                f"iterations={self.iterations})")
    
    def has_packets(self) -> bool:
        """Check if configuration includes packet information."""
        return self.packets is not None
    
    def get_packet_count(self) -> int:
        """Get the number of packets in configuration."""
        if self.packets is None:
            return 0
        elif isinstance(self.packets, list):
            return len(self.packets)
        else:
            return 1
    
    def get_packets_as_list(self) -> List[Packet]:
        """Get packets as a list, converting single packet if needed."""
        if self.packets is None:
            return []
        elif isinstance(self.packets, list):
            return self.packets
        else:
            return [self.packets]


# =========================
# Field and Packet Metadata Classes  
# =========================

@dataclass
class FieldMetadata:
    """
    Complete metadata for a single field with direct storage approach.
    Contains all resolved configuration data needed for field-level operations.
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
    
    # Fuzzing configuration (direct storage - resolved from all sources)
    fuzz_weight: float = 1.0  # Final resolved weight
    dictionary_paths: List[str] = field(default_factory=list)  # Resolved dictionary file paths
    default_values: List[Any] = field(default_factory=list)  # Default values for fuzzing
    mutator_preferences: List[str] = field(default_factory=list)  # Preferred mutators (legacy)
    mutator_weights: Dict[str, float] = field(default_factory=dict)  # Mutator weights for weighted selection
    
    # Weight tracking for transparency and debugging
    base_weight: float = 1.0                     # Original weight before any scaling
    layer_scaled_weight: float = 1.0             # After layer weight scaling
    campaign_scaled_weight: float = 1.0          # After campaign scaling (final)
    layer_scaling_factor: float = 1.0            # Layer scaling multiplier applied
    campaign_scaling_factor: float = 1.0         # Campaign scaling multiplier applied
    final_scaling_factor: float = 1.0            # Combined scaling factor (layer * campaign)
    
    # Advanced configuration
    scapy_fuzz_weight: float = 0.1  # Weight for Scapy's fuzz() method
    dictionary_only_weight: float = 0.0  # Weight for dictionary-only mutations
    use_scapy_fuzz: bool = False  # Whether to use Scapy's built-in fuzz
    
    # Field constraints (extracted from Scapy field descriptors)
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    enum_values: Optional[Dict[str, Any]] = None
    is_signed: bool = False

    
    # Processing metadata
    is_fuzzable: bool = True  # Whether this field can be fuzzed
    exclusion_reason: Optional[str] = None  # Why field was excluded (if any)
    config_source: str = "default"  # Source of configuration ("embedded", "campaign", "default")
    
    # Statistics tracking
    mutation_count: int = 0  # Number of times this field was mutated
    successful_mutations: int = 0  # Number of successful mutations
    failed_mutations: int = 0  # Number of failed mutations
    last_mutated: Optional[datetime] = None  # Timestamp of last mutation


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
    
    def get_fuzzable_fields_by_layer(self, layer_name: str) -> List[FieldMetadata]:
        """Get all fuzzable fields belonging to a specific layer type."""
        return [field for field in self.fields.values() 
                if field.layer_name == layer_name and field.is_fuzzable]
    
    def has_layer_collisions(self) -> bool:
        """Check if packet has any layer name collisions (multiple instances)."""
        return any(count > 1 for count in self.layer_collision_map.values())


@dataclass
class ConfigurationSources:
    """
    Container for all configuration sources collected for a field.
    
    This separates data collection from calculation logic, making the system
    more testable and maintainable. Each source is collected independently.
    """
    # Default/fallback configuration (Priority 5)
    default_weight: float = 0.0
    
    # Dictionary Manager sources - separated by priority level
    # Priority 3: Advanced/campaign-level mapping
    # Priority 4: Global defaults (name/type-based)
    manager_weight: Optional[float] = None
    manager_dictionaries: List[str] = field(default_factory=list)
    manager_values: List[Any] = field(default_factory=list)
    manager_source_type: Optional[str] = None  # "advanced" or "global"
    
    # Embedded packet configuration (priority 2)
    embedded_weight: Optional[float] = None
    embedded_dictionaries: List[str] = field(default_factory=list)
    embedded_values: List[Any] = field(default_factory=list)
    
    # FuzzField configuration (priority 1 - highest)
    fuzzfield_weight: Optional[float] = None
    fuzzfield_dictionaries: List[str] = field(default_factory=list)
    fuzzfield_values: List[Any] = field(default_factory=list)
    fuzzfield_mutators: List[str] = field(default_factory=list)  # Legacy list format
    fuzzfield_mutator_weights: Dict[str, float] = field(default_factory=dict)  # New dict format
    fuzzfield_scapy_weight: Optional[float] = None
    fuzzfield_dictionary_only_weight: Optional[float] = None
    fuzzfield_use_scapy_fuzz: Optional[bool] = None
    fuzzfield_dictionary_override: bool = False
    fuzzfield_object: Optional[Any] = None  # For materialization
    
    # Collection metadata
    collection_errors: List[str] = field(default_factory=list)
    collection_successful: bool = True


@dataclass
class ResolvedConfiguration:
    """
    Final resolved configuration after priority-based calculation.
    
    This is the output of the calculation phase and input to the application phase.
    """
    final_weight: float
    final_dictionaries: List[str]
    final_values: List[Any]
    config_source: str  # Which priority level was used
    
    # Weight tracking for transparency and debugging
    base_weight: float = 0.0                    # Original weight before any scaling
    layer_scaled_weight: float = 0.0            # After layer weight scaling
    campaign_scaled_weight: float = 0.0         # After campaign scaling (final)
    layer_scaling_factor: float = 1.0           # Layer scaling multiplier applied
    campaign_scaling_factor: float = 1.0        # Campaign scaling multiplier applied
    final_scaling_factor: float = 1.0           # Combined scaling factor (layer * campaign)
    
    # FuzzField-specific properties (if applicable)
    scapy_fuzz_weight: Optional[float] = None
    dictionary_only_weight: Optional[float] = None
    use_scapy_fuzz: Optional[bool] = None
    mutator_preferences: List[str] = field(default_factory=list)  # Legacy list format
    mutator_weights: Dict[str, float] = field(default_factory=dict)  # New dict format
    
    # Resolution metadata
    priority_level: int = 5  # 1=highest (FuzzField), 5=lowest (default)
    resolution_notes: List[str] = field(default_factory=list)


class MutatorManagerData:
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
        
        # Extract packet and iteration information
        self.packets = fuzz_config.packets
        self.iterations = fuzz_config.iterations or DEFAULT_MAX_MUTATIONS # Default if not specified
        
        # Validate inputs
        if self.packets is None:
            raise ValueError("FuzzConfig must include packets for data tracking")
        
        # Normalize packet input to list
        if isinstance(self.packets, Packet):
            self.packet_list = [self.packets]
            self.is_single_packet = True
        elif isinstance(self.packets, list):
            if len(self.packets) == 0:
                raise ValueError("Packet list cannot be empty")
            self.packet_list = list(self.packets)
            self.is_single_packet = False
        else:
            raise ValueError("Packets must be a Packet instance or list of Packets")
        
        # Initialize data structures
        self.packet_data: List[PacketData] = []
        self.global_field_index: Dict[str, List[Tuple[int, str]]] = {}  # field_key -> [(packet_idx, field_key)]
        
        # Processing statistics
        self.total_packets = len(self.packet_list)
        self.total_fields = 0
        self.fuzzable_field_count = 0
        self.excluded_field_count = 0
        self.layer_collision_count = 0
        
        # Processing state
        self.is_preprocessed = False
        self.preprocessing_errors: List[str] = []
        
        logger.info(f"MutatorManagerData initialized: {self.total_packets} packets, "
                   f"{self.iterations} iterations, single_packet={self.is_single_packet}")
    
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
        
        try:
            # CRITICAL: Create deep copies with iteration logic during preprocessing
            # USER REQUIREMENT: ITERATION MULTIPLICATION MUST HAPPEN DURING PREPROCESSING
            # DO NOT MOVE THIS LOGIC TO A LATER PHASE!
            self._create_packet_copies()
            
            # Process each packet to extract field metadata
            for packet_idx, packet in enumerate(self.packet_list):
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
            
        except Exception as e:
            error_msg = f"Preprocessing failed: {e}"
            self.preprocessing_errors.append(error_msg)
            logger.error(error_msg)
            raise
    
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
        
        ITERATION LOGIC APPLIED DURING PREPROCESSING:
        - Single packet + iterations: Create `iterations` copies of that packet
        - Packet list shorter than iterations: Cycle through list until we have `iterations` packets  
        - Packet list longer than iterations: Use only the first `iterations` packets
        - Single iteration: Use original packets as-is
        
        THIS MUST HAPPEN DURING PREPROCESSING - DO NOT CHANGE THIS AGAIN!
        """
        import copy
        
        # Normalize packets from config to a list
        if isinstance(self.fuzz_config.packets, list):
            self.original_packets = list(self.fuzz_config.packets)
        else:
            self.original_packets = [self.fuzz_config.packets]
        
        if not self.iterations or self.iterations <= 1:
            # Single iteration: use original packets as-is
            self.packet_list = [copy.deepcopy(pkt) for pkt in self.original_packets]
            logger.debug(f"Single iteration: created {len(self.packet_list)} packet copies")
            return
            
        # Multiple iterations: implement cycling logic DURING PREPROCESSING
        self.packet_list = []
        num_original = len(self.original_packets)
        
        for i in range(self.iterations):
            # Cycle through original packets using modulo
            packet_index = i % num_original
            self.packet_list.append(copy.deepcopy(self.original_packets[packet_index]))
        
        logger.debug(f"PREPROCESSING: Created {len(self.packet_list)} packet copies for {self.iterations} iterations "
                    f"(cycling through {num_original} original packets)")

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
            
            try:
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
                    
            except Exception as e:
                error_msg = f"Failed to process field {layer_name}[{layer_index}].{field_name}: {e}"
                self.preprocessing_errors.append(error_msg)
                logger.warning(error_msg)
                
                # Create minimal metadata for failed field
                field_key = self._generate_field_key(layer_name, field_name, layer_index)
                failed_field = FieldMetadata(
                    field_key=field_key,
                    layer_name=layer_name,
                    field_name=field_name,
                    layer_index=layer_index,
                    packet_index=packet_index,
                    field_type="unknown",
                    field_kind="unknown",
                    current_value=None,
                    is_fuzzable=False,
                    exclusion_reason=f"Processing error: {e}"
                )
                packet_data.fields[field_key] = failed_field
                packet_data.excluded_fields.append(field_key)
    
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
        try:
            from packetfuzz.utils.field_utils import get_field_type_chain
            
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
            
        except ImportError:
            # Fallback to field descriptor-based logic
            pass
        
        # Fallback logic using field descriptor
        field_desc = None
        for desc in layer.__class__.fields_desc:
            if desc.name == field_name:
                field_desc = desc
                break
        
        if field_desc:
            # Import here to avoid circular imports
            from scapy.fields import (BitField, FlagsField, EnumField, StrField, 
                                     IntField, ByteField, ShortField, IntEnumField)
            
            # Use same categorization logic as MutatorManager._build_field_info
            if isinstance(field_desc, (ByteField, ShortField, IntField, BitField)):
                return "numeric"
            elif isinstance(field_desc, StrField):
                return "string"
            elif isinstance(field_desc, (EnumField, IntEnumField)):
                return "enum"
            elif isinstance(field_desc, FlagsField):
                return "flags"
                
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
        try:
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
            from scapy.fields import (BitField, ByteField, ShortField, IntField, 
                                     EnumField, IntEnumField, StrField)
            
            # Numeric field constraints (consistent with MutatorManager._build_field_info)
            if isinstance(field_desc, BitField):
                bits = getattr(field_desc, 'size', 8)
                constraints['min_value'] = 0
                constraints['max_value'] = (1 << bits) - 1
            elif isinstance(field_desc, ByteField):
                constraints['min_value'] = 0
                constraints['max_value'] = 0xFF
            elif isinstance(field_desc, ShortField):
                constraints['min_value'] = 0
                constraints['max_value'] = 0xFFFF
            elif isinstance(field_desc, IntField):
                constraints['min_value'] = 0
                constraints['max_value'] = 0xFFFFFFFF
            
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
            
        except ImportError:
            # Fallback to original logic if utils not available
            return self._extract_field_constraints_fallback(layer, field_desc, layer_name, field_name)
    
    def _extract_field_constraints_fallback(self, layer: Packet, field_desc: Field, layer_name: str, field_name: str) -> Dict[str, Any]:
        """
        Fallback method for extracting field constraints when field_utils is unavailable.
        
        Args:
            layer: The packet layer containing the field
            field_desc: The field descriptor
            
        Returns:
            Dictionary of field constraints
        """
        constraints = {}
        
        # Basic field constraint extraction
        if hasattr(field_desc, 'fmt'):
            fmt = getattr(field_desc, 'fmt', None)
            if fmt:
                constraints['format'] = fmt
        
        if hasattr(field_desc, 'default'):
            default = getattr(field_desc, 'default', None)
            if default is not None:
                constraints['default'] = default
        
        # Length constraints
        if hasattr(field_desc, 'length_of'):
            length_of = getattr(field_desc, 'length_of', None)
            if length_of:
                constraints['length_of'] = length_of
        
        if hasattr(field_desc, 'max_len'):
            max_len = getattr(field_desc, 'max_len', None)
            if max_len:
                constraints['max_length'] = max_len
        
        return constraints
    
    def _resolve_field_configuration(self, field_metadata: FieldMetadata, 
                                    layer: Packet, dictionary_manager: Optional[Any]) -> None:
        """
        Centralized field configuration resolution with clear separation of concerns.
        
        This method orchestrates the three-phase configuration resolution:
        1. Collection: Gather all available configuration sources
        2. Calculation: Apply priority-based resolution logic  
        3. Application: Apply resolved configuration and handle side effects
        
        This separation makes the system more testable, maintainable, and debuggable.
        """
        # Phase 1: Data Collection - Pure data gathering, no business logic
        sources = self._collect_configuration_sources(field_metadata, layer, dictionary_manager)
        
        # Phase 2: Resolution & Calculation - Pure priority logic, no side effects
        # Phase 2: Calculate configuration priority and apply scaling
        resolved = self._resolve_configuration_priority(sources, layer)
        
        # Phase 3: Application - Apply configuration and handle side effects
        self._apply_resolved_configuration(field_metadata, layer, resolved, sources)
    
    def _collect_configuration_sources(self, field_metadata: FieldMetadata, 
                                      layer: Packet, dictionary_manager: Optional[Any]) -> ConfigurationSources:
        """
        Phase 1: Collect all available configuration sources.
        
        This is pure data collection with no business logic or side effects.
        Each source is collected independently and errors are captured.
        
        Args:
            field_metadata: Field to collect configuration for
            layer: Scapy layer containing the field
            dictionary_manager: DictionaryManager for configuration sources
            
        Returns:
            ConfigurationSources object with all collected data
        """
        sources = ConfigurationSources()
        
        # Default configuration (always available)
        sources.default_weight = self.fuzz_config.fuzz_weight
        
        # Dictionary Manager sources - separate priority 3 & 4
        if dictionary_manager:
            try:
                # Get separated dictionary manager sources
                advanced_config = self._get_advanced_manager_config(dictionary_manager, field_metadata)
                global_config = self._get_global_manager_config(dictionary_manager, field_metadata)
                
                # Priority 3: Advanced/campaign-level mapping
                if advanced_config['weight'] is not None:
                    sources.manager_weight = advanced_config['weight'] 
                    sources.manager_source_type = "advanced"
                if advanced_config['dictionaries']:
                    sources.manager_dictionaries = advanced_config['dictionaries']
                if advanced_config['values']:
                    sources.manager_values = advanced_config['values']
                
                # Priority 4: Global defaults (only if no advanced config)
                if sources.manager_weight is None and global_config['weight'] is not None:
                    sources.manager_weight = global_config['weight']
                    sources.manager_source_type = "global"
                if not sources.manager_dictionaries and global_config['dictionaries']:
                    sources.manager_dictionaries = global_config['dictionaries']
                if not sources.manager_values and global_config['values']:
                    sources.manager_values = global_config['values']
                    
            except Exception as e:
                sources.collection_errors.append(f"Dictionary manager error: {e}")
                sources.collection_successful = False
                logger.warning(f"Failed to collect dictionary manager configuration for {field_metadata.field_key}: {e}")
        
        # Embedded packet configuration (priority 2)
        if hasattr(layer, 'get_field_fuzz_config'):
            try:
                embedded_config = layer.get_field_fuzz_config(field_metadata.field_name)
                if embedded_config:
                    sources.embedded_weight = embedded_config.fuzz_weight
                    sources.embedded_dictionaries = embedded_config.dictionary.copy()
                    sources.embedded_values = embedded_config.default_values.copy()
            except Exception as e:
                sources.collection_errors.append(f"Embedded config error: {e}")
                logger.warning(f"Failed to collect embedded configuration for {field_metadata.field_key}: {e}")
        
        # FuzzField configuration (priority 1 - highest)
        field_value = getattr(layer, field_metadata.field_name, None)
        fuzzfield_config = self._extract_fuzzfield_configuration(field_value)
        if fuzzfield_config['is_fuzzfield']:
            sources.fuzzfield_weight = fuzzfield_config['fuzz_weight']
            sources.fuzzfield_dictionaries = fuzzfield_config['dictionaries']
            sources.fuzzfield_values = fuzzfield_config['values']
            sources.fuzzfield_mutators = fuzzfield_config['mutators']  # Legacy list
            sources.fuzzfield_mutator_weights = fuzzfield_config['mutator_weights']  # New dict
            sources.fuzzfield_scapy_weight = fuzzfield_config['scapy_fuzz_weight']
            sources.fuzzfield_dictionary_only_weight = fuzzfield_config['dictionary_only_weight']
            sources.fuzzfield_use_scapy_fuzz = fuzzfield_config['use_scapy_fuzz']
            sources.fuzzfield_dictionary_override = fuzzfield_config['dictionary_override']
            sources.fuzzfield_object = field_value  # Store for materialization
        
        return sources
    
    def _get_advanced_manager_config(self, dictionary_manager: Any, field_metadata: FieldMetadata) -> Dict[str, Any]:
        """
        Get Priority 3 configuration: Campaign-level advanced field mapping.
        
        CORRECTED: Uses DictionaryManager's advanced resolution methods directly on raw mappings,
        not on processed FieldMetadata. This preserves the proper collection phase logic.
        """
        from .default_mappings import FIELD_ADVANCED_WEIGHTS, FIELD_ADVANCED_DICTIONARIES
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name  
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        
        config = {'weight': None, 'dictionaries': [], 'values': []}
        properties = {'length': field_metadata.max_length, 'context': None}
        
        # Use DictionaryManager's advanced resolution methods directly on raw mappings
        if hasattr(dictionary_manager, '_resolve_advanced_weight'):
            adv_weight = dictionary_manager._resolve_advanced_weight(
                FIELD_ADVANCED_WEIGHTS,
                field_name=key,
                field_type=field_type,
                properties=properties,
                global_mode="override"
            )
            if adv_weight is not None:
                config['weight'] = adv_weight
        
        # Use DictionaryManager's advanced dictionary resolution
        if hasattr(dictionary_manager, '_resolve_advanced_dictionary'):
            adv_dictionaries = dictionary_manager._resolve_advanced_dictionary(
                FIELD_ADVANCED_DICTIONARIES.get(key, []) if isinstance(FIELD_ADVANCED_DICTIONARIES.get(key), list) else [],
                field_name=key,
                field_type=field_type,
                properties=properties,
                global_mode="merge"
            )
            if adv_dictionaries:
                resolved_paths = [dictionary_manager._resolve_path(path) for path in adv_dictionaries]
                config['dictionaries'] = resolved_paths
        
        # Use DictionaryManager's advanced values resolution
        if hasattr(dictionary_manager, '_resolve_advanced_values'):
            adv_values = dictionary_manager._resolve_advanced_values(
                FIELD_ADVANCED_DICTIONARIES.get(key, []) if isinstance(FIELD_ADVANCED_DICTIONARIES.get(key), list) else [],
                field_name=key,
                field_type=field_type,
                properties=properties,
                global_mode="override"
            )
            if adv_values:
                config['values'] = adv_values
        
        # Fallback to simple dictionary mapping if advanced resolution not available
        if not config['dictionaries'] and key in FIELD_ADVANCED_DICTIONARIES:
            adv_config = FIELD_ADVANCED_DICTIONARIES[key]
            
            # Handle dictionary configuration (dict format)
            if isinstance(adv_config, dict) and 'dictionaries' in adv_config:
                adv_dicts = adv_config['dictionaries']
                resolved_paths = [dictionary_manager._resolve_path(path) for path in adv_dicts]
                config['dictionaries'] = resolved_paths
                
                # Load dictionary entries as values
                try:
                    dict_entries = dictionary_manager.get_dictionary_entries(adv_dicts)
                    config['values'] = [entry.decode('utf-8', errors='ignore') for entry in dict_entries]
                except Exception:
                    pass
            
            # Handle direct values list (list format)
            elif isinstance(adv_config, list):
                config['values'] = adv_config.copy()
        
        return config
    
    def _get_global_manager_config(self, dictionary_manager: Any, field_metadata: FieldMetadata) -> Dict[str, Any]:
        """
        Get Priority 4 configuration: Global dictionary manager defaults.
        
        CORRECTED: Uses raw mapping lookups during collection phase, not processed FieldMetadata.
        This preserves name-based and type-based mapping logic during collection.
        """
        from .default_mappings import (FIELD_NAME_WEIGHTS, FIELD_TYPE_WEIGHTS, 
                                      FIELD_NAME_DICTIONARIES, FIELD_TYPE_DICTIONARIES)
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        
        config = {'weight': None, 'dictionaries': [], 'values': []}
        dictionary_paths = []
        
        # Check name-based weight (higher priority within global)
        if key in FIELD_NAME_WEIGHTS:
            config['weight'] = FIELD_NAME_WEIGHTS[key]
        # Check type-based weight (lower priority within global)
        elif field_type in FIELD_TYPE_WEIGHTS:
            config['weight'] = FIELD_TYPE_WEIGHTS[field_type]
        
        # Type-based dictionaries
        if field_type in FIELD_TYPE_DICTIONARIES:
            type_dicts = FIELD_TYPE_DICTIONARIES[field_type]
            for d in type_dicts:
                dictionary_paths.extend(dictionary_manager.expand_macro(d))
        
        # Name-based dictionaries
        if key in FIELD_NAME_DICTIONARIES:
            for d in FIELD_NAME_DICTIONARIES[key]:
                dictionary_paths.extend(dictionary_manager.expand_macro(d))
        
        # Resolve paths using DictionaryManager utilities
        if dictionary_paths:
            config['dictionaries'] = [dictionary_manager._resolve_path(path) for path in set(dictionary_paths)]
        
        return config
    
    def _resolve_field_weight(self, field_metadata: FieldMetadata, layer: Packet, 
                             dictionary_manager: Optional[Any]) -> float:
        """
        Centralized weight resolution with proper priority handling.
        
        Priority Order (highest to lowest):
        1. FuzzField configuration
        2. Embedded packet configuration  
        3. Advanced mapping (campaign/user overrides)
        4. Name-based mapping
        5. Type-based mapping
        6. Default fallback
        
        Args:
            field_metadata: Field to resolve weight for
            layer: Scapy layer containing the field
            dictionary_manager: DictionaryManager for mapping operations
            
        Returns:
            Resolved weight value
        """
        from .default_mappings import FIELD_ADVANCED_WEIGHTS, FIELD_NAME_WEIGHTS, FIELD_TYPE_WEIGHTS
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        properties = {'length': field_metadata.max_length, 'context': None}
        
        # Priority 1: FuzzField configuration (highest)
        field_value = getattr(layer, field_name, None)
        fuzzfield_config = self._extract_fuzzfield_configuration(field_value)
        if fuzzfield_config['is_fuzzfield'] and fuzzfield_config['fuzz_weight'] is not None:
            return fuzzfield_config['fuzz_weight']
        
        # Priority 2: Embedded packet configuration
        if hasattr(layer, 'get_field_fuzz_config'):
            try:
                embedded_config = layer.get_field_fuzz_config(field_name)
                if embedded_config and embedded_config.fuzz_weight is not None:
                    return embedded_config.fuzz_weight
            except Exception:
                pass
        
        # Priority 3: Advanced mapping (campaign/user overrides)
        if dictionary_manager and hasattr(dictionary_manager, '_resolve_advanced_weight'):
            adv_weight = dictionary_manager._resolve_advanced_weight(
                FIELD_ADVANCED_WEIGHTS, field_name=key, field_type=field_type, 
                properties=properties, global_mode="override"
            )
            if adv_weight is not None:
                return adv_weight
        
        # Priority 4: Name-based mapping
        if key in FIELD_NAME_WEIGHTS:
            return FIELD_NAME_WEIGHTS[key]
        
        # Priority 5: Type-based mapping
        if field_type in FIELD_TYPE_WEIGHTS:
            return FIELD_TYPE_WEIGHTS[field_type]
        
        # Priority 6: Default fallback
        return self.fuzz_config.fuzz_weight  # Campaign default weight
    
    def _resolve_field_dictionaries(self, field_metadata: FieldMetadata, layer: Packet,
                                   dictionary_manager: Optional[Any]) -> List[str]:
        """
        Centralized dictionary resolution with proper priority handling.
        
        Priority Order (highest to lowest):
        1. FuzzField configuration
        2. Embedded packet configuration
        3. Advanced mapping (campaign/user overrides)  
        4. Name-based mapping
        5. Type-based mapping
        
        Args:
            field_metadata: Field to resolve dictionaries for
            layer: Scapy layer containing the field
            dictionary_manager: DictionaryManager for mapping operations
            
        Returns:
            List of resolved dictionary file paths
        """
        from .default_mappings import (FIELD_ADVANCED_DICTIONARIES, FIELD_NAME_DICTIONARIES, 
                                      FIELD_TYPE_DICTIONARIES)
        
        field_name = field_metadata.field_name
        layer_name = field_metadata.layer_name
        field_type = field_metadata.field_type
        key = f"{layer_name}.{field_name}"
        properties = {'length': field_metadata.max_length, 'context': None}
        
        dictionary_paths = []
        
        # Priority 1: FuzzField configuration (highest)
        field_value = getattr(layer, field_name, None)
        fuzzfield_config = self._extract_fuzzfield_configuration(field_value)
        if fuzzfield_config['is_fuzzfield']:
            if fuzzfield_config['dictionaries']:
                # If FuzzField has dictionary override, use only those
                if fuzzfield_config['dictionary_override']:
                    if dictionary_manager:
                        return [dictionary_manager._resolve_path(path) for path in fuzzfield_config['dictionaries']]
                    return fuzzfield_config['dictionaries']
                else:
                    dictionary_paths.extend(fuzzfield_config['dictionaries'])
        
        # Priority 2: Embedded packet configuration
        if hasattr(layer, 'get_field_fuzz_config'):
            try:
                embedded_config = layer.get_field_fuzz_config(field_name)
                if embedded_config and embedded_config.dictionary:
                    dictionary_paths.extend(embedded_config.dictionary)
            except Exception:
                pass
        
        # Priority 3: Advanced mapping (campaign/user overrides)
        if dictionary_manager and hasattr(dictionary_manager, '_resolve_advanced_dictionary'):
            # Get advanced mappings for this field from constants
            adv_mappings = FIELD_ADVANCED_DICTIONARIES.get(key, [])
            if adv_mappings:
                adv_dicts = dictionary_manager._resolve_advanced_dictionary(
                    adv_mappings, field_name=key, field_type=field_type, 
                    properties=properties, global_mode="merge"
                )
                if adv_dicts:
                    dictionary_paths.extend(adv_dicts)

        # Use existing name and type based mapping from constants
        if key in FIELD_NAME_DICTIONARIES:
            for d in FIELD_NAME_DICTIONARIES[key]:
                if dictionary_manager:
                    dictionary_paths.extend(dictionary_manager.expand_macro(d))
                else:
                    dictionary_paths.append(d)

        if field_type in FIELD_TYPE_DICTIONARIES:
            type_dicts = FIELD_TYPE_DICTIONARIES[field_type]
            for d in type_dicts:
                if dictionary_manager:
                    dictionary_paths.extend(dictionary_manager.expand_macro(d))
                else:
                    dictionary_paths.append(d)

        # Remove duplicates and resolve paths
        unique_paths = list(dict.fromkeys(dictionary_paths))
        if dictionary_manager:
            return [dictionary_manager._resolve_path(path) for path in unique_paths]
        return unique_paths

    def _calculate_layer_depth(self, layer):
        """
        Calculate the depth of a layer from the innermost layer.
        Uses consolidated utility for layer depth calculation.
        
        Returns:
            int: Depth below the current layer (0 = innermost, 1+ = outer layers)
        """
        try:
            from packetfuzz.utils.field_utils import calculate_layer_depth_below
            return calculate_layer_depth_below(layer)
        except ImportError:
            # Fallback to local implementation if utility not available
            depth_below = 0
            cursor = layer
            while hasattr(cursor, 'payload') and not isinstance(cursor.payload, NoPayload):
                depth_below += 1
                cursor = cursor.payload
            return depth_below
    
    def _resolve_field_mutator_weights(self, sources: ConfigurationSources, layer: Packet) -> Dict[str, float]:
        """
        Resolve mutator weights for a field from default mappings.
        
        Args:
            sources: Configuration sources collected for this field
            layer: The packet layer containing the field
            
        Returns:
            Dict mapping mutator names to weights
        """
        # Import the default mappings
        try:
            from .default_mappings import (
                FIELD_TYPE_MUTATOR_WEIGHTS, 
                FIELD_NAME_MUTATOR_WEIGHTS, 
                FIELD_ADVANCED_MUTATOR_WEIGHTS
            )
        except ImportError:
            return {}
        
        # Extract field information for lookup
        field_name = getattr(sources, 'manager_source_type', None) or "unknown"
        field_type = getattr(layer, '__class__', object).__name__
        layer_name = layer.__class__.__name__
        
        # Build field key similar to how it's done elsewhere
        key = f"{layer_name}.{field_name}"
        
        # Priority 1: Advanced mappings (most specific)
        for rule in FIELD_ADVANCED_MUTATOR_WEIGHTS:
            condition = rule.get('condition', {})
            
            # Check layer name condition
            if 'layer_name' in condition and condition['layer_name'] != layer_name:
                continue
                
            # Check field name contains condition
            if 'field_name_contains' in condition:
                if condition['field_name_contains'].lower() not in field_name.lower():
                    continue
                    
            # Check field type condition
            if 'field_type' in condition and condition['field_type'] != field_type:
                continue
                
            # If all conditions match, return the mutator weights
            return rule.get('mutator_weights', {}).copy()
        
        # Priority 2: Name-based mapping
        if key in FIELD_NAME_MUTATOR_WEIGHTS:
            return FIELD_NAME_MUTATOR_WEIGHTS[key].copy()
        
        # Priority 3: Type-based mapping
        if field_type in FIELD_TYPE_MUTATOR_WEIGHTS:
            return FIELD_TYPE_MUTATOR_WEIGHTS[field_type].copy()
        
        # Priority 4: Campaign-level default (if available)
        if hasattr(self.fuzz_config, 'mutator_preference') and isinstance(self.fuzz_config.mutator_preference, dict):
            return self.fuzz_config.mutator_preference.copy()
        elif hasattr(self.fuzz_config, 'mutator_preference') and isinstance(self.fuzz_config.mutator_preference, list):
            # Convert list to equal weights
            if self.fuzz_config.mutator_preference:
                equal_weight = 1.0 / len(self.fuzz_config.mutator_preference)
                return {mutator: equal_weight for mutator in self.fuzz_config.mutator_preference}
        
        # Priority 5: Fallback to libfuzzer
        return {"libfuzzer": 1.0}
    
    def _apply_layer_weight_scaling(self, base_weight: float, layer: Packet) -> Tuple[float, float]:
        """
        Apply layer weight scaling to the base weight.
        
        Args:
            base_weight: Original weight before scaling
            layer: Scapy layer for depth calculation
            
        Returns:
            Tuple[scaled_weight, scaling_factor]: The scaled weight and the scaling factor applied
        """
        # Check if layer weight scaling is enabled
        if not getattr(self.fuzz_config, 'enable_layer_weight_scaling', True):
            return base_weight, 1.0
        
        # Get layer scaling factor from config or default
        layer_scaling_factor = getattr(self.fuzz_config, 'layer_weight_scaling', None)
        if layer_scaling_factor is None:
            # Import default scaling constant
            try:
                from .default_mappings import LAYER_WEIGHT_SCALING
                layer_scaling_factor = LAYER_WEIGHT_SCALING
            except ImportError:
                layer_scaling_factor = 0.5  # Fallback default
        
        # Calculate depth and apply scaling
        depth_below = self._calculate_layer_depth(layer)
        
        # Apply scaling: base * (scale ** depth_below)
        # Lower scale means outer layers (higher depth_below) get reduced more
        if isinstance(layer_scaling_factor, (int, float)) and layer_scaling_factor > 0:
            scaling_multiplier = layer_scaling_factor ** depth_below
            scaled_weight = base_weight * scaling_multiplier
            return scaled_weight, scaling_multiplier
        
        return base_weight, 1.0
    
    def _apply_campaign_scaling(self, weight: float) -> Tuple[float, float]:
        """
        Apply campaign-level weight scaling.
        
        Args:
            weight: Weight before campaign scaling
            
        Returns:
            Tuple[scaled_weight, scaling_factor]: The scaled weight and the scaling factor applied
        """
        campaign_scaling_factor = getattr(self.fuzz_config, 'fuzz_weight_scale', 1.0)
        
        if isinstance(campaign_scaling_factor, (int, float)) and campaign_scaling_factor > 0:
            scaled_weight = weight * campaign_scaling_factor
            return scaled_weight, campaign_scaling_factor
        
        return weight, 1.0
    
    def _resolve_configuration_priority(self, sources: ConfigurationSources, layer: Packet) -> ResolvedConfiguration:
        """
        Phase 2: Apply priority-based resolution logic.
        
        This is pure calculation logic with no side effects. The priority system
        is clearly implemented with explicit precedence rules.
        
        Priority levels (highest to lowest):
        1. FuzzField configuration (inline packet field config)
        2. Embedded packet field configuration (field_fuzz())
        3. Campaign-level advanced field mapping (via dictionary manager)
        4. Global dictionary manager defaults (name/type-based)
        5. FuzzConfig fallback defaults
        
        Args:
            sources: All collected configuration sources
            
        Returns:
            ResolvedConfiguration with final calculated values
        """
        resolved = ResolvedConfiguration(
            final_weight=sources.default_weight,
            final_dictionaries=[],
            final_values=[],
            config_source="default",
            priority_level=5
        )
        
        # Apply sources in reverse priority order (lowest to highest)
        
        # Priority 5: Default (already applied above)
        
        # Priority 4: Global dictionary manager defaults (only if advanced didn't provide)
        if sources.manager_weight is not None and sources.manager_source_type == "global":
            resolved.final_weight = sources.manager_weight
            resolved.config_source = "dictionary_manager"  # Simplified for backward compatibility
            resolved.priority_level = 4
            resolved.resolution_notes.append("Applied global dictionary manager weight")
        
        if sources.manager_dictionaries and sources.manager_source_type == "global":
            resolved.final_dictionaries = sources.manager_dictionaries.copy()
            resolved.resolution_notes.append("Applied global dictionary manager dictionaries")
        
        if sources.manager_values and sources.manager_source_type == "global":
            resolved.final_values = sources.manager_values.copy()
            resolved.resolution_notes.append("Applied global dictionary manager values")
        
        # Priority 3: Advanced/campaign-level dictionary manager configuration
        if sources.manager_weight is not None and sources.manager_source_type == "advanced":
            resolved.final_weight = sources.manager_weight
            resolved.config_source = "dictionary_manager"  # Simplified for backward compatibility
            resolved.priority_level = 3
            resolved.resolution_notes.append("Applied advanced dictionary manager weight")
        
        if sources.manager_dictionaries and sources.manager_source_type == "advanced":
            resolved.final_dictionaries = sources.manager_dictionaries.copy()
            resolved.resolution_notes.append("Applied advanced dictionary manager dictionaries")
        
        if sources.manager_values and sources.manager_source_type == "advanced":
            resolved.final_values = sources.manager_values.copy()
            resolved.resolution_notes.append("Applied advanced dictionary manager values")
        
        # Priority 2: Embedded configuration
        if sources.embedded_weight is not None:
            resolved.final_weight = sources.embedded_weight
            resolved.final_dictionaries = sources.embedded_dictionaries.copy()
            resolved.final_values = sources.embedded_values.copy()
            resolved.config_source = "embedded"
            resolved.priority_level = 2
            resolved.resolution_notes.append("Applied embedded configuration")
        
        # Priority 1: FuzzField configuration (highest)
        if sources.fuzzfield_weight is not None:
            resolved.final_weight = sources.fuzzfield_weight
            resolved.config_source = "fuzzfield"
            resolved.priority_level = 1
            resolved.resolution_notes.append("Applied FuzzField weight")
        
        if sources.fuzzfield_dictionaries:
            # Handle dictionary override vs merge
            if sources.fuzzfield_dictionary_override:
                resolved.final_dictionaries = sources.fuzzfield_dictionaries.copy()
                resolved.resolution_notes.append("FuzzField dictionaries (override)")
            else:
                # Merge with existing
                existing_set = set(resolved.final_dictionaries)
                fuzzfield_set = set(sources.fuzzfield_dictionaries)
                resolved.final_dictionaries = list(existing_set.union(fuzzfield_set))
                resolved.resolution_notes.append("FuzzField dictionaries (merged)")
        
        if sources.fuzzfield_values:
            resolved.final_values = sources.fuzzfield_values.copy()
            resolved.resolution_notes.append("Applied FuzzField values")
        
        # Apply FuzzField-specific properties
        if sources.fuzzfield_scapy_weight is not None:
            resolved.scapy_fuzz_weight = sources.fuzzfield_scapy_weight
        if sources.fuzzfield_dictionary_only_weight is not None:
            resolved.dictionary_only_weight = sources.fuzzfield_dictionary_only_weight
        if sources.fuzzfield_use_scapy_fuzz is not None:
            resolved.use_scapy_fuzz = sources.fuzzfield_use_scapy_fuzz
        if sources.fuzzfield_mutators:
            resolved.mutator_preferences = sources.fuzzfield_mutators.copy()
        if sources.fuzzfield_mutator_weights:
            resolved.mutator_weights = sources.fuzzfield_mutator_weights.copy()
            resolved.resolution_notes.append("Applied FuzzField mutator weights")
        else:
            # Resolve mutator weights from default mappings
            resolved.mutator_weights = self._resolve_field_mutator_weights(sources, layer)
            if resolved.mutator_weights:
                resolved.resolution_notes.append("Applied default mutator weights")
        
        # === WEIGHT SCALING PHASE ===
        # Apply layer weight scaling first, then campaign scaling
        
        # Store the base weight before any scaling
        resolved.base_weight = resolved.final_weight
        
        # Apply layer weight scaling
        layer_scaled_weight, layer_scaling_factor = self._apply_layer_weight_scaling(
            resolved.final_weight, layer
        )
        resolved.layer_scaled_weight = layer_scaled_weight
        resolved.layer_scaling_factor = layer_scaling_factor
        
        # Apply campaign scaling
        campaign_scaled_weight, campaign_scaling_factor = self._apply_campaign_scaling(
            layer_scaled_weight
        )
        resolved.campaign_scaled_weight = campaign_scaled_weight
        resolved.campaign_scaling_factor = campaign_scaling_factor
        
        # Calculate final scaling factor and update final weight
        resolved.final_scaling_factor = layer_scaling_factor * campaign_scaling_factor
        resolved.final_weight = campaign_scaled_weight
        
        # Add resolution notes for scaling
        if layer_scaling_factor != 1.0:
            resolved.resolution_notes.append(f"Applied layer scaling: {layer_scaling_factor:.3f}")
        if campaign_scaling_factor != 1.0:
            resolved.resolution_notes.append(f"Applied campaign scaling: {campaign_scaling_factor:.3f}")
        if resolved.final_scaling_factor != 1.0:
            resolved.resolution_notes.append(f"Total scaling: {resolved.final_scaling_factor:.3f}")
        
        return resolved
    
    def _apply_resolved_configuration(self, field_metadata: FieldMetadata, layer: Packet, 
                                     resolved: ResolvedConfiguration, sources: ConfigurationSources) -> None:
        """
        Phase 3: Apply resolved configuration and handle side effects.
        
        This phase takes the calculated configuration and applies it to the field metadata.
        It also handles FuzzField materialization and other side effects.
        
        Args:
            field_metadata: FieldMetadata to update
            layer: Scapy layer for FuzzField materialization
            resolved: Final resolved configuration
            sources: Original sources (for FuzzField materialization)
        """
        # Apply resolved configuration to field metadata
        field_metadata.fuzz_weight = resolved.final_weight
        field_metadata.dictionary_paths = resolved.final_dictionaries
        field_metadata.default_values = resolved.final_values
        field_metadata.config_source = resolved.config_source
        
        # Apply weight tracking information
        field_metadata.base_weight = resolved.base_weight
        field_metadata.layer_scaled_weight = resolved.layer_scaled_weight
        field_metadata.campaign_scaled_weight = resolved.campaign_scaled_weight
        field_metadata.layer_scaling_factor = resolved.layer_scaling_factor
        field_metadata.campaign_scaling_factor = resolved.campaign_scaling_factor
        field_metadata.final_scaling_factor = resolved.final_scaling_factor
        
        # Apply FuzzField-specific properties if available
        if resolved.scapy_fuzz_weight is not None:
            field_metadata.scapy_fuzz_weight = resolved.scapy_fuzz_weight
        if resolved.dictionary_only_weight is not None:
            field_metadata.dictionary_only_weight = resolved.dictionary_only_weight
        if resolved.use_scapy_fuzz is not None:
            field_metadata.use_scapy_fuzz = resolved.use_scapy_fuzz
        if resolved.mutator_preferences:
            field_metadata.mutator_preferences = resolved.mutator_preferences
        if resolved.mutator_weights:
            field_metadata.mutator_weights = resolved.mutator_weights
        
        # Handle FuzzField materialization (side effect)
        if sources.fuzzfield_object is not None:
            self._materialize_fuzzfield_in_packet(layer, field_metadata.field_name, sources.fuzzfield_object)
        
        # Determine if field is fuzzable
        field_metadata.is_fuzzable = (
            field_metadata.fuzz_weight > 0 and 
            field_metadata.field_kind != "unknown"
        )
        
        # Set exclusion reason if not fuzzable
        if not field_metadata.is_fuzzable and not field_metadata.exclusion_reason:
            if field_metadata.fuzz_weight <= 0:
                field_metadata.exclusion_reason = "Zero fuzz weight"
            elif field_metadata.field_kind == "unknown":
                field_metadata.exclusion_reason = "Unknown field type"
        
        # Debug logging
        logger.debug(f"Applied config for {field_metadata.field_key}: "
                    f"weight={field_metadata.fuzz_weight}, "
                    f"dictionaries={len(field_metadata.dictionary_paths)}, "
                    f"values={len(field_metadata.default_values)}, "
                    f"source={resolved.config_source} (priority {resolved.priority_level})")
        
        if resolved.resolution_notes:
            logger.debug(f"Resolution notes for {field_metadata.field_key}: {', '.join(resolved.resolution_notes)}")
    
    def _materialize_fuzzfield_in_packet(self, layer: Packet, field_name: str, fuzzfield_object: Any) -> None:
        """
        Replace FuzzField with a chosen value in the packet layer.
        
        This is separated from the main configuration logic to clearly isolate
        side effects (packet modification) from pure configuration calculation.
        """
        try:
            chosen_value = fuzzfield_object.choose_value()
            if chosen_value is not None:
                setattr(layer, field_name, chosen_value)
                logger.debug(f"Materialized FuzzField {field_name} to value: {chosen_value}")
            else:
                # If no value chosen, remove the attribute to let Scapy resolve defaults
                if hasattr(layer, field_name):
                    delattr(layer, field_name)
                    logger.debug(f"Removed FuzzField {field_name} attribute (no value chosen)")
        except Exception as e:
            logger.warning(f"Failed to materialize FuzzField {field_name}: {e}")
            # Leave the field as-is on error
    
    def _extract_fuzzfield_configuration(self, field_value: Any) -> Dict[str, Any]:
        """
        Extract configuration from a FuzzField object if present.
        
        Returns a dictionary with FuzzField configuration or empty config if not a FuzzField.
        """
        # Import FuzzField
        try:
            from .fuzzing_framework import FuzzField
        except ImportError:
            try:
                from fuzzing_framework import FuzzField
            except ImportError:
                return {'is_fuzzfield': False}
        
        if not isinstance(field_value, FuzzField):
            return {'is_fuzzfield': False}
        
        return {
            'is_fuzzfield': True,
            'values': field_value.values or [],
            'dictionaries': field_value.dictionaries or [],
            'fuzz_weight': field_value.fuzz_weight,
            'mutators': list(field_value.mutators.keys()) if isinstance(field_value.mutators, dict) else [],  # Legacy list for compatibility
            'mutator_weights': field_value.mutators if isinstance(field_value.mutators, dict) else {},  # New dict format
            'scapy_fuzz_weight': field_value.scapy_fuzz_weight,
            'dictionary_only_weight': field_value.dictionary_only_weight,
            'use_scapy_fuzz': field_value.use_scapy_fuzz,
            'dictionary_override': getattr(field_value, 'dictionary_override', False)
        }
    
    def _build_global_field_index(self) -> None:
        """Build global index for cross-packet field analysis."""
        for packet_data in self.packet_data:
            for field_key, field_metadata in packet_data.fields.items():
                if field_key not in self.global_field_index:
                    self.global_field_index[field_key] = []
                self.global_field_index[field_key].append(
                    (packet_data.packet_index, field_key)
                )
    
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
        import copy
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
                try:
                    s = v.decode('utf-8', errors='ignore').strip()
                except Exception:
                    return None
            elif isinstance(v, str):
                s = v.strip()
            if s is None or s == "":
                return None
            try:
                if s.lower().startswith(("0x", "+0x", "-0x")):
                    return int(s, 16)
                return int(s, 10)
            except Exception:
                return None
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
            'creation_time': self.creation_time.isoformat(),
            'single_packet_mode': self.is_single_packet
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
            else:
                field_metadata.failed_mutations += 1
            field_metadata.last_mutated = datetime.now()
    
    def __str__(self) -> str:
        return (f"MutatorManagerData({self.total_packets} packets, "
                f"{self.total_fields} fields, {self.fuzzable_field_count} fuzzable)")
    
    def __repr__(self) -> str:
        return (f"MutatorManagerData(packets={self.total_packets}, "
                f"fields={self.total_fields}, fuzzable={self.fuzzable_field_count}, "
                f"iterations={self.iterations}, preprocessed={self.is_preprocessed})")
    
    def get_final_field_weight(self, field_key: str, packet_index: int = 0) -> float:
        """
        Get the final effective weight for a field, including all scaling factors.
        
        Args:
            field_key: The field identifier (e.g., "IP[0].dst")
            packet_index: Index of the packet containing the field
            
        Returns:
            Final effective weight for the field (0.0 to 1.0)
        """
        field_metadata = self.get_field_by_key(field_key, packet_index)
        if not field_metadata:
            return 0.0
            
        if not field_metadata.is_fuzzable:
            return 0.0
            
        # Start with base field weight
        weight = field_metadata.fuzz_weight
        
        # Apply global weight scaling
        weight *= self.fuzz_config.fuzz_weight_scale
        
        # Apply layer-based scaling if enabled
        if self.fuzz_config.enable_layer_weight_scaling:
            # Use layer_index as a proxy for layer distance
            # Higher layer_index means further from innermost layer
            layer_distance = field_metadata.layer_index
            
            if self.fuzz_config.layer_weight_scaling is not None:
                # Custom layer scaling factor
                scaling_factor = self.fuzz_config.layer_weight_scaling ** layer_distance
            else:
                # Default layer scaling (inner layers get higher weight)
                # Distance 0 = innermost layer (full weight), distance increases outward
                scaling_factor = 0.8 ** layer_distance
            weight *= scaling_factor
        
        # Ensure weight stays in valid range
        return max(0.0, min(1.0, weight))
