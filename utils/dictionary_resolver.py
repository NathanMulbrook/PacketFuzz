#!/usr/bin/env python3
"""
Dictionary Resolver - Standalone Utility

This utility resolves all dictionary mappings from the default_mappings.py file,
expands macros, and outputs the complete resolved dictionaries to files for inspection.

Usage: python dictionary_resolver.py
Output: Files in artifacts/dictionary_analysis/
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime

# Add the project root to the path so we can import the mappings
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from packetfuzz.default_mappings import (
        MACROS, 
        FIELD_TYPE_DICTIONARIES, 
        FIELD_NAME_DICTIONARIES,
        FIELD_ADVANCED_DICTIONARIES
    )
except ImportError as e:
    print(f"Error importing mappings: {e}")
    sys.exit(1)


class DictionaryResolver:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.output_dir = project_root / "artifacts" / "dictionary_analysis"
        self.resolved_macros = {}
        self.missing_files = set()
        self.macro_dependencies = {}
        self.deduplication_stats = {}  # Track original vs deduplicated counts
        
    def setup_output_dir(self):
        """Create output directory structure"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {self.output_dir}")
        
    def check_file_exists(self, file_path: str) -> bool:
        """Check if a dictionary file exists"""
        full_path = self.project_root / file_path
        return full_path.exists()
        
    def load_dictionary_file(self, file_path: str) -> List[str]:
        """Load lines from a dictionary file"""
        full_path = self.project_root / file_path
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for line in f:
                    line = line.strip()
                    # Skip empty lines, comments, and lines that are just whitespace
                    if line and not line.startswith('#') and not line.startswith('//'):
                        lines.append(line)
                return lines
        except (OSError, IOError, UnicodeDecodeError) as e:
            print(f"Warning: Could not load {file_path}: {e}")
            self.missing_files.add(file_path)
            return []
            
    def deduplicate_preserving_order(self, items: List[str], context: str = "") -> List[str]:
        """Remove duplicates while preserving order and tracking statistics"""
        seen = set()
        unique_items = []
        original_count = len(items)
        
        for item in items:
            # Normalize whitespace and skip empty entries
            normalized = item.strip()
            if normalized and normalized not in seen:
                unique_items.append(normalized)
                seen.add(normalized)
                
        deduplicated_count = len(unique_items)
        if context and original_count > deduplicated_count:
            self.deduplication_stats[context] = {
                'original': original_count,
                'deduplicated': deduplicated_count,
                'saved': original_count - deduplicated_count
            }
            
        return unique_items
        
    def resolve_macro(self, macro_name: str, visited: Set[str] = None) -> List[str]:
        """Resolve a macro, handling circular dependencies"""
        if visited is None:
            visited = set()
            
        if macro_name in visited:
            print(f"Warning: Circular dependency detected for macro {macro_name}")
            return []
            
        if macro_name in self.resolved_macros:
            return self.resolved_macros[macro_name]
            
        visited.add(macro_name)
        resolved_entries = []
        
        if macro_name not in MACROS:
            print(f"Warning: Macro {macro_name} not found in MACROS")
            return []
            
        for entry in MACROS[macro_name]:
            if entry.startswith('@'):
                # This is another macro reference
                sub_macro = entry[1:]  # Remove @ prefix
                self.macro_dependencies.setdefault(macro_name, set()).add(sub_macro)
                resolved_entries.extend(self.resolve_macro(sub_macro, visited.copy()))
            else:
                # This is a file path
                if self.check_file_exists(entry):
                    resolved_entries.extend(self.load_dictionary_file(entry))
                else:
                    print(f"Warning: File not found: {entry}")
                    self.missing_files.add(entry)
                    
        # Deduplicate at the macro level
        resolved_entries = self.deduplicate_preserving_order(resolved_entries, f"macro_{macro_name}")
        self.resolved_macros[macro_name] = resolved_entries
        return resolved_entries
        
    def resolve_field_mapping(self, field_name: str, dictionary_list: List[str]) -> List[str]:
        """Resolve a field mapping that may contain macros and file paths"""
        resolved_entries = []
        
        for entry in dictionary_list:
            if entry.startswith('@'):
                # This is a macro reference
                macro_name = entry[1:]  # Remove @ prefix
                resolved_entries.extend(self.resolve_macro(macro_name))
            else:
                # This is a file path
                if self.check_file_exists(entry):
                    resolved_entries.extend(self.load_dictionary_file(entry))
                else:
                    print(f"Warning: File not found for field {field_name}: {entry}")
                    self.missing_files.add(entry)
                    
        # Deduplicate at the field mapping level
        return self.deduplicate_preserving_order(resolved_entries, f"field_{field_name}")
        
    def analyze_macros(self):
        """Analyze and resolve all macros"""
        print("Analyzing macros...")
        
        macro_analysis = {}
        for macro_name in MACROS:
            print(f"  Resolving macro: @{macro_name}")
            resolved = self.resolve_macro(macro_name)
            
            # Additional deduplication to ensure clean results  
            unique_resolved = self.deduplicate_preserving_order(resolved, f"final_macro_{macro_name}")
                    
            macro_analysis[macro_name] = {
                'count': len(unique_resolved),
                'entries': unique_resolved,
                'dependencies': list(self.macro_dependencies.get(macro_name, [])),
                'raw_definition': MACROS[macro_name]
            }
            
        return macro_analysis
        
    def analyze_field_mappings(self, mappings: Dict, mapping_type: str):
        """Analyze field mappings"""
        print(f"Analyzing {mapping_type}...")
        
        field_analysis = {}
        for field_name, dictionary_list in mappings.items():
            print(f"  Resolving field: {field_name}")
            resolved = self.resolve_field_mapping(field_name, dictionary_list)
            
            # Additional deduplication to ensure clean results
            unique_resolved = self.deduplicate_preserving_order(resolved, f"final_field_{field_name}")
                    
            field_analysis[field_name] = {
                'count': len(unique_resolved),
                'entries': unique_resolved,
                'raw_definition': dictionary_list
            }
            
        return field_analysis
        
    def write_analysis_files(self, macro_analysis, type_analysis, name_analysis, advanced_analysis):
        """Write analysis results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Write macro analysis
        macro_file = self.output_dir / f"macro_analysis_{timestamp}.json"
        with open(macro_file, 'w') as f:
            json.dump(macro_analysis, f, indent=2)
        print(f"Macro analysis written to: {macro_file}")
        
        # Write field type analysis
        type_file = self.output_dir / f"field_type_analysis_{timestamp}.json"
        with open(type_file, 'w') as f:
            json.dump(type_analysis, f, indent=2)
        print(f"Field type analysis written to: {type_file}")
        
        # Write field name analysis
        name_file = self.output_dir / f"field_name_analysis_{timestamp}.json"
        with open(name_file, 'w') as f:
            json.dump(name_analysis, f, indent=2)
        print(f"Field name analysis written to: {name_file}")
        
        # Write advanced analysis
        advanced_file = self.output_dir / f"field_advanced_analysis_{timestamp}.json"
        with open(advanced_file, 'w') as f:
            json.dump(advanced_analysis, f, indent=2)
        print(f"Field advanced analysis written to: {advanced_file}")
        
        # Write summary report
        self.write_summary_report(macro_analysis, type_analysis, name_analysis, advanced_analysis, timestamp)
        
        # Write individual dictionary files
        self.write_individual_dictionaries(macro_analysis, type_analysis, name_analysis, timestamp)
        
    def write_summary_report(self, macro_analysis, type_analysis, name_analysis, advanced_analysis, timestamp):
        """Write a human-readable summary report"""
        summary_file = self.output_dir / f"dictionary_summary_{timestamp}.txt"
        
        with open(summary_file, 'w') as f:
            f.write("PacketFuzz Dictionary Analysis Summary\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("Note: All entries are deduplicated while preserving order\n\n")
            
            # Macro summary
            f.write("MACRO SUMMARY\n")
            f.write("-" * 20 + "\n")
            total_macro_entries = 0
            # Sort macros by entry count (descending)
            sorted_macros = sorted(macro_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
            for macro_name, info in sorted_macros:
                f.write(f"@{macro_name}: {info['count']} entries\n")
                total_macro_entries += info['count']
                if info['dependencies']:
                    f.write(f"  Dependencies: {', '.join('@' + dep for dep in info['dependencies'])}\n")
            f.write(f"\nTotal macros: {len(macro_analysis)}\n")
            f.write(f"Total deduplicated entries across all macros: {total_macro_entries}\n\n")
            
            # Field type summary
            f.write("FIELD TYPE MAPPINGS SUMMARY\n")
            f.write("-" * 30 + "\n")
            total_type_entries = 0
            # Sort field types by entry count (descending)
            sorted_types = sorted(type_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
            for field_type, info in sorted_types:
                f.write(f"{field_type}: {info['count']} entries\n")
                total_type_entries += info['count']
            f.write(f"\nTotal field types: {len(type_analysis)}\n")
            f.write(f"Total deduplicated entries: {total_type_entries}\n\n")
            
            # Field name summary
            f.write("FIELD NAME MAPPINGS SUMMARY\n")
            f.write("-" * 30 + "\n")
            total_name_entries = 0
            # Sort field names by entry count (descending)
            sorted_names = sorted(name_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
            for field_name, info in sorted_names:
                f.write(f"{field_name}: {info['count']} entries\n")
                total_name_entries += info['count']
            f.write(f"\nTotal field names: {len(name_analysis)}\n")
            f.write(f"Total deduplicated entries: {total_name_entries}\n\n")
            
            # Advanced mappings summary
            f.write("ADVANCED MAPPINGS SUMMARY\n")
            f.write("-" * 25 + "\n")
            if advanced_analysis:
                total_advanced_entries = 0
                # Sort advanced mappings by entry count (descending)
                sorted_advanced = sorted(advanced_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
                for field_name, info in sorted_advanced:
                    f.write(f"{field_name}: {info['count']} entries\n")
                    total_advanced_entries += info['count']
                f.write(f"\nTotal advanced mappings: {len(advanced_analysis)}\n")
                f.write(f"Total deduplicated entries: {total_advanced_entries}\n\n")
            else:
                f.write("No advanced mappings defined.\n\n")
            
            # Missing files
            if self.missing_files:
                f.write("MISSING FILES\n")
                f.write("-" * 15 + "\n")
                for missing_file in sorted(self.missing_files):
                    f.write(f"  {missing_file}\n")
                f.write(f"\nTotal missing files: {len(self.missing_files)}\n")
            else:
                f.write("All dictionary files found successfully!\n")
            
            # Deduplication statistics
            if self.deduplication_stats:
                f.write("\nDEDUPLICATION STATISTICS\n")
                f.write("-" * 25 + "\n")
                total_saved = sum(stats['saved'] for stats in self.deduplication_stats.values())
                f.write(f"Total entries saved through deduplication: {total_saved}\n")
                f.write("Top deduplication savings:\n")
                sorted_stats = sorted(self.deduplication_stats.items(), 
                                    key=lambda x: x[1]['saved'], reverse=True)[:10]
                for context, stats in sorted_stats:
                    if stats['saved'] > 0:
                        f.write(f"  {context}: {stats['original']} → {stats['deduplicated']} "
                               f"(saved {stats['saved']})\n")
                
        print(f"Summary report written to: {summary_file}")
        
    def write_individual_dictionaries(self, macro_analysis, type_analysis, name_analysis, timestamp):
        """Write individual resolved dictionary files"""
        dict_dir = self.output_dir / f"resolved_dictionaries_{timestamp}"
        dict_dir.mkdir(exist_ok=True)
        
        # Write macro dictionaries
        macro_dir = dict_dir / "macros"
        macro_dir.mkdir(exist_ok=True)
        for macro_name, info in macro_analysis.items():
            macro_file = macro_dir / f"macro_{macro_name}.txt"
            with open(macro_file, 'w') as f:
                f.write(f"# Resolved macro: @{macro_name}\n")
                f.write(f"# Total entries: {info['count']} (deduplicated)\n")
                f.write(f"# Dependencies: {', '.join('@' + dep for dep in info['dependencies'])}\n")
                f.write(f"# Raw definition: {info['raw_definition']}\n\n")
                for entry in info['entries']:
                    f.write(f"{entry}\n")
                    
        # Write field type dictionaries
        type_dir = dict_dir / "field_types"
        type_dir.mkdir(exist_ok=True)
        for field_type, info in type_analysis.items():
            type_file = type_dir / f"type_{field_type.replace('/', '_')}.txt"
            with open(type_file, 'w') as f:
                f.write(f"# Resolved field type: {field_type}\n")
                f.write(f"# Total entries: {info['count']} (deduplicated)\n")
                f.write(f"# Raw definition: {info['raw_definition']}\n\n")
                for entry in info['entries']:
                    f.write(f"{entry}\n")
                    
        # Write field name dictionaries
        name_dir = dict_dir / "field_names"
        name_dir.mkdir(exist_ok=True)
        for field_name, info in name_analysis.items():
            name_file = name_dir / f"name_{field_name.replace('.', '_').replace('/', '_')}.txt"
            with open(name_file, 'w') as f:
                f.write(f"# Resolved field name: {field_name}\n")
                f.write(f"# Total entries: {info['count']} (deduplicated)\n")
                f.write(f"# Raw definition: {info['raw_definition']}\n\n")
                for entry in info['entries']:
                    f.write(f"{entry}\n")
                    
        print(f"Individual dictionaries written to: {dict_dir}")
        
    def run(self):
        """Run the complete analysis"""
        print("Starting dictionary analysis...")
        self.setup_output_dir()
        
        # Analyze all components
        macro_analysis = self.analyze_macros()
        type_analysis = self.analyze_field_mappings(FIELD_TYPE_DICTIONARIES, "field type mappings")
        name_analysis = self.analyze_field_mappings(FIELD_NAME_DICTIONARIES, "field name mappings") 
        advanced_analysis = self.analyze_field_mappings(FIELD_ADVANCED_DICTIONARIES, "advanced field mappings")
        
        # Write results
        self.write_analysis_files(macro_analysis, type_analysis, name_analysis, advanced_analysis)
        
        print(f"\nAnalysis complete!")
        print(f"Results saved to: {self.output_dir}")
        if self.missing_files:
            print(f"Warning: {len(self.missing_files)} dictionary files were not found")
        else:
            print("All dictionary files resolved successfully!")


def main():
    resolver = DictionaryResolver(project_root)
    resolver.run()


if __name__ == "__main__":
    main()
