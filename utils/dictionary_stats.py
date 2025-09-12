#!/usr/bin/env python3
"""
Dictionary Stats - Quick Stats Utility

This utility provides quick statistics about the dictionary mappings without 
generating full resolution files.

Usage: python dictionary_stats.py
"""

import os
import sys
from pathlib import Path
from collections import Counter

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


def count_file_lines(file_path: str) -> int:
    """Count lines in a dictionary file"""
    full_path = project_root / file_path
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return len(lines)
    except (OSError, IOError, FileNotFoundError):
        return 0


def analyze_macro_dependencies():
    """Analyze macro dependency relationships"""
    dependencies = {}
    for macro_name, entries in MACROS.items():
        deps = [entry[1:] for entry in entries if entry.startswith('@')]
        if deps:
            dependencies[macro_name] = deps
    return dependencies


def get_macro_stats():
    """Get quick statistics about macros"""
    print("MACRO STATISTICS")
    print("=" * 50)
    
    total_entries = 0
    file_count = 0
    macro_deps = analyze_macro_dependencies()
    
    for macro_name, entries in MACROS.items():
        entry_count = 0
        files_in_macro = 0
        macro_references = 0
        
        for entry in entries:
            if entry.startswith('@'):
                macro_references += 1
            else:
                files_in_macro += 1
                entry_count += count_file_lines(entry)
                
        total_entries += entry_count
        file_count += files_in_macro
        
        deps_str = f" (deps: {', '.join('@' + d for d in macro_deps.get(macro_name, []))})" if macro_name in macro_deps else ""
        print(f"@{macro_name}: {entry_count} entries from {files_in_macro} files{deps_str}")
        
    print(f"\nTotal: {len(MACROS)} macros, {file_count} files, ~{total_entries} entries")
    return total_entries, file_count


def get_field_stats():
    """Get statistics about field mappings"""
    print(f"\nFIELD MAPPING STATISTICS")
    print("=" * 50)
    
    print(f"Field Types: {len(FIELD_TYPE_DICTIONARIES)} mappings")
    print(f"Field Names: {len(FIELD_NAME_DICTIONARIES)} mappings") 
    print(f"Advanced Fields: {len(FIELD_ADVANCED_DICTIONARIES)} mappings")
    
    # Count unique files referenced
    all_files = set()
    macro_refs = set()
    
    for mappings in [FIELD_TYPE_DICTIONARIES, FIELD_NAME_DICTIONARIES, FIELD_ADVANCED_DICTIONARIES]:
        for field_name, entries in mappings.items():
            for entry in entries:
                if entry.startswith('@'):
                    macro_refs.add(entry)
                else:
                    all_files.add(entry)
                    
    print(f"Unique files referenced: {len(all_files)}")
    print(f"Macro references: {len(macro_refs)}")


def get_file_usage_stats():
    """Show which files are used most frequently"""
    print(f"\nFILE USAGE STATISTICS")
    print("=" * 50)
    
    file_counter = Counter()
    
    # Count from macros
    for macro_name, entries in MACROS.items():
        for entry in entries:
            if not entry.startswith('@'):
                file_counter[entry] += 1
                
    # Count from field mappings
    for mappings in [FIELD_TYPE_DICTIONARIES, FIELD_NAME_DICTIONARIES, FIELD_ADVANCED_DICTIONARIES]:
        for field_name, entries in mappings.items():
            for entry in entries:
                if not entry.startswith('@'):
                    file_counter[entry] += 1
                    
    print("Most frequently used files:")
    for file_path, count in file_counter.most_common(10):
        line_count = count_file_lines(file_path)
        print(f"  {file_path} (used {count}x, {line_count} entries)")


def main():
    print("PacketFuzz Dictionary Statistics")
    print("=" * 60)
    
    get_macro_stats()
    get_field_stats()
    get_file_usage_stats()
    
    print(f"\nFor detailed analysis, run: python utils/dictionary_resolver.py")


if __name__ == "__main__":
    main()
