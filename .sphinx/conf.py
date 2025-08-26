# Configuration file for the Sphinx documentation builder.

import os
import sys

# Add the project root to the Python path for autodoc
sys.path.insert(0, os.path.abspath('..'))

# -- Project information -----------------------------------------------------
project = 'PacketFuzz'
copyright = '2025, Nathan Mulbrook'
author = 'Nathan Mulbrook'
version = '2.0.0'
release = '2.0.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',       # Auto-generate from docstrings
    'sphinx.ext.napoleon',      # Google/NumPy docstring support
    'sphinx.ext.viewcode',      # Source code links
    'sphinx.ext.intersphinx',   # Cross-project references
    'myst_parser',              # Markdown support
    'sphinxcontrib.mermaid',    # Mermaid diagram support
]

# Source file types  
source_suffix = {
    '.rst': None,
    '.md': 'myst',
}

# MyST configuration for Markdown support
myst_enable_extensions = [
    "strikethrough",
    "tasklist", 
    "colon_fence",
    "linkify",
]

# Configure mermaid to use the directive instead of code blocks
myst_fence_as_directive = ["mermaid"]

# Mermaid configuration for server-side rendering
mermaid_output_format = 'svg'
#mermaid_init_js = ""  # Disable client-side JS since we want server-side rendering
#mermaid_cmd = 'mmdc'  # Use mermaid-cli for server-side rendering  
#mermaid_cmd_shell = True  # Enable shell execution for CLI

# Files to exclude from processing
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# Suppress warnings for unknown lexer names (like mermaid)
suppress_warnings = ['misc.highlighting_failure', 'myst.header']

# The master toctree document
master_doc = 'index'
# -- Options for HTML output ------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_title = f"{project} Documentation"

# -- Extension configuration -------------------------------------------------
# AutoDoc configuration
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

# Intersphinx configuration
intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'scapy': ('https://scapy.readthedocs.io/en/latest/', None),
}

# Napoleon settings for docstring parsing
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
