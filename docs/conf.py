# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

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
    'sphinxcontrib.mermaid',    # Architecture diagrams
]

# Source file types  
source_suffix = ['.rst', '.md']

# MyST configuration for Markdown support
myst_enable_extensions = [
    "strikethrough",
    "tasklist",
    "colon_fence",
    "linkify",
]

# The master toctree document
master_doc = 'index'

# -- Options for HTML output ------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_title = f"{project} Documentation"

# Add version switcher to the template
html_context = {
    'display_github': True,
    'github_user': 'NathanMulbrook',
    'github_repo': 'PacketFuzz',
    'github_version': 'main',
    'conf_py_path': '/docs/',
}

# -- Options for autodoc ----------------------------------------------------
autodoc_default_options = {
    'members': True,
    'undoc-members': True,
    'show-inheritance': True,
    'special-members': '__init__',
}

# Don't show typehints in the signature (show them in the description instead)
autodoc_typehints = 'description'

# -- Intersphinx configuration ----------------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'scapy': ('https://scapy.readthedocs.io/en/latest/', None),
}

# -- Mermaid configuration --------------------------------------------------
mermaid_output_format = 'raw'
mermaid_init_js = "mermaid.initialize({startOnLoad:true});"
