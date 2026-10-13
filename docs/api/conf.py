"""Konfigurasi ekstraksi docstring dan pengujian contoh API."""
from importlib.metadata import version as package_version

project = "JAV-128"
author = "Tim JAV-128"
release = package_version("jav128")
version = release
language = "id"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.doctest", "sphinx.ext.viewcode"]
autodoc_member_order = "bysource"
autodoc_typehints = "signature"
html_theme = "alabaster"
html_title = "JAV-128 — Dokumentasi API"
html_theme_options = {"description": "Referensi API Python", "fixed_sidebar": True}
html_sidebars = {"**": ["about.html", "navigation.html", "searchfield.html"]}
