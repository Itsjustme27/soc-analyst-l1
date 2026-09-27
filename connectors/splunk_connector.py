"""
Backwards-compatibility shim.

The Splunk connector now lives behind the multi-SIEM layer
(connectors.siem.splunk.SplunkConnector) so the same interface serves Splunk,
QRadar, Elastic, Sentinel and mock. Existing imports keep working.
"""

from __future__ import annotations

from connectors.siem.splunk import SplunkConnector  # noqa: F401

__all__ = ["SplunkConnector"]
