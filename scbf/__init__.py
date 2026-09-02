"""
Supply Chain Behavioral Fingerprinting (SCBF)

A real-time malicious package detection system using Temporal Graph Networks
and eBPF-based behavioral monitoring.
"""

__version__ = "0.1.0"
__author__ = "SCBF Team"

from scbf.models.tgn_encoder import TGNEncoder, TGNMemory, TimeEncode
from scbf.models.itbg_constructor import ITBGConstructor, NodeIDMap

__all__ = [
    "TGNEncoder",
    "TGNMemory", 
    "TimeEncode",
    "ITBGConstructor",
    "NodeIDMap",
]
