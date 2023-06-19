# Import blocks at this level for backwards compatibility.
# blocks/ used to be blocks.py
from .aligned import Aligned
from .block import Block
from .checksum import Checksum
from .repeat import Repeat
from .request import Request
from .size import Size
from .rrrepeat import RRRepeat
from .tlv import TLV
from .asn1 import ASN1

__all__ = ["Block", "Checksum", "Repeat", "Request", "Size", "REQUESTS", "Aligned", "RRRepeat", "TLV", "ASN1"]

REQUESTS = {}
CURRENT = None
