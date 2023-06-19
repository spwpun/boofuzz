from typing import Any
from .. import exception, helpers
from boofuzz import s_get

import time
import random
import struct
import string

from ..fuzzable import Fuzzable

asn1_tags = {
    'BOOLEAN': 0x01,
    'INTEGER': 0x02,
    'BIT STRING': 0x03,
    'OCTET STRING': 0x04,
    'NULL': 0x05,
    'OBJECT IDENTIFIER': 0x06,
    'ObjectDescriptor': 0x07,
    'EXTERNAL': 0x08,
    'REAL': 0x09,
    'ENUMERATED': 0x0a,
    'EMBEDDED PDV': 0x0b,
    'UTF8String': 0x0c,
    'RELATIVE-OID': 0x0d,
    'SEQUENCE': 0x30,
    'SET': 0xA0,
    'CHOICE': 0xA1,
    'DATE': 0x1F,
} # maybe more......

class ASN1(Fuzzable):
    """
    This class is used to generate ASN1 fuzzable data, automatically encode the asn1 data using BER encoding.
    """

    def __init__(self, name, asn1_type, value_block_name, fuzzable=False, parent=None):
        """
        :param name: Name of the ASN1 block
        :param asn1_type: Type of the ASN1 block
        :param value_block_name: Name of the value block
        :param value_block: Value block
        :param parent: Parent of the ASN1 block
        :param fuzzable: Whether the ASN1 block is fuzzable
        """
        super().__init__(name, parent)
        self.asn1_type = asn1_type
        self.value_block_name = value_block_name
        self.value_block = s_get(value_block_name) # maybe error here
        self.value_block.parent = self
        self.fuzzable = fuzzable
        self._mutant_index = 0
        
        self._default_value = self.render()
        self._asn1_data_length = 0
        self.length_field_width = 0

    def render(self):
        """
        Render the ASN1 block, according to the asn1 tags and value block to construct the asn1 data.
        :return: Rendered ASN1 block
        """
        asn1_data = b''
        asn1_data += struct.pack('B', asn1_tags[self.asn1_type])
        
        length = len(self.value_block.render())
        self._asn1_data_length = length
        if length < 128:
            asn1_data += struct.pack('B', length)
            self.length_field_width = 1
        else:
            asn1_data += struct.pack('B', 0x80 | (length >> 8))
            asn1_data += struct.pack('B', length & 0xFF)
            self.length_field_width = 2
        
        asn1_data += self.value_block.render()
        return asn1_data
    
    @property
    def name(self):
        return self.name
    
    @property
    def fuzzable(self):
        return self.fuzzable
    
    @property
    def mutant_index(self):
        return self._mutant_index
    
    def num_mutations(self, default_value=None):
        # Fixed number of mutations for ASN1 block
        # Just change the length field of the value block, the length > len(value_block) or length < len(value_block), and set the length to -1
        return 3
    
    def mutate(self):
        """
        Mutate the ASN1 block, just changed the length field of the value block.
        """
        if self._mutant_index == 0:
            length = self._asn1_data_length + 1
        elif self._mutant_index == 1:
            length = self._asn1_data_length - 1
        elif self._mutant_index == 2:
            length = -1
        self._mutant_index += 1
        
        asn1_data = b''
        asn1_data += struct.pack('B', asn1_tags[self.asn1_type])

        if length < 128:
            asn1_data += struct.pack('B', length)
            self.length_field_width = 1
        else:
            asn1_data += struct.pack('B', 0x80 | (length >> 8))
            asn1_data += struct.pack('B', length & 0xFF)
            self.length_field_width = 2
        
        asn1_data += self.value_block.render()

        return asn1_data
    
    def __repr__(self):
        return "<ASN1: %s, %s, %s>" % (self.name, self.asn1_type, self.value_block_name)





