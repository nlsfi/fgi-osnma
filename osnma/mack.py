from bitstring import BitArray
from dataclasses import dataclass

from util.gst import GalileoSystemTime

'''
Classes for MACK related data structures.
'''

@dataclass
class MACK_header:
    raw_bits: BitArray # All data in the header in raw bits
    TAG0: BitArray # The authentication tag for ADKD=0 of the satellite transmitting this message
    MACSEQ: BitArray # TODO: need to implement

@dataclass
class MACK_tag_info:
    raw_bits: BitArray # All data in the message in raw bits
    PRND: int # The id of the satellite transmitting the bits that this tag authenticates
    ADKD: int # Authentication data and key delay. Described which data is being authenticated and how long the TESLA key delay is

@dataclass
class MACK_tags_and_info:
    raw_bits: BitArray # All data in the message in raw bits
    tag_list: list # List of BitArray
    info_list: list # List of MACK_tag_info

@dataclass
class TeslaKey:
    key: BitArray
    time: GalileoSystemTime

