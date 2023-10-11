import copy
from bitstring import BitArray
from collections import defaultdict

from util.gst import GalileoSystemTime
from osnma.navdata import InavSubframe
from osnma.authentication import OsnmaAuthenticator, OsnmaException
from osnma.dsm import NmaHeader, DsmHeader, DsmMessageType, DsmKrootMessage, DsmPkrMessage
from osnma.mack import MACK_header, MACK_tag_info, MACK_tags_and_info
from datasink.subscribers import SubscriberSystem

PUBLIC_KEY_TYPE_MAP = {}
for i in range(16):
    PUBLIC_KEY_TYPE_MAP[i] = 'reserved'
PUBLIC_KEY_TYPE_MAP[1] = 'ecdsa_p_256'
PUBLIC_KEY_TYPE_MAP[3] = 'ecdsa_p_521'
PUBLIC_KEY_TYPE_MAP[4] = 'osnma_alert_message'

PUBLIC_KEY_LENGTH_MAP = {
        "ecdsa_p_256": 264,
        "ecdsa_p_521": 536,
        }

# Number of block in DSM-KROOT
NBDK_MAP = {0: "reserved", 1: 7, 2: 8, 3: 9, 4: 10, 5: 11, 6: 12, 7: 13, 8: 14}
for i in range(9,16): NBDK_MAP[i] = "reserved"

# Hash function
HF_MAP = {0: "SHA-256", 1: "reserved", 2: "SHA3-256", 3: "reserved"}
# MAC function
MF_MAP = {0: "HMAC-SHA-256", 1: "CMAC-AES", 2: "reserved", 3: "reserved"}

# Key size
KS_MAP = {0: 96, 1: 104, 2: 112, 3: 120, 4: 128, 5: 160, 6: 192, 7: 224, 8: 256}
for i in range(9,16): KS_MAP[i] = "reserved"

# Tag size
TS_MAP = {5: 20, 6: 24, 7: 28, 8: 32, 9: 40}
for i in range(0,5): TS_MAP[i] = "reserved"
for i in range(10,16): TS_MAP[i] = "reserved"

class OSNMAFieldIsAllZerosException(OsnmaException):
    """
    Satellite is not transmitting OSNMA data: the OSNMA bits are all zeros.
    """
    pass

class OsnmaDecoder:
    '''
    Class handling all of the decoding, parsing, and OSNMA data extraction.
    '''
    def __init__(self, key_size=0, tag_size=0):
        self.pending_subframes = []

        self.key_size = key_size
        self.tag_size = tag_size

        self.current_nma_header = None

        self.number_of_dsm_blocks = {DsmMessageType.kroot: None, DsmMessageType.pkr: None}
        self.dsm_blocks = {DsmMessageType.kroot: None, DsmMessageType.pkr: None}

        self.subscribers = SubscriberSystem()

    def pre_check_nma_header(self, nma_header: NmaHeader):
        """Check that NMA header corresponds to valid data, i.e. does not
        contain reserved values. Note that this does not guarantee that the NMA
        header is valid: that is verfied part of the tag authentication
        process or the KROOT authentication process.

        :nma_header: NmaHeader object
        :returns: True, if data is okay to be used

        """
        if nma_header.nmas == 'reserved' or nma_header.cpks == 'reserved':
            return False
        return True

    # TODO: need to take EOC into account: during EOC you will get KROOTs from
    # two different chains
    def handle_dsm_block(self, hkroot: BitArray, have_kroot=False, have_pkr=False, expected_chain=None):
        """Parse HKROOT block and collect DSM-KROOT and DSM-PKR messages, and
        return the complete message when done. Note how the KROOT and PKR
        messages are handled almost identical fashion.

        :hkroot: BitArray representing the HKROOT message
        :returns: None, until a full DSM message is accumulated, in which case
        return a pair (msg, type), where msg is the completed DSM message, and
        the type is the type of the message (KROOT, PKR).
        """
        nma_header, dsm_header, dsm_block = self.parse_dsm_message_block(hkroot)
        dsm_type = dsm_header.dsm_id

        # During End of Chain event two different KROOTs will be transmitted,
        # and we may only want to process from the new chain
        if expected_chain != None and dsm_type == DsmMessageType.kroot and nma_header.cid != expected_chain:
            return

        # DSM messages can be ignore if we have received a full message
        # already, i.e. we already have a KROOT and/or PKR message
        if have_kroot and dsm_type == DsmMessageType.kroot:
            return
        if have_pkr and dsm_type == DsmMessageType.pkr:
            return

        # Ignore the block if the NMA header is invalid
        if not self.pre_check_nma_header(nma_header):
            return

        self.current_nma_header = nma_header

        # Handle first block if we have not started already
        if dsm_header.bid == 0 and self.number_of_dsm_blocks[dsm_type] == None:
            num_blocks = self.parse_number_of_blocks_from_first_dsm_block(dsm_block, dsm_type)

            # Allocate
            self.number_of_dsm_blocks[dsm_type] = num_blocks
            self.dsm_blocks[dsm_type] = [None] * num_blocks

            self.dsm_blocks[dsm_type][0] = dsm_block
            return

        # Insert blocks
        if self.number_of_dsm_blocks[dsm_type] != None:
            self.subscribers.send_info("Received DSM block {}/{} of type {}".format(
                dsm_header.bid+1, self.number_of_dsm_blocks[dsm_type], dsm_type))

            if dsm_header.bid < len(self.dsm_blocks[dsm_type]):
                self.dsm_blocks[dsm_type][dsm_header.bid] = dsm_block
            else:
                self.subscribers.send_info("DSM block ID larger than the expected block count, ignoring block")

        # DSM message completed
        if (self.number_of_dsm_blocks[dsm_type] != None) and (None not in self.dsm_blocks[dsm_type]):
            # Concatenate the message and return
            full_dsm_msg = sum(self.dsm_blocks[dsm_type])
            self.subscribers.send_info(f"DSM message of type {dsm_type} completed")
            
            dsm_msg = self._parse_dsm_message(full_dsm_msg, dsm_type)
            return dsm_msg, dsm_type

    def _parse_dsm_message(self, dsm_msg, msg_type):
        """Parse the DSM message of the given type from a BitArray

        :dsm_msg: DSM message as BitArray
        :msg_type: The DSM messge type as DsmMessageType
        :returns: either DsmPkrMessage or DsmKrootMessage based on the given
        type
        """
        if msg_type == DsmMessageType.kroot:
            return self.parse_dsm_kroot_message(dsm_msg)
        return self.parse_dsm_pkr_message(dsm_msg)

    def extract_tags(self, subframe: InavSubframe):
        """Extract tags from InavSubframe

        :subframe: InavSubframe object
        :returns: extracted tag0 and tags_and_info fields

        """
        _, MACK = self.extract_and_concatenate_OSNMA_bits(subframe)
        mack_header, MACK_tags_and_info, _ = self.parse_MACK_message(MACK)
        tag0 = mack_header.TAG0
        tags_and_info = self.parse_MACK_tags_and_info(MACK, self.tag_size, self.key_size)
        return tag0, tags_and_info

    def extract_and_concatenate_OSNMA_bits(self, subframe: InavSubframe):
        """ Parses and concatenates the 40-bit OSNMA fields out of the subframe.
        :subframe: InavSubframe object
        :return: A pair (HKROOT, MACK) that contains the concatenated BitArrays the respective fields.
        """
        even_page_size = 114
        odd_page_size = 120
        assert(len(subframe.data) == 15 * (even_page_size + odd_page_size))

        HKROOT = BitArray() # 120 bits
        MACK = BitArray() # 480 bits

        for page_idx in range(0,15):
            start = (even_page_size + odd_page_size)*page_idx
            page = subframe.data[start : start + even_page_size + odd_page_size]
            hkroot, mack = self.extract_osnma_field(page)
            HKROOT.append(hkroot)
            MACK.append(mack)

        if HKROOT.uint == 0 and MACK.uint == 0:
            wn = subframe.wn
            tow = subframe.tow
            svid = subframe.svid
            raise OSNMAFieldIsAllZerosException(f"No OSNMA bits available. WN: {wn}, TOW: {tow}, SVID: {svid}")

        return HKROOT, MACK

    def parse_dsm_message_block(self, HKROOT):
        """ Parse a single block of the DSM message.
        :subframe: InavSubframe object
        :HKROOT: the HKROOT field returned by extract_and_concatenate_OSNMA_bits
        :return: the parsed tuple (nma_header, dsm_header, dsm_block)
        """
        nma_header = self.parse_nma_header(HKROOT)

        # DSM data
        dsm_header = self.parse_dsm_header(HKROOT)
        dsm_block = HKROOT[16:120]

        return nma_header, dsm_header, dsm_block

    def parse_MACK_message(self, MACK):
        """ Parse the MACK message. The key and the tag sizes must be known to call this.

        :MACK: the MACK field returned by extract_and_concatenate_OSNMA_bits
        :return: the tuple (mack_header, mack_tags_and_info, mack_key).
        """

        if self.key_size == None or self.tag_size == None:
            return

        mack_header = self.parse_MACK_header(MACK, self.tag_size)
        mack_tags_and_info = self.parse_MACK_tags_and_info(MACK, self.tag_size, self.key_size)
        mack_start = len(mack_header.raw_bits) + len(mack_tags_and_info.raw_bits)
        mack_key = MACK[mack_start : mack_start + self.key_size]

        return (mack_header, mack_tags_and_info, mack_key)

    def parse_dsm_pkr_message(self, msg: BitArray):
        """Parse the fields from a DSM-PKR message. See the ICD for the notes
        about DSM-PKR message.

        :msg: BitArray of the raw message
        :returns: DsmPkrMessage object with the parsed data

        """
        nbdp = msg[:4].uint
        mid = msg[4:8]
        itn = msg[8:8+1024]
        npkt = msg[1032:1036]
        npkid = msg[1036:1040]

        pubk_length = PUBLIC_KEY_LENGTH_MAP[PUBLIC_KEY_TYPE_MAP[npkt.uint]]
        npk = msg[1040:1040+pubk_length]

        return DsmPkrMessage(msg, nbdp, mid, itn, npkt, npkid, npk)

    def parse_number_of_blocks_from_first_dsm_block(self, dsm_block: BitArray, msg=DsmMessageType.kroot):
        '''Determine the number of blocks the DSM message consists of. This
        information is obtained from the first DSM block. See ICD section 3.2.3.1
        for full info.

        :dsm_block: BitArray, the received DSM block
        :msg: enum DsmMessageType, the type of the DSM message

        '''
        nb = dsm_block[0:4].uint

        if msg == DsmMessageType.kroot:
            if nb == 0 or nb >= 9:
                raise Exception("NBDK value is " + str(nb) + ", which is a reserved value")

        elif msg == DsmMessageType.pkr:
            if nb <= 6 or nb >= 11:
                raise Exception("NBDP value is " + str(nb) + ", which is a reserved value")

        return nb + 6

    def extract_osnma_field(self, page: BitArray):
        """Extract the OSNMA from a BitArray of length 234 (the 6b between the
        pages are assumed to be removed.
        :page: BitArray corresponding to a nominal INAV page
        :return: hkroot and mack fields as BitArrays

        """
        oddpage = page[120-6: 120-6+120]
        osnma = oddpage[1+1+16 : 1+1+16 + 40]
        hkroot = osnma[0:8]
        mack = osnma[8:40]
        return hkroot, mack

    def parse_MACK_tags_and_info(self, mack: BitArray, TS: int, KS: int):
        '''Parse the Tags and Info field from the MACK section.

        :mack: the MACK section from the OSNMA subframe.
        :ts: the tag size
        :ks: the key size
        '''
        tag_list = []
        info_list = []
        n_tags = (480 - KS) // (TS + 16)
        # Skip over the MACK header
        start = TS + 12 + 4
        # Starting from 1 because tag 0 is in the MACK header
        for i in range(1, n_tags):
            idx = start + (i-1)*(TS+16)
            tag_list.append(mack[idx : idx+TS])
            info_list.append(self.parse_MACK_tag_info(mack[idx+TS : idx+TS+16]))
        return MACK_tags_and_info(mack[start : start + (n_tags-1)*(TS+16)], tag_list, info_list)

    def parse_nma_header(self, HKROOT: BitArray):
        '''Parse the NMA header from a BitArray corresponding to the HKROOT.

        :HKROOT: BitArray corresponding to the HKROOT data section.
        '''
        hkroot = HKROOT[0:8]
        nmas_map = {0: "reserved", 1: "test", 2: "operational", 3: "don't use"}
        cpks_map = {0: "reserved", 1: "nominal", 2: "end of chain", 3: "chain revoked", 4: "new public key", 5: "public key revoked", 6: "reserved", 7: "reserved"}

        nmas = nmas_map[hkroot[0:2].uint] # NMA status
        cid = hkroot[2:4].uint # Chain id
        cpks = cpks_map[hkroot[4:7].uint] # Chain and public key status

        return NmaHeader(hkroot, nmas, cid, cpks)

    def parse_dsm_header(self, HKROOT: BitArray):
        '''Parse the DSM header from a BitArray corresponding to the HKROOT.

        :HKROOT: BitArray corresponding to the HKROOT data section.
        '''
        hkroot = HKROOT[8:16]
        dsm_id = DsmMessageType.kroot if hkroot[0:4].uint <= 11 else DsmMessageType.pkr
        bid = hkroot[4:8].uint 
        return DsmHeader(hkroot, dsm_id, bid)

# Takes in the 120-bit HKROOT subframe and the tag size TS transmitted in the DSM-KROOT message.
    def parse_MACK_header(self, MACK: BitArray, TS: int):
        '''Parse the MACK header from a BitArray corresponding to the MACK
        section.

        :MACK: BitArray corresponding to the MACK data section.
        :TS: the tag size
        '''
        header = MACK[0:TS+12+4]
        TAG0 = header[0:TS]
        MACSEQ = header[0+TS : 0+TS+12]
        return MACK_header(header, TAG0, MACSEQ)

    def parse_MACK_tag_info(self, info_bits: BitArray):
        '''Parse the tag info from a BitArray corresponding the the info bits.

        :info_bits: the info bits from the Tag and Info field as a BitArray.
        '''
        PRND = info_bits[0:8].uint
        ADKD = info_bits[8:12].uint
        return MACK_tag_info(info_bits, PRND, ADKD)

    def parse_dsm_kroot_message(self, message):
        nbdk = NBDK_MAP[message[0:4].uint]
        pkid = message[4:8].uint
        cidkr = message[8:10].uint
        # Bits message[10:12] are reserved
        hf = HF_MAP[message[12:14].uint]
        mf = MF_MAP[message[14:16].uint]
        ks = KS_MAP[message[16:20].uint]
        ts = TS_MAP[message[20:24].uint]
        maclt = message[24:32].uint
        # Bits message[32:36] are reserved
        wnk = message[36:48].uint
        towhk = message[48:56].uint
        alpha = message[56:104]
        kroot = message[104:104+ks]
        signature = message[104+ks:104+ks+512]

        return DsmKrootMessage(message, nbdk, pkid, cidkr, hf, mf, ks, ts, maclt, wnk, towhk, alpha, kroot, signature)
