import cryptography
import copy
import hashlib
import hmac
from enum import Enum
from dataclasses import dataclass
from bitstring import BitArray
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from util.gst import GalileoSystemTime
from osnma.dsm import NmaHeader, DsmKrootMessage, DsmPkrMessage
from osnma.mack import TeslaKey, MACK_tags_and_info
from crypto.merkletree import MerkleTree
from datasink.subscribers import SubscriberSystem

class AuthOutcome(Enum):
    """Possible outcomes from authentication of a piece of data. Values:

    OK: authentication fully successful
    OK_WITH_OLD_NAVDATA: authentication successful, but older navigation data
    was used
    OK_WITH_INCOMPLETE_SUBFRAME: authentication successful, but a subframe with
    missing pages was used.
    INVALID_TAG_WITH_OLD_NAV_DATA: authentication failed, but old navigation
    data was used, so this may not be surprising
    INVALID_TAG_WITH_INCOMPLETE_SUBFRAME: authentication failed, but a subframe
    with missing pages was used, so this may not be surprising
    INVALID_TAG: authentication failed with no clear reason why

    """
    OK = 0
    OK_WITH_OLD_NAVDATA = 1
    OK_WITH_INCOMPLETE_SUBFRAME = 2
    INVALID_TAG = 90
    INVALID_TAG_WITH_OLD_NAV_DATA = 91
    INVALID_TAG_WITH_INCOMPLETE_SUBFRAME = 92

@dataclass
class AuthAttempt:
    """ This class contains information on what happened to the authentication of a piece of data
    in subframe at time (wn, tow), with data transmitted by satellite PRND and a tag transmitted
    by satellite PRNA. The ADKD number defines which data was authenticated and the key delay (normal or slow MAC).
    See the ICD for more detalis.
    """
    PRND: int # Id of the satellite transmitting the data that is being authenticated
    PRNA: int # Id of the satellite transmitting the tag. Can be None.
    wn: int # Week number
    tow: int # Time of week
    adkd: int # ADKD number (see the ICD).
    outcome: AuthOutcome

    def is_ok(self):
        """Does the attempt correspond to a successful authentication.
        :returns: True if succesful auth

        """
        # Values less than 10 for AuthOutcome correspond to successful authentications
        if self.outcome < 10:
            return True
        return False

@dataclass
class OsnmaCryptoMaterial:
    public_key: bytes # Stored in ascii-encoded pem format.
    tesla_root_key: BitArray # Received in the DSM-KROOT message
    tesla_newest_key: BitArray # Received in the MACK message
    alpha: BitArray # Random salt received in the DSM-KROOT message

class OsnmaException(Exception): # Base class for OSNMA expections
    pass

class OsnmaAuthenticationException(OsnmaException):
    """ OSNMA Authentication failures raise this exception """
    pass

def pad_to_multiple_of_8(data: BitArray):
    """ Append zeros to data until the length is a multiple of 8
    """
    pad_length = 8 - len(data) % 8
    if pad_length < 8:
        padding = "0b" + "".join(['0']*pad_length) # pad_length zeroes
        data.append(BitArray(padding))

class OsnmaAuthenticator:
    """Class for OSNMA related cryptographic material and operations. See the
    OSNMA documentation for the full details.

    Members:
    :public_key: Galileo public key as bytes
    :tesla_root_key: TESLA root key as BitArray
    :tesla_root_key: newest verified TESLA key as BitArray
    :alpha: hash salt that is received with the DSM-KROOT message
    """
    def __init__(self, public_key_pem, merkle_root=None):
        """
        :public_key_pem: The Galileo OSNMA public key, in PEM text format. The
        key can be downloaded from the OSNMA website. The PEM should contain
        both the elliptic curve parameters and the key. For example, the key on
        6.12.2021 is encoded as follows:

        -----BEGIN EC PARAMETERS-----
        BggqhkjOPQMBBw==
        -----END EC PARAMETERS-----
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErZl4QOS6BOJl6zeHCTnwGpmgYHEb
        gezdrKuYu/ghBqHcKerOpF1eEDAU1azJ0vGwe4cYiwzYm2IiC30L1EjlVQ==
        -----END PUBLIC KEY-----
        """
        self.public_key = bytes(public_key_pem, encoding="ascii")
        self.merkle_tree = None
        if merkle_root != None:
            self.merkle_tree = MerkleTree(merkle_root)

        # These will be usually obtained with a delay
        self.tesla_root_key = None
        self.tesla_newest_key = None
        self.alpha = None

        self.hash_function = hashlib.sha256
        # TODO: mac function
        self.mac_function = None

        self.subscribers = SubscriberSystem()

    def validate_dsm_kroot(self, dsm_kroot: DsmKrootMessage, nma_header: NmaHeader, public_key_pem: bytes=None):
        """ Authenticate the DSM-KROOT message and the NMA header using the given public key. Implements Section 6.3 of [1].

        :nma_header: NMA header as NmaHeader object
        :dsm_kroot: DSM-KROOT as DsmKrootMessage object
        :public_key_pem: The public key in ASCII-encoded pem format.
        :return: True if authentication was successful.
        :raises OsnmaAuthenticationException: If authentication was unsuccesful.
        """

        ks = dsm_kroot.key_size
        ds = dsm_kroot.digital_signature

        bits_to_authenticate = nma_header.raw_bits + dsm_kroot.raw_bits[8:104+ks]
        pad_to_multiple_of_8(bits_to_authenticate)

        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
        # Split the digital signature into the parts (r,s) and encode in DER
        # format
        sig_der = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(ds[0:256].uint, ds[256:512].uint)

        # Verify that DS is a valid signature of the message with the known public key of Galileo OSNMA
        # Use the state public key unless a key is explicitly given
        if public_key_pem == None:
            public_key_pem = self.public_key
        public_key = load_pem_public_key(public_key_pem)

        try:
            public_key.verify(sig_der, bits_to_authenticate.tobytes(), ec.ECDSA(hashes.SHA256()))
            return True
        except cryptography.exceptions.InvalidSignature:
            raise OsnmaAuthenticationException("DSM-KROOT authentication failure.")

    def iterate_key_chain(self, key: TeslaKey, alpha: BitArray, steps: int):
        """ Iterate the key chain to the past

        :key: The key to start from.
        :alpha: hash salt
        :steps: How many steps to go to the past.
        :return: The computed past key
        """
        K = key.key[:]
        t = copy.deepcopy(key.time)
        for i in range(steps):
            t.subtract_seconds(30)
            m = self.hash_function()
            m.update((K + t.bit_packed() + alpha).tobytes())
            K = BitArray(m.digest())[0 : len(K)]
        return TeslaKey(K,t)

    def iterate_to_correct_key(self, key, target_gst, alpha, adkd=0):
        """Iterate key until the correct key.

        :key: TeslaKey object
        :target_gst: gst to iterate until
        :alpha: salt to use in hashing
        :adkd: ADKD number, specifies whether there should be 1 or 11 subframe
        offset between the key and the tag

        :returns: the iterated key, or None if the iteration cannot be
        performed. This can be the case because the key corresponding to the
        tag is transmitted with a delay.
        """
        if key == None:
            return None

        # Key and tesla key timestamp should differ by a multiple of
        # subframe time (30s), and to perform authentication, the key must
        # be at least one subframe after the tag
        dt = key.time.total_seconds() - target_gst.total_seconds()
        assert(dt % 30 == 0)
        if dt <= 0: return None

        # ADKD 12 aka slow MAC: additional 10 key delay instead of 1
        if adkd == 12 and dt < 11*30:
            # Not ready for ADKD 12 authentication
            return None

        # Derive the correct key from the newest key for others than ADKD=12
        past_key = key
        if dt > 30 and adkd != 12:
            n_steps = dt // 30 - 1
            past_key = self.iterate_key_chain(key, alpha, n_steps)

        # ADKD=12 key iteration
        if adkd == 12 and dt > 11*30:
            # Slow MAC: normal delay is 330s, iterate to that
            n_steps = (dt - 330) // 30
            past_key = self.iterate_key_chain(key, alpha, n_steps)

        return past_key

    def verify_and_input_tesla_key(self, key: TeslaKey):
        """Verify the TESLA key against either the root key or a previously
        verified key.

        :key: TESLA key to verify
        :returns: True if the key is valid, return False if the key is not
        processed (i.e. key is not newer than current)
        :except: throw exception if the key is not valid
        """
        if self.tesla_newest_key == None:
            raise OsnmaAuthenticationException(f"Key could not be authenticated: no root/verified key available")

        if key.time.total_seconds() <= self.tesla_newest_key.time.total_seconds():
            # Do not process keys unless they are newer than current
            return False

        is_valid = self.verify_tesla_key_against_trusted_key(key, self.tesla_newest_key, self.alpha)
        if is_valid:
            self.tesla_newest_key = key
            return True
        return False

    def verify_tesla_key_against_trusted_key(self, key: TeslaKey, trusted_key: TeslaKey, alpha: BitArray):
        """ Authenticate a new TESLA key against a trusted TESLA key. Implements Section 6.4 of [1].

        :key: The key to authenticate.
        :trusted_key: The trusted key.
        :alpha: The hash salt of the key chain (distributed in the DSM_KROOT message).
        :return: True if authentication was successful.
        :raises OsnmaAuthenticationException: If authentication was unsuccesful.
        """

        # Key must come after a trusted key
        dt = key.time.total_seconds() - trusted_key.time.total_seconds()
        assert(dt > 0)
        assert(dt % 30 == 0)
        K = self.iterate_key_chain(key, alpha, dt // 30)

        if K.key.hex == trusted_key.key.hex:
            return True
        return False

    def verify_MACSEQ(self):
        """Verify MACSEQ. TODO
        """
        pass

    def verify_tag_info_list(self, MACLT: int, mack_tags_and_info: MACK_tags_and_info, subframe_start_time: GalileoSystemTime, auth_source_svid: int):
        """ Verify that the tag info sequence matches the MACLT entry. Implements Section 6.5 of [1].

        :MACLT: The pointer to the MACLT table (transmitted in the DMS_KROOT message).
        :mack_tags_and_info: The MACK tags and info strucure (transmitted in the MACK message).
        :subframe_start_time: Start time of the subframe containing the data.
        :auth_source_svid: The SVID (Space Vehicle ID) of the satellite transmitting the tag info.
        :return: True if authentication was successful.
        :raises OsnmaAuthenticationException: If authentication was unsuccesful.
        """

        t = subframe_start_time.tow % 60
        if t != 0 and t != 30:
            raise ValueError("Subframe TOW is not a multiple of 30.")

        # See the ICD
        if MACLT == 27 and t == 0: seq = ["00S", "00E", "00E", "00E", "12S", "00E"]
        elif MACLT == 27 and t == 30: seq = ["00S", "00E", "00E", "04S", "12S", "00E"]
        elif MACLT == 28 and t == 0: seq = ["00S", "00E", "00E", "00E", "00S", "00E", "00E", "12S", "00E", "00E"]
        elif MACLT == 28 and t == 30: seq = ["00S", "00E", "00E", "00S", "00E", "00E", "04S", "12S", "00E", "00E"]
        elif MACLT == 31 and t == 0: seq = ["00S", "00E", "00E", "12S", "00E"]
        elif MACLT == 31 and t == 30: seq = ["00S", "00E", "00E", "12S", "04S"]
        elif MACLT == 33 and t == 0: seq = ["00S", "00E", "04S", "00E", "12S", "00E"]
        elif MACLT == 33 and t == 30: seq = ["00S", "00E", "00E", "12S", "00E", "12E"]
        else: raise OsnmaAuthenticationException("MACLT value is reserved. The MAC lookup table in might be outdated.")


        # Check that the sequence matches the mack_tags_and_info
        if len(mack_tags_and_info.info_list) + 1 != len(seq): # +1 because tag0 is not in the list
            raise OsnmaAuthenticationException("Number of tags does not match the MAC lookup table.")

        for i in range(1,len(seq)): # seqs[0] is not checked because tag0 always has type 00S by definition.

            transmitted_info = mack_tags_and_info.info_list[i-1] # -1 to account for the missing tag0

            if seq[i] == "FLX":
                raise OsnmaAuthenticationException("Flexible authentication is not implemented.")

            ADKD = int(seq[i][0:2])
            if ADKD != transmitted_info.ADKD:
                self.subscribers.send_info(f"MACLT: expected ADKD={ADKD}, got ADKD={transmitted_info.ADKD} from {auth_source_svid}")
                raise OsnmaAuthenticationException("Tag {} does not match MAC lookup table.".format(i))

            is_self_auth = (transmitted_info.PRND == auth_source_svid) or (transmitted_info.ADKD == 4 and transmitted_info.PRND == 255)
            if seq[i][2] == 'S' and not is_self_auth:
                raise OsnmaAuthenticationException("Tag {} authentication target SVID is inconsistent with MAC lookup table".format(i))
            if seq[i][2] == 'E' and is_self_auth:
                raise OsnmaAuthenticationException("Tag {} authentication target SVID is inconsistent with MAC lookup table".format(i))

        return True

    def verify_tag(self, tag: BitArray, key: TeslaKey, nav_data: BitArray,
                   tag_gst: GalileoSystemTime, nma_header: NmaHeader,
                   index: int, prnd: int, prna: int, adkd: int):
        """Verify a tag be recomputing it from the navigation data and
        metadata, and comparing the result to the target tag.

        :tag: the target tag as a BitArray
        :key: TeslaKey object to use
        :nav_data: received navigation data as BitArray
        :tag_data_gst: GalileoSystemTime corresponding to the tag
        :nma_header: NmaHeader object
        :index: the tag index
        :prnd: SVID of the satellite from which the navigation data comes from
        :prna: SVID of the satellite from which the tag comes from
        :returns: AuthAttempt object with the authentication result

        """
        received_tag = tag.tobytes()
        data = self.create_auth_msg(nav_data, prnd, prna, tag_gst, index, nma_header)
        computed_tag = hmac.new(key.key.tobytes(), data.tobytes(), hashlib.sha256).digest()[0:len(received_tag)]

        attempt = AuthAttempt(prnd, prna, tag_gst.wn, tag_gst.tow, adkd, AuthOutcome.OK)
        if received_tag != computed_tag:
            attempt.outcome = AuthOutcome.INVALID_TAG

        return attempt

    def verify_public_key(self, pkr_msg: DsmPkrMessage):
        """Verify a public key by using the cryptographic material from a PKR
        message.

        :pkr_msg: the entire PKR message as DsmPkrMessage
        :returns: True when the public key is valid

        """
        if self.merkle_tree == None:
            self.subscribers.send_info("No merkle root: public key verification not possible")
            return True
        return self.merkle_tree.validate_public_key(pkr_msg)

    def create_auth_msg(self, auth_data: BitArray, PRND: int, PRNA: int, gst: GalileoSystemTime, tag_index: int, nma_header: NmaHeader):
        """Concatenate context information to create the input for the tag
        creation and authentication.

        :auth_data: Bits to be authenticated (e.g. from _get_ADKD0_data or _get_ADKD4_data)
        :PRND: the id of the satellite transmitting the authentication data
        :PRNA: the id of the satellite transmitting the tag
        :gst: The time at which `auth_data` was transmitted
        :tag_index: The 0-based index of the tag that authenticates `auth_data` in the tag list (tag0 has index 0).
        :nma_header: The current NMA header

        :return: the message that will be authenticated
        """

        PRNA_byte = BitArray(uint=PRNA, length=8)
        PRND_byte = BitArray(uint=PRND, length=8)
        GST = gst.bit_packed()
        CTR = BitArray(uint=tag_index+1, length=8) # +1: the counter uses 1-based indexing
        nmas = nma_header.raw_bits[0:2]

        # ADKD=4 calculation uses PRND=PRNA
        if PRND == 255:
            PRND_byte = PRNA_byte

        if tag_index == 0: # TAG0
            msg = PRNA_byte + GST + CTR + nmas + auth_data
        else:
            msg = PRND_byte + PRNA_byte + GST + CTR + nmas + auth_data

        pad_to_multiple_of_8(msg)
        return msg

