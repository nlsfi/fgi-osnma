import copy
import hashlib
from enum import Enum
from bitstring import BitArray
from dataclasses import dataclass
from collections import defaultdict

from util.gst import GalileoSystemTime
from osnma.navdata import InavSubframe, NavDataManager
from osnma.decoder import OsnmaDecoder
from osnma.authentication import OsnmaAuthenticationException, OsnmaException, OsnmaAuthenticator, AuthOutcome, AuthAttempt
from osnma.dsm import NmaHeader, DsmMessageType, DsmKrootMessage
from osnma.mack import TeslaKey
from datasink.subscribers import SubscriberSystem

@dataclass
class OsnmaProtocolConfig:
    """ See ICD for more information.

    PKID: ID of the Galileo public key in place
    CIDKR: Chain ID to which the KROOT belongs to
    HF: Hash function
    MF: MAC function
    KS: Key size
    TS: Tag size
    MACLT: MAC lookup table value (specifies the TAG order, see the documentation)
    WNK: Week Number associated with the KROOT
    TOWHK: Time of Week number associated with the KROOT
    """
    PKID: int = None
    CIDKR: int = None
    HF: str = None
    MF: str = None
    KS: int = None
    TS: int = None
    MACLT: int = None
    WNK: int  = None
    TOWHK: int = None

class ReceiverState(Enum):
    """OSNMA related receiver state.

    INITIALIZING: in the process of collecting and validating the KROOT message
    READY_TO_AUTHENTICATE: initialization is done and we can start
    authenticating navigation messages
    """
    INITIALIZING = 0
    READY_TO_AUTHENTICATE = 1

@dataclass
class TagWithMetadata:
    """Tag with some metadata related to it
    """
    tag: BitArray
    tag_index: int
    gst: GalileoSystemTime
    PRND: int
    PRNA: int
    ADKD: int

class OsnmaEngine:
    """The main class for the OSNMA processing. Most notably it contains the
    process_subframe method, which uses the functionality of other classes to
    perform all of the required operations for the received subframe.
    """

    def __init__(self, public_key_pem, save_kroot=False):
        # Accumulated tags: dictionary with (gst, svid, adkd) -> list of tags
        self.collected_tags = defaultdict(list)
        self.pending_subframes = []

        # Save the received KROOT so it can be used to hot start the next runs
        self.save_kroot = save_kroot

        # Last received NMA header, verified NMA header, and Chain ID currently
        # in place, and whether End Of Chain event is coming
        self.current_nma_header = None
        self.verified_nma_header = None
        self.current_cid = None
        self.eoc_coming = False

        # Stashed KROOT/PKR for chain/pubk change events
        self._stashed_kroot = None
        self._stashed_pkr = None

        self.subscribers = SubscriberSystem()

        self.config = OsnmaProtocolConfig()
        self.state = ReceiverState.INITIALIZING
        self.navdata_manager = NavDataManager()
        self.authenticator = OsnmaAuthenticator(public_key_pem)
        self.decoder = OsnmaDecoder()

    def set_subscriber_system(self, subs: SubscriberSystem):
        """Set the current subscriber system for this class and its other
        member classes which use this system

        :subs: SubscriberSystem to set
        :returns: nothing

        """
        self.subscribers = subs
        self.decoder.subscribers = subs
        self.authenticator.subscribers = subs

    def add_tag(self, gst: GalileoSystemTime, adkd_number: int, PRND: int, PRNA: int, tag: BitArray, tag_index: int):
        self.collected_tags[(gst, PRND, adkd_number)].append(TagWithMetadata(tag, tag_index, gst, PRND, PRNA, adkd_number))

    def process_subframe(self, subframe: InavSubframe):
        """ Process the subframe, update receiver state and authenticate messages from previous subframes.
        Sends the authentication results to the subscribers.

        :subframe: a InavSubframe object
        :return: nothing, but calls subscriber callbacks
        """
        try:
            subframe_GST = GalileoSystemTime(subframe.wn, subframe.tow)

            # Raise exception if OSNMA field is all zeros
            HKROOT, MACK = self.decoder.extract_and_concatenate_OSNMA_bits(subframe)

            self.navdata_manager.extract_and_insert_authdata(subframe)
            self.pending_subframes.append((copy.deepcopy(subframe_GST), subframe.svid, copy.deepcopy(subframe.data)))

            # TODO: handle EOC properly
            have_kroot = (self.state == ReceiverState.READY_TO_AUTHENTICATE) and not self.eoc_coming
            have_pkr = self._stashed_pkr != None
            res = self.decoder.handle_dsm_block(HKROOT, have_kroot, have_pkr)
            # When the DSM message is fully received
            if res != None:
                self.current_nma_header = self.decoder.current_nma_header
                dsm_msg, dsm_type = res

                if dsm_type == DsmMessageType.kroot:
                    # Stash the KROOT if waiting for EOC, otherwise input it
                    # immediately
                    if self.eoc_coming:
                        self._stashed_kroot = dsm_msg
                    else:
                        self.validate_and_input_dsm_kroot(dsm_msg, self.current_nma_header)
                        if self.save_kroot:
                            self.write_kroot(dsm_msg)
                        self.subscribers.send_info("OSNMA Receiver initialization complete")
                if dsm_type == DsmMessageType.pkr:
                    self._stash_pkr(dsm_msg)

            if self.state == ReceiverState.READY_TO_AUTHENTICATE:
                nma_header, _, _ = self.decoder.parse_dsm_message_block(HKROOT)

                if self.decoder.pre_check_nma_header(nma_header):
                    self.current_nma_header = nma_header

                self._extract_and_insert_tags()
                self._extract_and_input_tesla_key(MACK, subframe_GST)

                # Use the new key to authenticate everything that is possible now
                results, successful_auths = self.authenticate()

                if len(results) > 0:
                    self.subscribers.send_subframe_report(results)

                    # When the NMA header has been part of successful
                    # authentications, it has been verified as a by product
                    if successful_auths > 0:
                        self.verified_nma_header = nma_header
                        self._handle_nma_header(self.verified_nma_header)

                self.pending_subframes = []

        # When no OSNMA bits
        except OsnmaException as e:
            # Even if we don't have OSNMA bits, add the auth data to support
            # cross authentication. Note: no need to add ADKD=4 auth data
            self.navdata_manager.extract_and_insert_authdata(subframe, False, True)

            self.subscribers.send_osnma_exception(e)

    def authenticate(self, tesla_key: TeslaKey=None, alpha: BitArray=None, nma_header: NmaHeader=None):
        '''
        Main authentication function: goes through the accumulated tags and
        navigation data, checks what can be authenticated, and produces an
        authentication report if any authentications were attempted.

        :tesla_key: the TESLA key class to use in the authentication attempts
        :alpha: hash salt to use in the tag computation
        :nma_header: current NMA header, which is used in tag computation
        :returns: list of AuthAttempt classes corresponding to the attempted
        authentications
        '''
        # Values from the class, when the arguments are not provided
        if tesla_key == None:
            tesla_key = self.authenticator.tesla_newest_key
        if alpha == None:
            alpha = self.authenticator.alpha
        if nma_header == None:
            nma_header = self.current_nma_header

        result = []
        successful_auths = 0

        # If arguments and class values are None, no authentications can be made
        if tesla_key == None:
            return result, successful_auths
        if alpha == None:
            return result, successful_auths
        if nma_header == None:
            return result, successful_auths

        # Iterate over collected tags
        attempted_authentications = set()
        for (tag_gst, PRND, adkd) in self.collected_tags:
            nav_data_gst = copy.deepcopy(tag_gst)
            nav_data_gst.subtract_seconds(30)

            old_nav_data_used = False
            nav_data = None
            if adkd == 4:
                nav_data = self.navdata_manager.get((nav_data_gst, 255, adkd))
            else:
                nav_data = self.navdata_manager.get((nav_data_gst, PRND, adkd))
            if nav_data == None:
                nav_data, _ = self.navdata_manager.get_any((nav_data_gst, PRND, adkd))
                old_nav_data_used = True
                if nav_data == None:
                    attempted_authentications.add((tag_gst, PRND, adkd))
                    continue

            # Iterate to the correct key, and continue if this is not possible
            past_key = self.authenticator.iterate_to_correct_key(tesla_key, tag_gst, alpha, adkd)
            if past_key == None:
                continue

            # Iterate over candidate tags
            available_tags = self.collected_tags[(tag_gst, PRND, adkd)]
            for tag_with_metadata in available_tags:
                PRNA, tag_index, tag = tag_with_metadata.PRNA, tag_with_metadata.tag_index, tag_with_metadata.tag
                attempt = self.authenticator.verify_tag(tag, past_key, nav_data, tag_gst,
                                                        nma_header, tag_index, PRND, PRNA, adkd)

                if old_nav_data_used and attempt.is_ok:
                    attempt.outcome = AuthOutcome.OK_WITH_OLD_NAVDATA
                result.append(attempt)
                if attempt.is_ok:
                    successful_auths += 1

            attempted_authentications.add((tag_gst, PRND, adkd))

        # Remove the processed tags from the collection
        for (tag_gst, PRND, adkd) in attempted_authentications:
            # Authenticated navigation data was 30s previously to tag
            nav_data_gst = copy.deepcopy(tag_gst)
            nav_data_gst.subtract_seconds(30)
            self.navdata_manager.remove((nav_data_gst, PRND, adkd))
            del self.collected_tags[(tag_gst, PRND, adkd)]

        return result, successful_auths

    def input_dsm_kroot(self, dsm_kroot):
        """Input the given DSM-KROOT message to the receiver. Can be used in
        hot start scenarios. Does not validate that the message is correct or
        from a trusted source. This is done by a separate function.

        :dsm_kroot: DsmKrootMessage object
        :returns: nothing, but parses the message and inputs the results to the
        receiver

        """
        msg = dsm_kroot
        self.config.HF = msg.hash_function
        self.config.MF = msg.mac_funciton
        self.config.KS = msg.key_size
        self.config.TS = msg.tag_size
        self.config.MACLT = msg.mac_lt
        self.config.WNK = msg.wn_kroot
        self.config.TOWHK = msg.tow_kroot

        self._update_hash_and_mac_functions()

        self.decoder.key_size = msg.key_size
        self.decoder.tag_size = msg.tag_size

        # TOWHK is given in hours but we need seconds.
        root_key_gst = GalileoSystemTime(msg.wn_kroot, msg.tow_kroot * 60 * 60)
        # The time of the root key is 30 seconds before the start of applicability of the chain
        root_key_gst.subtract_seconds(30)

        self.authenticator.tesla_root_key = TeslaKey(msg.root_key, root_key_gst)
        self.authenticator.tesla_newest_key = TeslaKey(msg.root_key, root_key_gst)
        self.authenticator.alpha = msg.alpha

        self.state = ReceiverState.READY_TO_AUTHENTICATE

    def _update_hash_and_mac_functions(self):
        """Take the hash and mac from the self.config, and update it to
        self.authenticator.
        """
        if self.config.HF == 'SHA-256':
            self.authenticator.hash_function = hashlib.sha256
        elif self.config.HF == 'SHA3-256':
            self.authenticator.hash_function = hashlib.sha3_256

        # TODO: different MAC functions not implemented
        if self.config.MF == 'HMAC-SHA256':
            self.authenticator.mac_function = None
        elif self.config.MF == 'CMAC-AES':
            self.authenticator.mac_function = None

    def validate_and_input_dsm_kroot(self, dsm_kroot, nma_header):
        """Validate the DSM-KROOT message against the public key and input the
        DSM-KROOT to the receiver if the validation was successful.

        :dsm_kroot: DSM-KROOT as DsmKrootMessage
        :nma_header: NmaHeader object
        :returns: True, if DSM-KROOT was validated and inputted, False otherwise

        """
        if self.authenticator.validate_dsm_kroot(dsm_kroot, nma_header):
            self.input_dsm_kroot(dsm_kroot)
            self.verified_nma_header = nma_header
            self._handle_nma_header(nma_header)
            return True
        return False

    def _extract_and_insert_tags(self):
        """Extract tags from the pending subframes. If the tag order is not
        what is defined by the MACLT value, throw an exception, otherwise
        insert them to the list of tags.

        :returns: nothing, but the tags will will be added to the list of tags

        """
        for this_gst, this_svid, this_subframe in self.pending_subframes:
            wn = this_gst.wn
            tow = this_gst.tow
            tag0, tags_and_info = self.decoder.extract_tags(InavSubframe(wn, tow, this_svid, this_subframe))
            try:
                self.authenticator.verify_tag_info_list(self.config.MACLT, tags_and_info, this_gst, this_svid)
            except OsnmaAuthenticationException as e:
                self.subscribers.send_osnma_exception(OsnmaException(f"Tag sequence verification failed. WN: {wn}, TOW: {tow}, SVID: {this_svid}"))
            else: # Add tags
                tag_list, info_list = tags_and_info.tag_list, tags_and_info.info_list

                self.add_tag(this_gst, 0, this_svid, this_svid, tag0, 0) # ADKD 0 tag 0
                for i in range(len(tag_list)): # Rest of the tags
                    self.add_tag(this_gst, info_list[i].ADKD, info_list[i].PRND, this_svid, tag_list[i], i+1)

    # TODO
    def _handle_nma_header(self, nma_header: NmaHeader):
        """React according to the status of the NMA header. See the ICD and
        Receiver guidelines for the CPKS or Chain and Public Key status for the
        full details on how to react to different values in the NMA header.
        This function should be called after the NMA header is verified, i.e.
        it has been used in a successful authentication.

        :nma_header: NmaHeader object to handle
        :returns: nothing, but performs necessary operations

        """
        if not self.decoder.pre_check_nma_header(nma_header):
            return

        self.current_nma_header = nma_header

        # Nothing to do
        if nma_header.cpks == 'nominal':
            return

        # Collect new DSM-KROOT on EOC event
        if nma_header.cpks == 'end of chain':
            self.eoc_coming = True

        if nma_header.cpks == 'chain revoked':
            # Previous chain revoked: jump to the next chain
            if nma_header.nmas == 'operational':
                self._jump_to_next_chain(int(nma_header.cid))
            # Current chain revoked: dump the chain, set status to initializing
            elif nma_header == "don't use":
                self.state = ReceiverState.INITIALIZING

        # New public key will be transmitted, and will be handled when it is
        # fully received
        if nma_header.cpks == 'new public key':
            if self._stashed_pkr != None:
                self._handle_pkr()

        # Old public key revoked, jump to next key
        if nma_header.cpks == 'public key revoked':
            # Previous public key revoked: use a stashed one
            if nma_header.nmas == 'operational':
                self._handle_pkr()
            # Current public key revoked: dump the chain, set status to initializing
            elif nma_header.nmas == "don't use":
                self.state = ReceiverState.INITIALIZING

    def _handle_pkr(self):
        """Handle a public key renewal event. Begin using existing stashed
        public or start collecting PKR messages to get new public key.

        :returns: nothing

        """
        if self._stashed_pkr != None:
            if self.authenticator.verify_public_key(self._stashed_pkr):
                self.authenticator.public_key = self._stashed_pkr.new_public_key
            self._stashed_pkr = None

    def _jump_to_next_chain(self, chain_id, kroot=None):
        """Jump to the next chain if possible, if not, set status to
        initializing.

        :chain_id: Key chain ID of the next chain
        :kroot: optionally give DSM-KROOT object of the next chain
        :returns: success status of the jump
        """
        if kroot == None:
            kroot = self._stashed_kroot
            # Set to initializing, if jump attempt failed
            if kroot == None:
                self.state = ReceiverState.INITIALIZING
                return

        if self.validate_and_input_dsm_kroot(kroot, self.current_nma_header):
            self.current_cid = chain_id
            self.eoc_coming = False
        else:
            # Something wrong, try to initialize again
            self.state = ReceiverState.INITIALIZING

    def _stash_pkr(self, pkr):
        """Stash the entire PKR message to be used in public key renewal event,
        when appropriate NMA status is seen.

        :pkr: PKR message as DsmPkrMessage
        :returns: nothing

        """
        self._stashed_pkr = pkr

    def _stash_dsm_kroot(self, kroot):
        """Stash a DSM-KROOT object for later use. Used to store future KROOTs
        in chain change events.

        :kroot: DSM-KROOT object
        :returns: nothing

        """
        self._stashed_kroot = kroot

    def _input_stashed_kroot(self):
        """Input a stashed DSM-KROOT to the engine and handle the
        initialization.

        :returns: success status

        """
        kroot = self._stashed_kroot
        if kroot != None:
            self.input_dsm_kroot(kroot)
            return True
        return False

    def _extract_and_input_tesla_key(self, MACK: BitArray, gst: GalileoSystemTime):
        """Parse the TESLA key from the MACK section and validate it against
        the root key or another already verified key

        :MACK: BitArray representing the MACK msg
        :gst: GST of when the key arrived
        :returns: nothing

        """
        _, _, mack_key = self.decoder.parse_MACK_message(MACK)
        parsed_key = TeslaKey(mack_key, gst)
        self.authenticator.verify_and_input_tesla_key(parsed_key)

    def write_kroot(self, kroot: DsmKrootMessage, filename=None):
        """Write the KROOT to a a file. If filename is not provided it will be
        stored to a file called kroot_<wn>_<tow>.

        :kroot: DsmKrootMessage
        :returns: nothing

        """
        wn = kroot.wn_kroot
        tow = kroot.tow_kroot

        if filename == None:
            filename = f"kroot_{wn}_{tow}"

        with open(filename, 'w') as f:
            f.write(kroot.raw_bits.hex)
