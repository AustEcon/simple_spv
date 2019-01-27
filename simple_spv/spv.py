# TODO modify bitcash to work entirely with bitindex and basic spv functions like
#  send version / verack and getdata on txid --> then can create transaction with this tx information (like scriptsig)
#  don't really want to rely on block explorers... but may be easier...
#  I think I already got it working for GETTING information... just not for SENDING


# TODO so maybe it will be (1) get balance and utxos whichever way you can (? even via block explorer if need
#  be at first) then... use bitindex for sending primarily with p2p as backup.
#  Basic plan is to get a working system no matter how you do it first! THEN AND ONLY THEN... do you add complexity
#  Goal is to make something USEABLE BY PEOPLE. HAVE SOMETHING TO SHOW FOR ALL YOUR WORK!
#  The validation of block headers can come SECONDARILY... to then VALIDATE the 3rd party UTXOS offered up...
#  Checks and balances... but convenience of obtaining this data first and foremost... there can be full nodes checking
#  up on them anyway... free market feedback... I think they should monetise their services personally. Would discourage
#  Spamming too and allow for bigger bandwidth and speed etc.. (? atomic swaps bitcoin for info ? ) - would encourage
#  local storage wherever possible and only using bitindex for bootstrapping on a new device

import io
import socket
import bitcash.utils as ut
import bitcoinx
import threading
import os
import random
import dns.resolver
import struct

import simple_spv
from simple_spv.constants import BITCOIN_SV_MAGIC, CCODES, MAX_BITS
from simple_spv.tools import DbManager
from simple_spv.serialize import Serialize

import time

from simple_spv import tools
from simple_spv.constants import INV_TYPES
from simple_spv.tools import get_block_hash
from simple_spv.config import Config

from simple_spv import faster_validate

# ------------------- GLOBAL VARIABLES ------------------- #
init = Config()
latest_checkpoint = init.latest_checkpoint
latest_checkpoint_height = init.latest_checkpoint_height
prev_hash_que = init.prev_hash_que
db_height = init.db_height
previous_validation_height = init.previous_validation_height
headers_stream = init.headers_stream
hashes_stream = init.hashes_stream
temp_headers_store = init.temp_headers_store
db = init.db = []

# ------------------- THREAD LOCKS ------------------- #
print_lock = threading.Lock()
sock_lock = threading.Lock()


# TODO move back out into own separate file - would need to change structure though for des headers modifying globals
class Deserialize:
    """
    Created a class to make use of the getattr() function
    for selecting the appropriate deserializer for recv'd message
    types in each buffer recv'd
    - see sockets.deserialize_full_buffer() function"""

    @classmethod
    def deserialize_message_header(cls, header):
        global checksum
        stream = io.BytesIO(header)

        magic = ut.bytes_to_hex(stream.read(4))
        command = stream.read(12).decode('ascii').strip('\x00')
        length = bitcoinx.read_le_uint32(stream.read)
        try:
            checksum = ut.bytes_to_hex(stream.read(4))
            decoded_header = {'magic': magic,
                              'command': command,
                              'length': length,
                              'checksum': checksum, }
            return decoded_header
        except Exception as e:
            print(e)
            print('reading in checksum failed...')

    @classmethod
    def deserialize_version(cls, f):
        version = bitcoinx.read_le_int32(f.read)
        services = bitcoinx.read_le_uint64(f.read)
        timestamp = time.ctime(bitcoinx.read_le_int64(f.read))
        addr_recv = cls.deserialize_IPv4_addr_from_version(f)
        addr_from = cls.deserialize_IPv4_addr_from_version(f)
        nonce = bitcoinx.read_le_uint64(f.read)
        user_agent = bitcoinx.packing.read_varbytes(f.read)
        start_height = bitcoinx.read_le_int32(f.read)

        v = {'version': version,
             'services': services,
             'timestamp': timestamp,
             'addr_recv': addr_recv,
             'addr_from': addr_from,
             'nonce': nonce,
             'user_agent': user_agent,
             'start_height': start_height}
        return v

    @classmethod
    def deserialize_IPv4_addr_from_version(cls, f):
        # addr fields in the version message do NOT have a timestamp
        services = bitcoinx.read_le_uint64(f.read)
        reserved = f.read(12)
        IPv4 = socket.inet_ntoa(f.read(4))
        port = bitcoinx.read_le_uint16(f.read)
        return {'services': services,
                'IPv4': IPv4,
                'port': port}

    @classmethod
    def deserialize_verack(cls, f):
        # No payload for verack
        return

    @classmethod
    def deserialize_sendheaders(cls, f):
        # No payload
        return

    @classmethod
    def deserialize_sendcmpct(cls, f):
        # ignore
        return f.read()

    @classmethod
    def deserialize_ping(cls, f):
        nonce = bitcoinx.read_le_uint64(f.read)
        return nonce

    @classmethod
    def deserialize_addr(cls, f):
        count = bitcoinx.read_varint(f.read)
        addresses = []
        for i in range(count):
            timestamp = time.ctime(bitcoinx.read_le_uint32(f.read))
            services = bitcoinx.read_le_uint64(f.read)
            reserved = f.read(12)  # IPv6
            IPv4 = socket.inet_ntoa(f.read(4))
            port = bitcoinx.read_le_uint16(f.read)
            addresses.append({'timestamp': timestamp,
                              'services': services,
                              'IPv4': IPv4,
                              'port': port})
        return addresses  # count not returned by choice

    @classmethod
    def deserialize_feefilter(cls, f):
        # ignore
        return

    @classmethod
    def deserialize_reject(cls, f):
        message = bitcoinx.packing.read_varbytes(f.read)
        ccode = f.read(1)
        reason = bitcoinx.packing.read_varbytes(f.read)
        # TODO different ccodes will / won't have "extra data" add mapping to CCODES in simple_spv.constants
        # data = bitcoinx.packing.read_varbytes(f.read) # no data

        ccode_translation = CCODES['0x' + ut.bytes_to_hex(ccode)]

        return message, ccode_translation, reason

    @classmethod
    def deserialize_inv(cls, f):
        message = []
        count = bitcoinx.read_varint(f.read)
        for i in range(count):
            inv_type = bitcoinx.read_le_uint32(f.read)
            inv_hash = bitcoinx.hash_to_hex_str(f.read(32))
            inv_vector = {'count': count,
                          'inv_type': inv_type,
                          'inv_hash': inv_hash}
        message.append(inv_vector)
        return message

    @classmethod
    def deserialize_getheaders(cls, f):
        """for checking my own getheaders request"""
        version = bitcoinx.read_le_uint32(f.read)
        hash_count = bitcoinx.read_varint(f.read)
        block_locator_hashes = []
        for i in range(hash_count):
            block_locator_hashes.append(bitcoinx.hash_to_hex_str(f.read(32)))
        hash_stop = bitcoinx.hash_to_hex_str(f.read(32))

        message = {'version': version,
                   'hash_count': hash_count,
                   'block_locator_hashes': block_locator_hashes,
                   'hash_stop': hash_stop}
        return message

    @classmethod
    def deserialize_headers(cls, f):
        """deserialize block headers into a list of dicts"""
        lst_headers = []
        global headers_stream
        global hashes_stream
        # Store headers temporarily to memory as binary stream
        headers_stream.seek(0)
        headers_stream.write(f.read())

        # make a list of block hashes for validating
        headers_stream.seek(0)
        count = bitcoinx.read_varint(headers_stream.read)  # count of headers
        for i in range(count):
            header = headers_stream.read(80)  # minus final txn count (1 byte)
            headers_stream.read(1)  # discard txn count
            _hash = simple_spv.tools.get_block_hash(header)  # calculates hash as part of validation
            hashes_stream.write(_hash + '\n')

        f.seek(0)

        number_headers = bitcoinx.read_varint(f.read)
        for i in range(number_headers):
            # TODO make into single function call for readability and reuse
            version = bitcoinx.read_le_int32(f.read)
            prev_block = bitcoinx.hash_to_hex_str(f.read(32))
            merkle_root = bitcoinx.hash_to_hex_str(f.read(32))
            timestamp = bitcoinx.read_le_uint32(f.read)
            bits = ut.int_to_hex(bitcoinx.read_le_uint32(f.read))
            nonce = bitcoinx.read_le_uint32(f.read)
            txn_count = bitcoinx.read_varint(f.read)

            block_header = {'version': version,
                            'prev_block_hash': prev_block,
                            'merkle_root': merkle_root,
                            'timestamp': timestamp,
                            'bits': bits,
                            'nonce': nonce,
                            'txn_count': txn_count}

            lst_headers.append(block_header)

        return lst_headers


class Validate:

    @staticmethod
    def validate_block_header(header):
        """ Takes in a single block header; returns True if valid block; False if invalid
            Validation checks to be performed
            (1) checks that calculated block hash is < target (difficulty)
            (2) checks that this hashed block contains a "prev_block_hash" field equal to
                the prior block calculated hash
            (3) check than target is set as per the consensus difficulty adjustment algorithm (NOT DONE HERE)
            see 'validate_header_difficulty()' --> this phase 2 check is done on the whole database in one go """

        # extract nbits as int direct from byte position 72:76 in header
        target = Validate.bits_to_target(bitcoinx.unpack_le_int32(header[72:72 + 4])[0])

        # get block hash
        block_hash = get_block_hash(header)

        prev_hash_que.append(block_hash)

        # check if hash of current block is less than nbits "target"
        is_less_than_target = int(block_hash, 16) < target
        if is_less_than_target:
            pass
        else:
            raise ValueError("hash of current block is not less than nbits target!")

        # check if prev_block_hash matches the last block on record in db
        # genesis block (#0) is not sent with "headers" message so first block is the block after genesis (#1)
        prev_block_hash = bitcoinx.hash_to_hex_str(header[4:36])
        if prev_block_hash == prev_hash_que.pop(0):
            return True
        else:
            return False

    @classmethod
    def validate_headers_batch(cls, f):
        """Takes in "headers" response as byte stream (up to max 2000 headers) and validates"""
        valid_headers = []  # list of [True, True, True...]
        global db_height
        f.seek(0)

        count = bitcoinx.read_varint(f.read)  # count of headers
        for i in range(count):
            header = f.read(80)  # minus final txn count (1 byte)
            f.read(1)  # discard txn count
            valid_headers.append(
                cls.validate_block_header(header))
            db_height += 1

        # check if all true
        if all(i is True for i in valid_headers):
            print("all valid")
        else:
            raise ValueError("Invalid header. Validation result for first 5 headers in batch: ", valid_headers[0:5])

        return True

    @staticmethod
    def bits_to_work(bits):
        return (1 << 256) // (Validate.bits_to_target(bits) + 1)

    @staticmethod
    def bits_to_target(bits):
        """takes int type"""
        if bits == 0:
            return 0
        size = bits >> 24
        assert size <= 0x1d

        word = bits & 0x00ffffff
        assert 0x8000 <= word <= 0x7fffff

        if size <= 3:
            return word >> (8 * (3 - size))
        else:
            return word << (8 * (size - 3))

    @staticmethod
    def target_to_bits(target):
        MAX_TARGET = Validate.bits_to_target(MAX_BITS)
        """takes int type"""
        if target == 0:
            return 0
        target = min(target, MAX_TARGET)
        size = (target.bit_length() + 7) // 8
        mask64 = 0xffffffffffffffff
        if size <= 3:
            compact = (target & mask64) << (8 * (3 - size))
        else:
            compact = (target >> (8 * (size - 3))) & mask64

        if compact & 0x00800000:
            compact >>= 8
            size += 1
        assert compact == (compact & 0x007fffff)
        assert size < 256
        return compact | size << 24

    @staticmethod
    def get_median_time_past(height, headers):
        # list of timestamps from 10 blocks back to next block
        times = [DbManager.get_block_at_height(h, headers)['timestamp']
                 for h in range(max(0, height - 10), height + 1)]
        return sorted(times)[len(times) // 2]  # medial value

    @classmethod
    def get_suitable_block_height(cls, height, headers):
        # avoids blocks with very skewed timestamp
        # select median of the 3 top most blocks as a start point
        # Reference: github.com/Bitcoin-ABC/bitcoin-abc/master/src/pow.cpp#L201
        blocks2 = DbManager.get_block_at_height(height, headers)
        blocks1 = DbManager.get_block_at_height(height - 1, headers)
        blocks = DbManager.get_block_at_height(height - 2, headers)

        if blocks['timestamp'] > blocks2['timestamp']:
            blocks, blocks2 = blocks2, blocks
        if blocks['timestamp'] > blocks1['timestamp']:
            blocks, blocks1 = blocks1, blocks
        if blocks1['timestamp'] > blocks2['timestamp']:
            blocks1, blocks2 = blocks2, blocks1

        return blocks1['height']

    @classmethod
    def get_bits(cls, height, header_db):
        """Return calculated bits for the given height based on prior header
        - adapted from electron cash v3.3.4 blockchain.py"""

        # Genesis
        if height == 0:
            return MAX_BITS

        # Get prior header from header_db if possible
        prior = DbManager.get_block_at_height(height - 1, header_db)
        if prior is None:
            raise Exception("get_bits missing header height {} ".format(height - 1))

        bits = int(prior['bits'], 16)

        # NOV 13 HF DAA
        prev_height = height - 1
        daa_mtp = cls.get_median_time_past(prev_height, header_db)

        if daa_mtp >= 1510600000:

            """if NetworkConstants.TESTNET:
                # testnet 20 minute rule
                if header['timestamp'] - prior['timestamp'] > 20*60:
                    return MAX_BITS"""

            # determine block range
            daa_starting_height = cls.get_suitable_block_height(prev_height - 144, header_db)
            daa_ending_height = cls.get_suitable_block_height(prev_height, header_db)

            # calculate cumulative work (EXcluding work from block daa_starting_height, INcluding work from block
            # daa_ending_height)
            daa_cumulative_work = 0
            for daa_i in range(daa_starting_height + 1, daa_ending_height + 1):
                daa_prior = tools.DbManager.get_block_at_height(daa_i, header_db)
                daa_bits_for_a_block = int(daa_prior['bits'], 16)
                daa_work_for_a_block = cls.bits_to_work(daa_bits_for_a_block)
                daa_cumulative_work += daa_work_for_a_block

            # calculate and sanitize elapsed time
            daa_starting_timestamp = tools.DbManager.get_block_at_height(daa_starting_height, header_db)['timestamp']
            daa_ending_timestamp = tools.DbManager.get_block_at_height(daa_ending_height, header_db)['timestamp']
            daa_elapsed_time = daa_ending_timestamp - daa_starting_timestamp

            # High - low filter
            if daa_elapsed_time > 172800:  # If > 2 days
                daa_elapsed_time = 172800
            if daa_elapsed_time < 43200:  # If <0.5 days
                daa_elapsed_time = 43200

            # calculate and return new target
            daa_Wn = (daa_cumulative_work * 600) // daa_elapsed_time
            daa_target = (1 << 256) // daa_Wn - 1
            daa_retval = cls.target_to_bits(daa_target)
            daa_retval = int(daa_retval)
            return daa_retval

        # END OF NOV-2017 DAA

        # Difficulty adjustment interval?
        if height % 2016 == 0:
            # print("loading block at height:", height)
            return cls.get_new_bits(height, header_db)

        # If testnet
        """if NetworkConstants.TESTNET:
            # testnet 20 minute rule
            if header_db['timestamp'] - prior['timestamp'] > 20*60:
                return MAX_BITS
            return self.read_header(height // 2016 * 2016, chunk)['bits']"""

        # bitcoin cash EDA 1st August
        # Can't go below minimum, so early bail
        if bits == MAX_BITS:
            return bits

        mtp_6blocks = (cls.get_median_time_past(height - 1, header_db) -
                       cls.get_median_time_past(height - 7, header_db))

        # TODO find out at what height this was introduced and consider skipping this step until then
        #  (would speed up initial (full) sync time by quite a bit due to all the calls to get_block_at_height()
        if mtp_6blocks < 12 * 3600:
            return bits
        # If it took over 12hrs to produce the last 6 blocks, increase the
        # target by 25% (reducing difficulty by 20%).
        target = cls.bits_to_target(bits)
        target += target >> 2

        return cls.target_to_bits(target)

    @classmethod
    def get_new_bits(cls, height, header_db):
        assert height % 2016 == 0
        # Genesis
        if height == 0:
            return MAX_BITS
        first = DbManager.get_block_at_height(height - 2016, header_db)
        prior = DbManager.get_block_at_height(height - 1, header_db)

        prior_target = cls.bits_to_target(int(prior['bits'], 16))

        target_span = 14 * 24 * 60 * 60
        span = prior['timestamp'] - first['timestamp']
        span = min(max(span, target_span // 4), target_span * 4)
        new_target = (prior_target * span) // target_span
        return cls.target_to_bits(new_target)

    @classmethod
    def validate_batch_difficulty(cls, headers, main_database):
        """validates new batch of headers against EXISTING main_database
        otherwise throws out an error when trying to find PRIOR header"""
        # Note new headers have been saved to db too so it's all available in db
        assert type(headers is dict)
        lst = []
        index_offset = headers[0]['height'] - 1  # Base height of batch to validate using global db
        for i in range(index_offset, len(headers) + index_offset):
            try:
                header_height = i
                # print(simple_spv.tools.get_block_at_height(header_height, headers)['bits'])
                bits_attr = int(DbManager.get_block_at_height(header_height, main_database)['bits'], 16)
                # If block #1 - skip checks and go back to top of loop
                if header_height == 1:
                    lst.append(True)
                    continue

                # Get calculated bits for the PREVIOUS header and compare to current
                calculated_bits = cls.get_bits(header_height, main_database)
                # If calculated difficulty matches
            except Exception as e:
                raise e

            if calculated_bits == bits_attr:
                lst.append(True)
                continue

            else:
                # REMEMBER - bits change every block...
                lst.append(False)
                print(int(DbManager.get_block_at_height(header_height, main_database)['bits'], 16))
                print("calculated bits:", calculated_bits, "bits_attr:", bits_attr, header_height)
                raise ValueError("fails at block:", header_height)

        # check if all true
        if all(i is True for i in lst):
            print("all valid")
        else:
            raise ValueError("Invalid header. Validation result for first 5 headers in batch: ", lst[0:5])

        return True


class Handlers:
    """
    Created a class to make use of the getattr() function
    for selecting the appropriate handler for recv'd message
    types from the main spv_daemon event loop
    - see sockets.handle() function"""

    start_height = 0
    global db

    @classmethod
    def handle_version(cls, sock, message_header, message):
        print('handling version...')

        # Extract "start_height"
        cls.start_height = message['start_height']
        print("start_height:", cls.start_height)

        return sock.send_verack()

    @classmethod
    def handle_verack(cls, sock, message_header, message):
        """implies that handshake has been completed
        defaults to get_headers currently to sync spv db"""
        # TODO - I don't like this "actual_db_height business...
        actual_db_height = db_height - latest_checkpoint_height
        hashes_stream.seek(0)
        _hashes = hashes_stream.readlines()
        last_hash = _hashes[len(_hashes) - 1]
        return sock.send_getheaders(last_hash.strip())  # gets the hash at the top

    @classmethod
    def handle_headers(cls, sock, message_header, message):
        global db
        global previous_validation_height
        # Validate this batch of headers (operates on binary "headers_stream")
        print("validating batch of block headers... (", db_height + 1, " to ", db_height + len(message) + 1, ")")
        time_start = time.time()
        headers_stream.seek(0)
        Validate.validate_headers_batch(headers_stream)

        headers_stream.seek(0)
        simple_spv.headers_stream = io.BytesIO()
        time_taken = time.time() - time_start
        print("validation time: {:.2f} seconds".format(time_taken))
        # Store the validated headers as json serialized dicts
        for i, header in zip(range(len(message)), message):
            # add 'height' key: value pair to headers
            header['height'] = (db_height + i - len(message) + 1)
        temp_headers_store.extend(message)

        # if next header in sequence is < "start_height" at time of version message...
        if db_height < cls.start_height:
            print("remote node height", cls.start_height, "> than db height:", db_height,
                  "so getting next batch of block headers")
            hashes_stream.seek(0)
            # db_height is incremented at validation
            actual_db_height = db_height - latest_checkpoint_height  # Must recalculate

            block_locator_hash = hashes_stream.readlines()[
                actual_db_height - 1]  # index = db_height-1 (index starts at 0 not 1)
            block_locator_hash = block_locator_hash.strip()  # convert to str

            sock.send_getheaders(block_locator_hash)

        if db_height >= cls.start_height:
            # phase 1 validation complete and all block headers up to "start_height" recv'd
            # commence full validation of difficulty adjustments from Genesis through to current height of db
            print("all headers received and phase 1 validation complete!")
            print("saving headers into headers.json database...")
            tools.DbManager.append_to_db('headers.json', temp_headers_store)

            # TODO only validate from previous validated height - 2000 blocks
            #  e.g. Validate.validate_batch_difficulty(db[previous_validation_height - 2000 :])
            global previous_validation_height
            if previous_validation_height == 0:
                print("validating difficulty adjustment... ")
                pass
            elif previous_validation_height > 1:
                print("validating difficulty adjustment from 2000 headers deep "
                      "(previously validated height was:", previous_validation_height)
                pass

            # Avoid unnecessary loading from disc
            if len(temp_headers_store) is not 0:
                db.extend(temp_headers_store)
            start = time.time()
            if previous_validation_height == 0:
                faster_validate.validate_batch_difficulty(db, db)
                stop = time.time() - start
                print("Validation time:", stop, 'sec for', db_height, "headers.")
            if previous_validation_height > 1:
                Validate.validate_batch_difficulty(db[previous_validation_height - 2000:], db)
                stop = time.time() - start
                print("Validation time:", stop, 'sec for latest', 2000, "headers.")
            stop = time.time() - start
            print("saving new validation height")
            previous_validation_height = db_height  # update

            # TODO Should then trigger BitIndex look up of UTXOs using private key

            print("handle_headers done...")

        return

    @classmethod
    def handle_ping(cls, sock, message_header, message):
        nonce = message
        print(nonce)
        return sock.send_pong(nonce)

    @classmethod
    def handle_sendheaders(cls, sock, message_header, message):
        # no response required
        return

    @classmethod
    def handle_sendcmpct(cls, sock, message_header, message):
        # no response required
        return

    @classmethod
    def handle_feefilter(cls, sock, message_header, message):
        # ignore
        return

    @classmethod
    def handle_addr(cls, sock, message_header, message):
        # ignore
        return

    @classmethod
    def handle_reject(cls, sock, message_header, message):
        print('[ERROR]:', message)

    @classmethod
    def handle_inv(cls, sock, message_header, message):
        # ignore for now
        # in time I will be very interested in registering new transactions to my own "mempool" (type = 1)
        for inv_vector in message:
            print('count:', inv_vector['count'], 'inv_type:', INV_TYPES[inv_vector['inv_type']], 'inv_hash:',
                  inv_vector['inv_hash'])


class SimpleSPV(object):
    """ Module for socket connections to bitcoin network. Main module for coordinating high order functions"""

    def __init__(self):
        self.peers = self.get_peers()
        self.ip = random.choice(self.peers)
        self.sock = self.get_socket(self.ip)
        self.buffer = io.BytesIO()

    def __repr__(self):
        return self.__class__.__name__ + " Object"

    @classmethod
    def get_peers(cls):
        """ Returns a list of ip addresses from seed list.
        Seeds: [seed.bitcoinsv.io]"""
        ip_lst = []
        answers = dns.resolver.query('seed.bitcoinsv.io')
        for data in answers:
            ip_lst.append(data.address)
        return ip_lst

    @classmethod
    def get_socket(cls, ip_addr):
        """returns socket to an ip address on port 8333"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip_addr, 8333))
        return sock

    @classmethod
    def set_checkpoint(cls, new_checkpoint_hash, new_checkpoint_height):
        global latest_checkpoint_hash, latest_checkpoint_height
        latest_checkpoint_hash = new_checkpoint_hash
        latest_checkpoint_height = new_checkpoint_height
        return latest_checkpoint_hash, latest_checkpoint_height

    def send_msg(self, command, payload):
        """for generic use"""
        return self.sock.send(Serialize.make_final_message(command, payload))

    def send_version(self):
        return self.sock.send(Serialize.make_final_message("version", Serialize.version_payload()))

    def send_verack(self):
        return self.sock.send(Serialize.make_final_message("verack", Serialize.verack_payload()))

    def send_pong(self, nonce):
        return self.sock.send(Serialize.make_final_message("pong", Serialize.pong_payload(nonce)))

    def send_getheaders(self, block_locator_hash=latest_checkpoint):
        """use this function with leading zero hash"""
        print("block locator in send_get headers: ", block_locator_hash)
        return self.sock.send(
            Serialize.make_final_message("getheaders",
                                         Serialize.get_headers_payload(block_locator_hash)))

    # TODO make this work
    def send_rawtx(self):
        return self.sock.send(Serialize.make_final_message("rawtx", Serialize.rawtx_payload()))

    # TODO I'm getting a lot of time outs halfway through sync... implement try / except and save db and reconnect.
    def receive_raw_bytes(self, buffer_size):
        return self.sock.recv(buffer_size)

    def close(self):
        """close the socket"""
        self.sock.close()

    def handle(self, message_header, message=None):
        """selects appropriate handler function"""
        message_header_command = message_header['command']
        handler_func_name = "handle_" + message_header_command
        print(handler_func_name)
        handler_func = getattr(Handlers, handler_func_name, None)
        handler_func(self, message_header, message)

    def deserialize_all_messages(self):
        """This method is called inside the main spv_daemon loop and
        deserializes all messages in self.buffer and will independently
        recv the rest of the buffer if needed for long messages. For
        example "headers" with up to 2000 headers in a single message."""

        messages = []

        # deserialize all messages in buffer and if incomplete messages remain, recv more buffer until complete
        while self.buffer.getbuffer().nbytes > 0:

            # Calculate the size of the buffer
            self.buffer.seek(0, os.SEEK_END)
            buffer_size = self.buffer.tell()

            # Check if a complete message header is present
            if buffer_size < struct.calcsize("i 12s i i"):
                print("incomplete header")
                self.buffer.seek(0, os.SEEK_END)
                self.buffer.write(
                    self.sock.recv(1024 * 8))  # potentially blocking but I'll risk it... should be more to come...
                continue  # return to top of loop to try again with hopefully complete header

            # check if message begins with network magic as expected
            self.buffer.seek(0)
            if self.buffer.read(4) == BITCOIN_SV_MAGIC:
                pass
            else:
                raise ValueError(
                    "message does not begin with bitcoin SV network magic: 0xe3e1f3e8")  # should never happen

            # Go to the beginning of the buffer
            self.buffer.seek(0)

            # Deserialize header
            try:
                header_bytes = self.buffer.read(struct.calcsize("i 12s i i"))
                message_header = Deserialize.deserialize_message_header(header_bytes)
            except Exception as e:
                print(e)
                print("couldn't deserialize message header")

            total_length = len(header_bytes) + message_header['length']

            # Check if complete message is present
            if buffer_size < total_length:
                # print('buffer size less than total length of message')
                self.buffer.seek(0, os.SEEK_END)  # puts buffer to end so that recv(1024*8) is appended to the end
                self.buffer.write(self.sock.recv(1024 * 8))
                continue  # go directly to top of loop to try again with hopefully complete message

            # Read in payload
            payload = self.buffer.read(message_header['length'])

            # Re-initialise self.buffer with remainder only (clips away processed message)
            self.buffer = io.BytesIO(self.buffer.read())

            payload_checksum = ut.bytes_to_hex(simple_spv.tools.checksum(payload))
            # Check if the checksum is valid

            if payload_checksum == message_header['checksum']:
                with open('logger.txt', 'a') as outfile:
                    outfile.write('checksums match for: ' + str(message_header['command']) + "\n")

                    # Call appropriate deserialization function from deserializers class
                message_header_command = message_header['command']
                deser_func_name = "deserialize_" + message_header_command
                print(deser_func_name)
                deser_func = getattr(Deserialize, deser_func_name, None)

                f = io.BytesIO(payload)
                message = deser_func(f)
                # print(message)
            else:
                raise ValueError("something went wrong with deserialization of payload")

            messages.append((message_header, message))
        # Success
        # Return messages for handling in main loop
        return messages

    def start_daemon(self):
        spv_daemon(self)

def check_for_existing_database():
    print("checking for existing database...")
    # TODO simple data integrity check on the last line and check if there is a complete line of
    #  json present if not then just delete the last entry and you're golden! :)
    global db
    global db_height
    global prev_hash_que
    global previous_validation_height
    if os.path.isfile('headers.json'):
        print("found! loading...")
        db = tools.DbManager.load_db('headers.json')
        if len(db) is not 0:
            db_height = db[len(db) - 1]['height']
            for h in db:
                if h['height'] == 1:  # skip first block because we are "cheating" here using "prev_block" field
                    pass
                else:
                    hashes_stream.write(h['prev_block_hash'] + '\n')  # hashes as strings separated by "\n"
            # Then actually calculate the hash for the last one
            top_db_hash = tools.get_block_hash(Serialize.block_header_payload(db[len(db) - 1]))
            hashes_stream.write(top_db_hash + '\n')
            # reconfigure for validation
            prev_hash_que = [top_db_hash]
            previous_validation_height = len(db)
    else:
        tools.DbManager.new_db('headers.json')


def raw_user_input(message):
    """sends a serialized message to remote node via daemon"""
    # ADD SENDING FUNCTION HERE ADD checks for validity of message IMPERATIVE to add sock_lock to every usage of
    # socket send or recv statements otherwise could potentially corrupt the data in the buffer. To make it all
    # tidier - one possibility is to run all code through a single thread locking send / recv function with parameter
    # to select which one... This way I can have "one thread lock to rule them all" (and seeing as though this I/O
    # operation by the user will be expected to be brief (sending requests only) It should - in theory have minimal
    # impact on performance - even if it causes "collateral" blocking of some associated CPU intensive tasks for that
    # brief moment.
    with sock_lock:
        print(b'daemon sending: ' + message + b"...")


# TODO add support for syncing from checkpoint -  currently only goes from genesis forward
def spv_daemon(sock):
    """
    listens for incoming data from remote node and responds with appropriate handlers.
    requires a "sock" object of class SPV_socket()
    intended to be run on a daemon thread of it's own"""
    with print_lock:
        print('starting spv daemon thread...')

    check_for_existing_database()

    sock.send_version()

    open('logger.txt', 'w').close()
    with open('logger.txt', 'a') as outfile:
        while True:
            time.sleep(0.5)

            # Recv (blocking step)
            with sock_lock:
                data = sock.receive_raw_bytes(1024 * 8)

            if not data:
                print('Close the connection')
                sock.close()
                break

            sock.buffer.write(data)
            sock.buffer.seek(0)

            # Deserialize all messages in buffer
            messages = sock.deserialize_all_messages()

            # Handlers
            for message_header, message in messages:
                sock.handle(message_header, message)
                # log
                outfile.write(str(message_header) + '\n')


if __name__ == '__main__':
    s = SimpleSPV()

    thread1 = threading.Thread(target=spv_daemon, args=([s]))
    thread1.start()
