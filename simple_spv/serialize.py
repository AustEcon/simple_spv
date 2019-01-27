import io
import time
import struct
import random
from bitcash import utils as ut

from simple_spv.tools import *

class Serialize:

    @staticmethod
    def make_final_message(cmd, payload):
        """
        Adds standard header to payload
        Format: magic + command + length + check + payload
        Doesn't have the "relay" flag added here yet.
        Network magic 0xe3e1f3e8 set for Bitcoin SV network"""
        magic = bytes.fromhex('e3e1f3e8')  # Main network
        command = cmd.encode('ASCII') + (12 - len(cmd)) * b"\00"
        length = struct.pack("I", len(payload))
        check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return magic + command + length + check + payload

    @staticmethod
    def version_payload():
        """creates a versionMessage payload"""
        version = struct.pack("i", 70015)
        services = struct.pack("Q", 0)
        timestamp = struct.pack("q", int(time.time()))
        addr_recv = struct.pack("Q", 0)
        addr_recv += struct.pack(">16s", "127.0.0.1".encode('utf-8'))
        addr_recv += struct.pack(">H", 8333)
        addr_from = struct.pack("Q", 0)
        addr_from += struct.pack(">16s", "127.0.0.1".encode('utf-8'))
        addr_from += struct.pack(">H", 8333)
        nonce = struct.pack("Q", random.getrandbits(64))
        user_agent_bytes = struct.pack("B", 0)
        height = struct.pack("i", 0)
        payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent_bytes + height
        return payload

    @staticmethod
    def verack_payload():
        """verack has an empty payload; checksum == 5DF6E0E2"""
        payload = ''.encode('ascii')
        return payload

    @staticmethod
    def pong_payload(nonce):
        payload = bitcoinx.pack_le_uint64(nonce)
        return payload

    @staticmethod
    def get_headers_payload(block_locator_hash,
                            hash_stop="0000000000000000000000000000000000000000000000000000000000000000"):
        """makes a getheaders serialized payload"""
        version = struct.pack("i", 70015)
        hash_count = ut.int_to_varint(1)
        block_locator_hash = ut.hex_to_bytes(ut.flip_hex_byte_order(block_locator_hash))
        hash_stop = ut.hex_to_bytes(hash_stop)

        payload = version + hash_count + block_locator_hash + hash_stop
        return payload

    @staticmethod
    def block_header_payload(header, include_txn_count=False):
        version = bitcoinx.pack_le_int32(header['version'])
        prev_block = bitcoinx.hex_str_to_hash(header['prev_block_hash'])
        merkle_root = bitcoinx.hex_str_to_hash(header['merkle_root'])
        timestamp = bitcoinx.pack_le_uint32(header['timestamp'])
        bits = bitcoinx.pack_le_uint32(int(header['bits'],16))
        nonce = bitcoinx.pack_le_uint32(header['nonce'])
        # for hashing purposes (most likely use case of this function) exclude txn_count
        if include_txn_count:
            txn_count = bitcoinx.pack_varint(header['txn_count'])

        stream = io.BytesIO()
        for field in [version, prev_block, merkle_root, timestamp, bits, nonce]:
            stream.write(field)

        if include_txn_count:
            stream.write(txn_count)

        stream.seek(0)
        block_header = stream.read()
        # For hashing
        if not include_txn_count:
            assert len(block_header) == 80, "block header did not serialize to 80 bytes"
        return block_header
