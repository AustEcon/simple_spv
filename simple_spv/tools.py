import sys
import hashlib
import json
import time
import json_lines
import os

from bitcash import utils
import bitcoinx
from simple_spv.constants import GENESIS_DICTIONARY


class DbManager:

    @staticmethod
    def get_block_at_height(height, headers):
        """headers in list of dictionaries format"""
        if height == 0:
            print('retrieving genesis block...')
            return GENESIS_DICTIONARY

        else:
            height_bottom = headers[0]['height']  # TODO can pass in height_bottom as an argument to save recompute
            result = headers[height_bottom + height - 2]
            assert height == result['height']
            return result

    @classmethod
    def integrity_check_before_append(cls, file, headers):
        """data integrity check"""
        if len(headers) == 0:
            print('no further headers received; abort append')
            return False
        base_height_new_headers = headers[0]['height']
        if os.path.isfile(file):
            try:
                # check data integrity of db
                db = cls.load_db(file)
                assert isinstance(db, list)  # List of...
                # if empty headers.json
                if len(db) == 0 and base_height_new_headers == 1:
                    return True

                if len(db) > 0:
                    assert isinstance(db[0], dict)  # Dicts...
                    # check that new headers begin at precisely the very next block in the sequence
                    top_height_db = db[len(db) - 1]["height"]
                    er_msg = ("new headers are out of sequence at base height: " + str(base_height_new_headers) +
                              " compared to db at height: " + str(top_height_db))
                    print("checking!")
                    assert top_height_db == base_height_new_headers - 1, er_msg
                    return True

            except IOError as e:
                print(e)
                print(file, "Error opening and writing to headers.json file. Database likely corrupted")
                sys.exit()

        else:
            # create new with 'w' mode
            print("No file exists. creating new before append...")
            cls.new_db(file)
            if base_height_new_headers == 1:
                return True

    @classmethod
    def append_to_db(cls, file, headers):
        """db is dicts stored line by line in json string format

        - if file doesn't exist - creates new headers.json with new_headers
        - otherwise performs data integrity check and appends new headers to the end of the file"""
        # if file already exists
        if cls.integrity_check_before_append(file, headers):
            with open(file, 'a') as f:
                start = time.time()
                for i in headers:
                    f.write(json.dumps(i) + '\n')
                stop = time.time() - start
                print(stop, 'sec')

        else:
            print("something went wrong")
            return

    @staticmethod
    def erase_db(file):
        """restores to empty list"""
        open(file, 'w').close()

    new_db = erase_db

    @staticmethod
    def load_db(file):
        """basic buffered reader to workaround MemoryError with opening / loading large json file"""
        if os.path.isfile(file):
            try:
                start = time.time()
                db = []
                with open(file, 'r') as f:
                    for item in json_lines.reader(f):
                        db.append(item)
                stop = time.time() - start
                print("load_db time: ", stop, 'sec')
                return db
            except Exception as e:
                print(file, "is probably corrupted. Creating empty db now...")
                DbManager.erase_db(file)
                raise e

        else:
            # corrupt...
            print("database not found. creating new")
            DbManager.new_db(file)


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def reverse_hash(hex_string):
    hex_string = bitcoinx.hex_str_to_hash(hex_string)[::-1]
    return bitcoinx.hash_to_hex_str(hex_string)


def bytes_to_hex(binary):
    """bytes to hex"""
    return utils.hexlify(binary)


def get_block_hash(header_bin):
    """takes in bytes outputs hex string"""
    _hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
    return reverse_hash(_hash.hex())


def hex_to_int(num):
    """takes a hex string"""
    return int(num, 16)


def int_to_hex(num):
    """takes an int - returns a hex string with leading 0x"""
    return hex(num)
