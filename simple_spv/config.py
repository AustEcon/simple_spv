import io
from simple_spv.constants import GENESIS_BLOCK_HASH


class Config(object):
    """configuration object that can be modified later as needed"""
    def __init__(self):
        # Defaults set for full sync (from Genesis)
        self.latest_checkpoint = GENESIS_BLOCK_HASH
        self.latest_checkpoint_height = 0  # (genesis)
        self.prev_hash_que = [GENESIS_BLOCK_HASH]
        self.db_height = self.latest_checkpoint_height
        self.previous_validation_height = self.db_height
        self.headers_stream = io.BytesIO()
        self.hashes_stream = io.StringIO(self.latest_checkpoint)
        self.temp_headers_store = []  # avoids writing to disc

        # Headers as list of dicts --> serialized to json format when stored to disc
        self.db = []  # promptly populated on running daemon
