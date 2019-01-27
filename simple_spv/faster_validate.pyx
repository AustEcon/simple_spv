# cython: language_level=3
# distutils: language = c++
from libcpp.vector cimport vector

GENESIS_BLOCK_HASH = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
GENESIS_BLOCK_VERSION = 1
GENESIS_PREVIOUS_BLOCK_HASH = None
GENESIS_MERKLE_ROOT = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
GENESIS_BLOCK_TIMESTAMP = 1231006505
GENESIS_BLOCK_BITS = '1d00ffff'
GENESIS_NONCE = 2083236893

GENESIS_DICTIONARY = {
    'version': 1,
    'prev_block_hash': GENESIS_PREVIOUS_BLOCK_HASH,
    'merkle_root':     GENESIS_MERKLE_ROOT,
    'timestamp': GENESIS_BLOCK_TIMESTAMP,
    'bits': GENESIS_BLOCK_BITS,
    'nonce': GENESIS_NONCE,
    'txn_count': 0,
    'height': 0
}

cdef int MAX_BITS = 0x1d00ffff


cdef bits_to_work(const int bits):
    return (1 << 256) // (bits_to_target(bits) + 1)


cdef bits_to_target(const int bits):
    """takes int type"""
    cdef int size

    if bits == 0:
        return 0
    size = bits >> 24
    # assert size <= 0x1d
    word = bits & 0x00ffffff
    # assert 0x8000 <= word <= 0x7fffff
    if size <= 3:
        return word >> (8 * (3 - size))
    else:
        return word << (8 * (size - 3))

cdef get_block_at_height(int height, headers):
    """headers in list of dictionaries format"""
    cdef int height_bottom
    if height == 0:
        print('retrieving genesis block...')
        return GENESIS_DICTIONARY
    else:
        height_bottom = headers[0]['height']  # TODO can pass in height_bottom as an argument to save recompute
        result = headers[height_bottom + height - 2]
        assert height == result['height'], ("failed at height: " + str(height))
        return result


cdef int target_to_bits(target):
    MAX_TARGET = bits_to_target(MAX_BITS)
    """takes int type"""
    if target == 0:
        return 0
    target = min(target, MAX_TARGET)
    cdef int size = (target.bit_length() + 7) // 8
    cdef int mask64 = 0xffffffffffffffff
    cdef int compact
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


cdef int get_median_time_past(int height, headers):
    # list of timestamps from 10 blocks back to next block
    times = [get_block_at_height(h, headers)['timestamp']
             for h in range(max(0, height - 10), height + 1)]
    return sorted(times)[len(times) // 2]  # medial value


cdef int get_suitable_block_height(int height, headers):
    # avoids blocks with very skewed timestamp
    # select median of the 3 top most blocks as a start point
    # Reference: github.com/Bitcoin-ABC/bitcoin-abc/master/src/pow.cpp#L201
    blocks2 = get_block_at_height(height, headers)
    blocks1 = get_block_at_height(height - 1, headers)
    blocks = get_block_at_height(height - 2, headers)

    if blocks['timestamp'] > blocks2['timestamp']:
        blocks, blocks2 = blocks2, blocks
    if blocks['timestamp'] > blocks1['timestamp']:
        blocks, blocks1 = blocks1, blocks
    if blocks1['timestamp'] > blocks2['timestamp']:
        blocks1, blocks2 = blocks2, blocks1

    return blocks1['height']


cdef get_bits(int height, header_db):
    """Return calculated bits for the given height based on prior header
    - adapted from electron cash v3.3.4 blockchain.py"""

    # Genesis
    if height == 0:
        return MAX_BITS

    # Get prior header from header_db if possible
    prior = get_block_at_height(height - 1, header_db)
    if prior is None:
        raise Exception("get_bits missing header height {} ".format(height - 1))

    cdef int bits = int(prior['bits'], 16)

    # NOV 13 HF DAA
    cdef int prev_height = height - 1
    cdef int daa_mtp = get_median_time_past(prev_height, header_db)


    cdef int daa_starting_height
    cdef int daa_ending_height
    cdef int daa_bits_for_a_block

    cdef int daa_starting_timestamp
    cdef int daa_ending_timestamp
    if daa_mtp >= 1510600000:

        """if NetworkConstants.TESTNET:
            # testnet 20 minute rule
            if header['timestamp'] - prior['timestamp'] > 20*60:
                return MAX_BITS"""

        # determine block range
        daa_starting_height = get_suitable_block_height(prev_height - 144, header_db)
        daa_ending_height = get_suitable_block_height(prev_height, header_db)

        # calculate cumulative work (EXcluding work from block daa_starting_height, INcluding work from block
        # daa_ending_height)
        daa_cumulative_work = 0
        for daa_i in range(daa_starting_height + 1, daa_ending_height + 1):
            daa_prior = get_block_at_height(daa_i, header_db)
            daa_bits_for_a_block = int(daa_prior['bits'], 16)
            daa_work_for_a_block = bits_to_work(daa_bits_for_a_block)
            daa_cumulative_work += daa_work_for_a_block

        # calculate and sanitize elapsed time
        daa_starting_timestamp = get_block_at_height(daa_starting_height, header_db)['timestamp']
        daa_ending_timestamp = get_block_at_height(daa_ending_height, header_db)['timestamp']
        daa_elapsed_time = daa_ending_timestamp - daa_starting_timestamp

        # High - low filter
        if daa_elapsed_time > 172800:  # If > 2 days
            daa_elapsed_time = 172800
        if daa_elapsed_time < 43200:  # If <0.5 days
            daa_elapsed_time = 43200

        # calculate and return new target
        daa_Wn = (daa_cumulative_work * 600) // daa_elapsed_time
        daa_target = (1 << 256) // daa_Wn - 1
        daa_retval = target_to_bits(daa_target)
        daa_retval = int(daa_retval)
        return daa_retval

    # END OF NOV-2017 DAA

    # Difficulty adjustment interval?
    if height % 2016 == 0:
        # print("loading block at height:", height)
        return get_new_bits(height, header_db)

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

    mtp_6blocks = (get_median_time_past(height - 1, header_db) -
                   get_median_time_past(height - 7, header_db))

    # TODO find out at what height this was introduced and consider skipping this step until then
    #  (would speed up initial (full) sync time by quite a bit due to all the calls to get_block_at_height()
    if mtp_6blocks < 12 * 3600:
        return bits
    # If it took over 12hrs to produce the last 6 blocks, increase the
    # target by 25% (reducing difficulty by 20%).
    target = bits_to_target(bits)
    target += target >> 2

    return target_to_bits(target)


cdef int get_new_bits(int height, header_db):
    assert height % 2016 == 0
    # Genesis
    if height == 0:
        return MAX_BITS
    first = get_block_at_height(height - 2016, header_db)
    prior = get_block_at_height(height - 1, header_db)

    prior_target = bits_to_target(int(prior['bits'], 16))

    cdef int target_span = 14 * 24 * 60 * 60
    cdef int span
    span = prior['timestamp'] - first['timestamp']
    span = min(max(span, target_span // 4), target_span * 4)
    new_target = (prior_target * span) // target_span
    return target_to_bits(new_target)


cpdef validate_batch_difficulty(headers, main_database):
    """validates new batch of headers against EXISTING main_database
    otherwise throws out an error when trying to find PRIOR header"""
    # Note new headers have been saved to db too so it's all available in db
    assert type(headers is dict)
    cdef vector[int] lst
    cdef int index_offset = headers[0]['height'] - 1  # Base height of batch to validate using global db
    cdef int i
    cdef int bits_attr

    print("index offset:", index_offset)
    for i in range(index_offset, len(headers) + index_offset):
        header_height = i + index_offset
        # print(simple_spv.get_block_at_height(header_height, headers)['bits'])
        bits_attr = int(get_block_at_height(header_height, main_database)['bits'], 16)
        # If block #1 - skip checks and go back to top of loop
        if header_height == 1:
            lst.push_back(1)
            continue

        # Get calculated bits for the PREVIOUS header and compare to current
        calculated_bits = get_bits(header_height, main_database)
        # If calculated difficulty matches

        if calculated_bits == bits_attr:
            lst.push_back(1)
            continue

        else:
            # REMEMBER - bits change every block...
            lst.push_back(0)
            # TODO consider statically typing get_block_at_height function vars for cython extension
            print(int(get_block_at_height(header_height, main_database)['bits'], 16))
            print("calculated bits:", calculated_bits, "bits_attr:", bits_attr, header_height)
            raise ValueError("fails at block:", header_height)

    # check if all true
    switch = 1  # True
    for i in lst:
        if i is 1:
            continue
        elif i is 0:  # False
            switch = 0
    if switch == 1:
        print("all valid")
        return True
    else:
        raise ValueError("Invalid header. Validation result for first 5 headers in batch: ", lst[0:5])
        return False
