Simple SPV (Incomplete)
=======================

::

  Licence: MIT Licence
  Author: AustEcon[SV]
  Language: Python

.. image:: https://img.shields.io/badge/pypi-v0.1-orange.svg
    :target: https://pypi.org/

.. image:: https://img.shields.io/badge/bitcoin-SV-brightgreen.svg
    :target: https://pypi.org/

.. image:: https://img.shields.io/badge/python-%203.7-blue.svg
    :target: https://www.python.org/downloads/


Getting started
===============

Simple SPV is designed to be an easy-to-use library for directly accessing the p2p bitcoin (SV) network
over tcp/ip connections to remote nodes - i.e. you do NOT require bitcoind or any rpc authorisation keys etc.
permissionless access. It just works.

This library aims to:

- solve the issue of over-reliance on block explorer servers for sending and receiving transaction data (which can get DOS attacked, have more latency and often times simply do not provide an api for sending rawtx data - especially over testnet)
- be a minimalist educational resource for developers who are familiar with python and want to take a look under the hood of how the p2p bitcoin protocol works
- be an easy-to-use foundation for the rapid proliferation of client side bitcoin applications written in python
- to be optimised to a performance level meeting the requirements of most client side spv applications (refactoring and writing c extensions only by popular demand / on an as-needed basis)

To install (recommended method)::

    pip install simple_spv

Or you can use the setup.py

Linux::

    sudo apt-get install python3-setuptools
    python3 setup.py install

Windows::

    pip install python3-setuptools
    python3 setup.py install

This will download and install the Python dependencies used by
Simple SPV.

To import and run::

    >>> from simple_spv import spv
    >>> my_spv = spv.SimpleSPV()  # multiple configuration options for this constructor
    >>> my_spv.start_daemon()           # starts spv_daemon on a separate thread as a background process
    starting daemon...
    syncing...
    [########################     ] 89% (522256 / 533789 headers)

Requests to remote nodes can be sent concurrently while this process goes on in the background. So there's no need to wait around. Later versions will also add in the option (or maybe default) of only syncing from ~ 2000 block headers deep (which should be very fast at only 81 bytes per header)

After syncing, the daemon verifies the difficulty adjustment of the headers.

At this point the daemon will continue to run in the background and update your "headers.json"
database file with any new blocks that are broadcast over the network. It will also listen
for updates on any transactions / address information of interest (either specified in config.py; at
initial construction of the my_spv object, or subsequently specified for example like this. ::

    # returns a python dict if found; otherwise returns False;
    # by default only requests from 2 random peers
    >>> my_spv.get_tx("khfo41269ls2a5jlioh241lfafa410agsa0fgsafgsalkhfsahkjfsaikfhs", peers=2)
    # TODO feature not added yet

To construct a raw transaction for sending is easy but you will need a private key for signing.
This library uses **bitsv** as a dependency for it's main method of generating transactions.
https://github.com/AustEcon/bitsv/blob/master/README.rst - a minimalist framework for working
with private keys, signatures and generating rawtx (with or without OP_RETURN data).

.. code-block:: python

    >>> from simple_spv import bitsv
    >>> my_key = bitsv.Key('WIF Compressed (base58) here')
    >>> my_key.get_unspents() #necessary step --> updates my_key.unspents object variable
    >>> my_key.get_balance()
    900000
    >>> outputs = [('1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v', 0.0035)]  # 0.0035 bsv
    >>> my_key.send(outputs)
    '9f59f5c6757ec46fdc7440acbeb3920e614c8d1d247ac174eb6781b832710c1c'

To send pushdata / OP_RETURN data send a list of tuples as follows for hex or utf-8 encoding

.. code-block:: python

    >>> import bitsv
    >>> my_key = Key('YourPrivateKeyGoesHere')
    # input a list of tuples with (data, encoding) pairs where encoding is "utf-8" or "hex"
    # each tuple represents separate pushdata. If you want one really big push then just use one tuple.
    >>> lst_of_pushdata = [('6d01', 'hex'), ('new_name', 'utf-8')]
    # This sets memo.cash name to "new_name" as per https://memo.cash/protocol as an example usecase of op-return metadata
    >>> my_key.send_op_return(lst_of_pushdata)

Just three lines of code!

Hierarchical Deterministic wallet features are not currently supported.

Listing of main commands
========================
... TODO


