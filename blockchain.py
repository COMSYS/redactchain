#!/usr/bin/env python3
""" This module handles reading/writing (simulated) blockchain data, and provides the required data structures. """
import sys
import logging
import argparse
import pathlib
import struct

import json
from progressbar import progressbar

from Cryptodome.Random import random, get_random_bytes
from bitcoin.core import NoWitnessData, x, b2lx, WITNESS_COINBASE_SCRIPTPUBKEY_MAGIC, CheckBlockError, CTransaction
from bitcoin.core import COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160, Hash
# from bitcoin.core.serialize import *
from bitcoin.core.serialize import Serializable, VectorSerializer, ser_read
from bitcoin.core.script import CScriptOp, CScript, OP_DUP, OP_HASH160, OP_HASH256, OP_EQUALVERIFY, OP_CHECKSIG, OP_RETURN, SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinSecret

import config
from parameters import bit_length
import chf


log = logging.getLogger('blockchain')
log.setLevel(logging.INFO)


DEFAULT_BLOCKCHAIN_LENGTH = 1000
DEFAULT_TXS_PER_BLOCK = 1000
DEFAULT_OUTPUTS_PER_REDACT_TX = 50
DEFAULT_OUTPUTS_PER_TX = 2
DEFAULT_NUMBER_ACCOUNTS = 100
DEFAULT_BLOCKCHAIN_FOLDER = 'blockchain'


SAT_PER_OUTPUT = 546


valid_redaction_claims = ['opreturn', 'obfuscate']

# Taken from from original bitcoin.core.serialize
if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x[0]
    from io import BytesIO as _BytesIO
else:
    _bchr = chr
    _bord = ord
    from cStringIO import StringIO as _BytesIO


# The following classes, CRedactableBlockHeader and CRedactableBlock, are redactable replacements for the classes CBlockHeader and CBlock of the original python-bitcoinlib, respectively. python-bitcoinlib is available at https://github.com/petertodd/python-bitcoinlib


class CRedactableBlockHeader(Serializable):
    """A redactable block header, adapted from bitcoin.core.CBlockHeader"""
    __slots__ = ['nVersion', 'hashPrevBlock', 'hashOriginalMerkleRoot', 'nTime', 'nBits', 'nNonce', 'hashesRedactionLog', 'hashesValidity', 'checkValueR', 'checkValueS', 'hashMerkleRoot', 'hashHistoryRoot']

    def __init__(
            self,
            nVersion=3,
            hashPrevBlock=b'\x00' * 32,
            hashOriginalMerkleRoot=b'\x00' * 32,
            nTime=0,
            nBits=0,
            nNonce=0,
            hashesRedactionLog=(),
            hashesValidity=(),
            checkValueR=b'\x00' * (bit_length // 8),
            checkValueS=b'\x00' * (bit_length // 8),
            hashMerkleRoot=b'\x00' * 32,
            hashHistoryRoot=b'\x00' * 32
    ):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashPrevBlock) == 32
        object.__setattr__(self, 'hashPrevBlock', hashPrevBlock)
        assert len(hashOriginalMerkleRoot) == 32
        object.__setattr__(self, 'hashOriginalMerkleRoot', hashOriginalMerkleRoot)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nBits', nBits)
        object.__setattr__(self, 'nNonce', nNonce)

        # hashesRedactionLog
        assert 0 < len(hashesRedactionLog) <= 9  # at most one unconfirmed branch for each jury to confirm on the redaction log
        for hashRedactionLog in hashesRedactionLog:
            assert len(hashRedactionLog) == 32
        object.__setattr__(self, 'hashesRedactionLog', tuple(hashRedactionLog for hashRedactionLog in hashesRedactionLog))  # Unrolling is likely not required but be safe and mime other similar functions from the original python-bitcoinlib

        # hashesValidity
        assert 0 < len(hashesValidity) <= 9 and len(hashesValidity) % 2 == 1  # One validity link per redaction jury, must be odd between 1 and 9
        for hashValidity in hashesValidity:
            assert len(hashValidity) == bit_length // 8
        object.__setattr__(self, 'hashesValidity', tuple(hashValidity for hashValidity in hashesValidity))  # Unrolling is likely not required but be safe and mime other similar functions from the original python-bitcoinlib

        assert len(checkValueR) == (bit_length // 8)
        object.__setattr__(self, 'checkValueR', checkValueR)
        assert len(checkValueS) == (bit_length // 8)
        object.__setattr__(self, 'checkValueS', checkValueS)
        assert len(hashMerkleRoot) == 32
        object.__setattr__(self, 'hashMerkleRoot', hashMerkleRoot)
        assert len(hashHistoryRoot) == 32
        object.__setattr__(self, 'hashHistoryRoot', hashHistoryRoot)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        hashPrevBlock = ser_read(f, 32)
        hashOriginalMerkleRoot = ser_read(f, 32)
        nTime = struct.unpack(b"<I", ser_read(f, 4))[0]
        nBits = struct.unpack(b"<I", ser_read(f, 4))[0]
        nNonce = struct.unpack(b"<I", ser_read(f, 4))[0]
        len_hashesRedactionLog = struct.unpack(b'<B', ser_read(f, 1))[0]
        hashesRedactionLog = list()
        for _ in range(len_hashesRedactionLog):
            hashesRedactionLog.append(ser_read(f, 32))
        hashesRedactionLog = tuple(hashesRedactionLog)
        len_hashesValidity = struct.unpack(b'<B', ser_read(f, 1))[0]
        hashesValidity = list()
        for _ in range(len_hashesValidity):
            hashesValidity.append(ser_read(f, (bit_length // 8)))
        hashesValidity = tuple(hashesValidity)
        checkValueR = ser_read(f, (bit_length // 8))
        checkValueS = ser_read(f, (bit_length // 8))
        hashMerkleRoot = ser_read(f, 32)
        hashHistoryRoot = ser_read(f, 32)

        return cls(
            nVersion=nVersion,
            hashPrevBlock=hashPrevBlock,
            hashOriginalMerkleRoot=hashOriginalMerkleRoot,
            nTime=nTime,
            nBits=nBits,
            nNonce=nNonce,
            hashesRedactionLog=hashesRedactionLog,
            hashesValidity=hashesValidity,
            checkValueR=checkValueR,
            checkValueS=checkValueS,
            hashMerkleRoot=hashMerkleRoot,
            hashHistoryRoot=hashHistoryRoot
        )

    def stream_serialize_immutable(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashPrevBlock) == 32
        f.write(self.hashPrevBlock)
        assert len(self.hashOriginalMerkleRoot) == 32
        f.write(self.hashOriginalMerkleRoot)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nBits))
        f.write(struct.pack(b"<I", self.nNonce))
        assert 0 < len(self.hashesValidity) <= 9
        f.write(struct.pack(b'<B', len(self.hashesRedactionLog)))
        for hashRedactionLog in self.hashesRedactionLog:
            assert len(hashRedactionLog) == 32
            f.write(hashRedactionLog)
        f.write(struct.pack(b'<B', len(self.hashesValidity)))
        for hashValidity in self.hashesValidity:
            assert len(hashValidity) == bit_length // 8
            f.write(hashValidity)

    def stream_serialize_mutable_payload(self, f):
        assert len(self.hashMerkleRoot) == 32
        f.write(self.hashMerkleRoot)
        assert len(self.hashHistoryRoot) == 32
        f.write(self.hashHistoryRoot)

    def stream_serialize(self, f):
        self.stream_serialize_immutable(f)
        assert len(self.checkValueR) == (bit_length // 8)
        f.write(self.checkValueR)
        assert len(self.checkValueS) == (bit_length // 8)
        f.write(self.checkValueS)
        self.stream_serialize_mutable_payload(f)

    def serialize_immutable(self, params={}):
        """Serialize immutable fields only, returning bytes"""
        f = _BytesIO()
        self.stream_serialize_immutable(f, **params)
        return f.getvalue()

    def serialize_for_chameleon_hashing(self, params={}):
        """Serialize all fields but the check value, returning bytes"""
        f = _BytesIO()
        self.stream_serialize_immutable(f, **params)
        self.stream_serialize_mutable_payload(f, **params)
        return f.getvalue()

    @staticmethod
    def calc_difficulty(nBits):
        """Calculate difficulty from nBits target"""
        nShift = (nBits >> 24) & 0xff
        dDiff = float(0x0000ffff) / float(nBits & 0x00ffffff)
        while nShift < 29:
            dDiff *= 256.0
            nShift += 1
        while nShift > 29:
            dDiff /= 256.0
            nShift -= 1
        return dDiff
    difficulty = property(lambda self: CRedactableBlockHeader.calc_difficulty(self.nBits))

    def __repr__(self):
        return "%s(%i, lx(%s), lx(%s), %s, 0x%08x, 0x%08x, %s, %s, lx(%s), lx(%s), lx(%s), lx(%s), %d txs)\n\nHash value: lx(%s)\n\nTransactions:\n\n%s" % (
            self.__class__.__name__,
            self.nVersion,
            b2lx(self.hashPrevBlock),
            b2lx(self.hashOriginalMerkleRoot),
            self.nTime,
            self.nBits,
            self.nNonce,
            str(tuple(b2lx(hashRedactionLog) for hashRedactionLog in self.hashesRedactionLog)),
            str(tuple(b2lx(hashValidity) for hashValidity in self.hashesValidity)),
            b2lx(self.checkValueR),
            b2lx(self.checkValueS),
            b2lx(self.hashMerkleRoot),
            b2lx(self.hashHistoryRoot),
            len(self.vtx),
            b2lx(self.GetHash()),
            '\n\n'.join([repr(t) for t in self.vtx])
        )

    def GetHash(self):
        """Overrides Serializable.GetHash by ignoring mutable fields."""
        """Return the hash of the serialized object"""
        return Hash(self.serialize_immutable())

    def GetChameleonHash(self, public_key=None, chameleon_hash_function=None):
        msg = self.serialize_for_chameleon_hashing()
        check_r = int.from_bytes(self.checkValueR, 'little')
        check_s = int.from_bytes(self.checkValueS, 'little')
        if chameleon_hash_function is None and public_key is not None:
            chameleon_hash_function = chf.ChameleonHashFunction(public_key=public_key)
        h, _, _ = chameleon_hash_function.get_hash(msg, check_r, check_s)
        return h


class CRedactableBlock(CRedactableBlockHeader):
    """A redactable block including all transactions in it, adapted from bitcoin.core.CBlock"""
    __slots__ = ['vtx', 'vMerkleTree', 'vWitnessMerkleTree']

    @staticmethod
    def build_merkle_tree_from_txids(txids):
        """Build a full CBlock merkle tree from txids

        txids - iterable of txids

        Returns a new merkle tree in deepest first order. The last element is
        the merkle root.

        WARNING! If you're reading this because you're learning about crypto
        and/or designing a new system that will use merkle trees, keep in mind
        that the following merkle tree algorithm has a serious flaw related to
        duplicate txids, resulting in a vulnerability. (CVE-2012-2459) Bitcoin
        has since worked around the flaw, but for new applications you should
        use something different; don't just copy-and-paste this code without
        understanding the problem first.
        """
        merkle_tree = list(txids)

        size = len(txids)
        j = 0
        while size > 1:
            for i in range(0, size, 2):
                i2 = min(i + 1, size - 1)
                merkle_tree.append(Hash(merkle_tree[j + i] + merkle_tree[j + i2]))

            j += size
            size = (size + 1) // 2

        return merkle_tree

    @staticmethod
    def build_merkle_tree_from_txs(txs):
        """Build a full merkle tree from transactions"""
        txids = [tx.GetTxid() for tx in txs]
        return CRedactableBlock.build_merkle_tree_from_txids(txids)

    def calc_merkle_root(self):
        """Calculate the merkle root

        The calculated merkle root is not cached; every invocation
        re-calculates it from scratch.
        """
        if len(self.vtx) == 0:
            raise ValueError('Block contains no transactions')
        return self.build_merkle_tree_from_txs(self.vtx)[-1]

    @staticmethod
    def build_witness_merkle_tree_from_txs(txs):
        """Calculate the witness merkle tree from transactions"""
        has_witness = False
        hashes = []
        for tx in txs:
            hashes.append(tx.GetHash())
            has_witness |= tx.has_witness()
        if not has_witness:
            raise NoWitnessData
        hashes[0] = b'\x00' * 32
        return CRedactableBlock.build_merkle_tree_from_txids(hashes)

    def calc_witness_merkle_root(self):
        """Calculate the witness merkle root

        The calculated merkle root is not cached; every invocation
        re-calculates it from scratch.
        """
        if len(self.vtx) == 0:
            raise ValueError('Block contains no transactions')
        return self.build_witness_merkle_tree_from_txs(self.vtx)[-1]

    def get_witness_commitment_index(self):
        """Find txout # of witness commitment in coinbase

        Return None or an index
        """
        if len(self.vtx) == 0:
            raise ValueError('Block contains no transactions')
        commit_pos = None
        for index, out in enumerate(self.vtx[0].vout):
            script = out.scriptPubKey
            if len(script) >= 38 and script[:6] == WITNESS_COINBASE_SCRIPTPUBKEY_MAGIC:
                commit_pos = index
        if commit_pos is None:
            raise ValueError('The witness commitment is missed')
        return commit_pos

    def __init__(
            self,
            nVersion=3,
            hashPrevBlock=b'\x00' * 32,
            hashOriginalMerkleRoot=b'\x00' * 32,
            nTime=0,
            nBits=0,
            nNonce=0,
            hashesRedactionLog=(),
            hashesValidity=(),
            checkValueR=b'\x00' * (bit_length // 8),
            checkValueS=b'\x00' * (bit_length // 8),
            hashMerkleRoot=b'\x00' * 32,
            hashHistoryRoot=b'\x00' * 32,
            vtx=(),
            chfs=()
    ):
        """Create a new block"""
        if vtx:
            vMerkleTree = tuple(CRedactableBlock.build_merkle_tree_from_txs(vtx))
            if hashMerkleRoot == b'\x00' * 32:
                hashMerkleRoot = vMerkleTree[-1]
            elif hashMerkleRoot != vMerkleTree[-1]:
                raise CheckBlockError("CBlock : hashMerkleRoot is not compatible with vtx")
        else:
            vMerkleTree = ()
        if hashOriginalMerkleRoot == b'\x00' * 32:
            hashOriginalMerkleRoot = hashMerkleRoot

        compute_hash_value = False
        if len(hashesValidity) == 0:
            compute_hash_value = True
            hashesValidity = [b'\x00' * (bit_length // 8)] * len(chfs)

        # Redaction Log is not part of the performance evaluation
        if len(hashesRedactionLog) == 0:
            hashesRedactionLog = (b'\x00' * 32, )

        # Initialize block header without chameleon hash values and r, s values
        super(CRedactableBlock, self).__init__(
            nVersion,
            hashPrevBlock,
            hashOriginalMerkleRoot,
            nTime,
            nBits,
            nNonce,
            hashesRedactionLog,
            hashesValidity,
            checkValueR,
            checkValueS,
            hashMerkleRoot,
            hashHistoryRoot
        )

        if compute_hash_value:
            # Get input for computing chameleon hash value
            msg = super(CRedactableBlock, self).serialize_for_chameleon_hashing()

            # Get validity hashes and check values
            r, s = None, None
            hashesValidity = list()
            for chf in chfs:
                h, r, s = chf.get_hash(msg, r, s)
                hashesValidity.append(h)

            object.__setattr__(self, 'checkValueR', int(r).to_bytes(bit_length // 8, 'little'))
            object.__setattr__(self, 'checkValueS', int(s).to_bytes(bit_length // 8, 'little'))
            object.__setattr__(self, 'hashesValidity', tuple(hashValidity for hashValidity in hashesValidity))

        object.__setattr__(self, 'vMerkleTree', vMerkleTree)
        try:
            vWitnessMerkleTree = tuple(CRedactableBlock.build_witness_merkle_tree_from_txs(vtx))
        except NoWitnessData:
            vWitnessMerkleTree = ()
        object.__setattr__(self, 'vWitnessMerkleTree', vWitnessMerkleTree)
        object.__setattr__(self, 'vtx', tuple(CTransaction.from_tx(tx) for tx in vtx))

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CRedactableBlock, cls).stream_deserialize(f)

        vtx = VectorSerializer.stream_deserialize(CTransaction, f)
        vMerkleTree = tuple(CRedactableBlock.build_merkle_tree_from_txs(vtx))
        object.__setattr__(self, 'vMerkleTree', vMerkleTree)
        try:
            vWitnessMerkleTree = tuple(CRedactableBlock.build_witness_merkle_tree_from_txs(vtx))
        except NoWitnessData:
            vWitnessMerkleTree = ()
        object.__setattr__(self, 'vWitnessMerkleTree', vWitnessMerkleTree)
        object.__setattr__(self, 'vtx', tuple(vtx))

        return self

    def stream_serialize(self, f, include_witness=True):
        super(CRedactableBlock, self).stream_serialize(f)
        VectorSerializer.stream_serialize(CTransaction, self.vtx, f, dict(include_witness=include_witness))

    def get_header(self):
        """Return the block header

        Returned header is a new object.
        """
        return CRedactableBlockHeader(
            nVersion=self.nVersion,
            hashPrevBlock=self.hashPrevBlock,
            hashOriginalMerkleRoot=self.hashOriginalMerkleRoot,
            nTime=self.nTime,
            nBits=self.nBits,
            nNonce=self.nNonce,
            hashesRedactionLog=self.hashesRedactionLog,
            hashesValidity=self.hashesValidity,
            hashMerkleRoot=self.hashMerkleRoot,
            hashHistoryRoot=self.hashHistoryRoot,
        )

    def GetHash(self):
        """Return the block hash

        Note that this is the hash of the header, not the entire serialized
        block.
        """
        return self.get_header().GetHash()

    def GetWeight(self):
        """Return the block weight: (stripped_size * 3) + total_size"""
        return len(self.serialize(dict(include_witness=False))) * 3 + len(self.serialize())


def generate_blockchain_credentials():
    private_key = CBitcoinSecret.from_secret_bytes(get_random_bytes(32))
    public_key = private_key.pub
    return private_key, public_key


def generate_new_blockchain(
        number_blocks: int,
        txs_per_block: int,
        outputs_per_tx: int,
        outputs_per_redact_tx: int,
        number_accounts: int,
):

    # For evaluation purposes, all transactions have exactly two outputs
    assert outputs_per_tx == 2

    log.info(f'Creating {number_accounts} empty accounts.')
    accounts = list()
    for i in progressbar(range(number_accounts), redirect_stdout=True):
        accounts.append({
            'id': i,
            'open_outputs': list()  # Tuples of (block, tx, index, sathoshi)
        })

    log.info(f'Planning out blockchain with {number_blocks} blocks, {txs_per_block} transactions per block, and each block has one redactworthy transaction with {outputs_per_redact_tx} P2PKH outputs, a different one has one OP_RETURN output in addition to the normal payload, and normal transactions have 2 P2PKH outputs. Coinbase goes to a random account')
    blockchain = list()
    log.info('Planning genesis block')
    genesis_tx = {
        'typ': 'coinbase',
        'owner': random.choice(accounts)['id'],
        'outputs': list(),
    }
    INITIAL_BUDGET = 10000000000000  # 100000 BTC for everyone
    MINING_REWARD = 5000000000  # 50 BTC mining reward
    for account in accounts:
        genesis_tx['outputs'].append((account['id'], INITIAL_BUDGET))
        account['open_outputs'].append((0, 0, account['id'], INITIAL_BUDGET))
    genesis_block = [genesis_tx]
    blockchain.append(genesis_block)

    log.info('Planning the blocks.')
    # Keep track of transactions to redact later - form: (block_id, transaction_id)
    txs_large = list()
    txs_opreturn = list()
    for block_id in progressbar(range(1, number_blocks + 1), redirect_stdout=True):
        # Select random miner
        miner_id = random.choice(range(len(accounts)))
        txs = list()
        coinbase_tx = {
            'typ': 'coinbase',
            'owner': miner_id,
            'outputs': [(miner_id, MINING_REWARD)]
        }
        accounts[miner_id]['open_outputs'].append((block_id, 0, miner_id, MINING_REWARD))
        txs.append(coinbase_tx)

        # Select two distinct special transactions
        tx_large, tx_opreturn = random.sample(range(1, txs_per_block + 1), 2)

        # Plan transactions
        for tx_id in range(1, txs_per_block + 1):
            if tx_id == tx_large:
                tx_owner = random.choice(range(len(accounts)))
                value = outputs_per_redact_tx * SAT_PER_OUTPUT
                output = None
                for i, available_output in enumerate(accounts[tx_owner]['open_outputs']):
                    if available_output[3] > value:
                        output = available_output
                        break
                if output is None:
                    raise RuntimeError('No single fund available to satisfy payment.')
                accounts[tx_owner]['open_outputs'] = accounts[tx_owner]['open_outputs'][:i] + accounts[tx_owner]['open_outputs'][(i + 1):]  # Remove the selected output from open outputs

                tx = {
                    'typ': 'large',
                    'owner': tx_owner,
                    'input': (output[0], output[1], output[2]),
                    'outputs': [(-1, SAT_PER_OUTPUT) for _ in range(outputs_per_redact_tx)] + [(tx_owner, output[3] - value)]
                }
                accounts[tx_owner]['open_outputs'].append((block_id, tx_id, 1, output[3] - value))
                txs_large.append((block_id, tx_id))
            else:
                tx_owner, beneficiary = random.sample(range(len(accounts)), 2)
                scale_factor = 10000
                lower_bound = scale_factor * (number_blocks - block_id)
                upper_bound = (scale_factor * ((number_blocks - block_id) + 1)) - 1
                value = random.randint(lower_bound * SAT_PER_OUTPUT, upper_bound * SAT_PER_OUTPUT)
                # Determine a random output that can spend the value
                output = None
                for i, available_output in enumerate(accounts[tx_owner]['open_outputs']):
                    if available_output[3] > value:
                        output = available_output
                        break
                if output is None:
                    raise RuntimeError('No single fund available to satisfy payment.')
                accounts[tx_owner]['open_outputs'] = accounts[tx_owner]['open_outputs'][:i] + accounts[tx_owner]['open_outputs'][(i + 1):]  # Remove the selected output from open outputs

                tx = {
                    'typ': 'normal',
                    'owner': tx_owner,
                    'input': (output[0], output[1], output[2]),
                    'outputs': [
                        (beneficiary, value),
                        (tx_owner, output[3] - value)
                    ]
                }
                accounts[beneficiary]['open_outputs'].append((block_id, tx_id, 0, value))
                accounts[tx_owner]['open_outputs'].append((block_id, tx_id, 1, output[3] - value))

                if tx_id == tx_opreturn:
                    tx['opreturn'] = 'F' * 80
                    txs_opreturn.append((block_id, tx_id))

            txs.append(tx)
        blockchain.append(txs)
    return blockchain, txs_large, txs_opreturn


def store_planned_blockchain(
        blockchain: list,
        txs_large: list,
        txs_opreturn: list,
        blockchain_folder: pathlib.Path
):
    if blockchain_folder.exists():
        raise RuntimeError('Target folder already exists.')
    blockchain_folder.mkdir(parents=True)

    path_blockchain = blockchain_folder / 'blockchain.planned.json'
    path_special_txs = blockchain_folder / 'redaction_txs.planned.json'

    with open(path_blockchain, 'w') as f_out:
        json.dump(blockchain, f_out, sort_keys=False)

    with open(path_special_txs, 'w') as f_out:
        json.dump({'txs_large': txs_large, 'txs_opreturn': txs_opreturn}, f_out, sort_keys=False)


def implement_blockchain(
        conf_file: pathlib.Path,
        blockchain_folder: pathlib.Path
):
    if not conf_file.exists():
        raise RuntimeError('Configuration file does not exist.')
    conf = config.RedactChainConfiguration(config_file=conf_file)
    chameleon_hash_function = chf.ChameleonHashFunction(public_key=conf['chf_pub'])

    if not blockchain_folder.exists():
        raise RuntimeError('Target folder does not exist.')

    path_blockchain_planned = blockchain_folder / 'blockchain.planned.json'
    path_redaction_txs_final = blockchain_folder / 'redaction_txs.json'

    path_validation_file = blockchain_folder / 'validation.csv'

    if not path_blockchain_planned.exists():
        raise RuntimeError('Planned blockchain file does not exist.')

    log.debug('Loading planned blockchain.')
    with open(path_blockchain_planned, 'r') as f_in:
        blockchain_planned = json.load(f_in)

    transaction_hashes = dict()
    prev_block_hash = b'\x00' * 32
    prev_block_chameleon_hash = b'\x00' * (bit_length // 8)
    redaction_txs = {'txs_large': list(), 'txs_opreturn': list()}

    # Read number of accounts from genesis transaction and create credentials
    number_accounts = len(blockchain_planned[0][0]['outputs'])
    accounts = list()
    log.info(f'Creating blockchain credentials for {number_accounts} accounts.')
    for _ in progressbar(range(number_accounts), redirect_stdout=True):
        private_key, public_key = generate_blockchain_credentials()
        accounts.append({'priv': private_key, 'pub': public_key})

    log.info('Implementing planned blocks.')
    path_validation_file.touch(exist_ok=False)
    with open(path_validation_file, 'w') as f_val:
        f_val.write('block_height;block_id;prev_block_id;chameleon_hash;prev_chameleon_hash;tx_large;tx_opreturn\n')

    for i, block in progressbar(list(enumerate(blockchain_planned)), redirect_stdout=True):
        transaction_hashes[i] = dict()
        txs = list()
        tx_large, tx_opreturn = None, None
        for j, tx in enumerate(block):
            tx_owner = tx['owner']

            # Create outputs first, since we need to prepare transaction before signing (and finalizing the input) for normal transactions
            txouts = list()
            for output in tx['outputs']:
                beneficiary_id, value = output[0], output[1]
                if beneficiary_id == -1:
                    payload = x('cafebabedeadbeef8badf00dbeefcacea5a5a5a5')
                else:
                    payload = Hash160(accounts[beneficiary_id]['pub'])
                output_script = CScript([OP_DUP, OP_HASH160, payload, OP_EQUALVERIFY, OP_CHECKSIG])
                txouts.append(CMutableTxOut(value, output_script))

            if 'opreturn' in tx.keys():
                payload = tx['opreturn'].encode('utf-8')
                assert len(payload) <= 80
                txouts.append(CMutableTxOut(0, CScript([OP_RETURN, payload])))

            if tx['typ'] == 'coinbase':
                txin = CMutableTxIn(COutPoint())  # Empty reference to previous input
            elif tx['typ'] in ['normal', 'large']:
                inp = tx['input']  # Format: (Block ID, Transaction ID in block, index in TX)
                prev_hash = transaction_hashes[inp[0]][inp[1]]
                txin = CMutableTxIn(COutPoint(prev_hash, inp[2]))
            else:
                raise RuntimeError('Unknown transaction type')

            tx_obj = CMutableTransaction([txin], txouts)

            if tx['typ'] in ['normal', 'large']:
                # Create the script that we're spending - since we reuse credentials in this evaluation we don't have to look anything up
                public_key = accounts[tx_owner]['pub']
                private_key = accounts[tx_owner]['priv']
                txin_script_to_be_spent = CScript([OP_DUP, OP_HASH160, Hash160(public_key), OP_EQUALVERIFY, OP_CHECKSIG])

                sighash = SignatureHash(txin_script_to_be_spent, tx_obj, 0, SIGHASH_ALL)
                sig = private_key.sign(sighash) + bytes([SIGHASH_ALL])
                txin.scriptSig = CScript([sig, public_key])
                VerifyScript(txin.scriptSig, txin_script_to_be_spent, tx_obj, 0, (SCRIPT_VERIFY_P2SH,))  # Taken from an example in original python-bitcoinlib
            else:
                coinbase_payload = struct.pack('<I', i).rstrip(b'\x00')
                txin.scriptSig = CScript([coinbase_payload])

            tx_hash = tx_obj.GetTxid()
            transaction_hashes[i][j] = tx_hash
            txs.append(tx_obj)

            if tx['typ'] == 'large':
                tx_large = b2lx(tx_hash)
                redaction_txs['txs_large'].append(tx_large)
            elif 'opreturn' in tx.keys():
                tx_opreturn = b2lx(tx_hash)
                redaction_txs['txs_opreturn'].append(tx_opreturn)

        block_obj = CRedactableBlock(
            hashPrevBlock=prev_block_hash,
            hashesValidity=(prev_block_chameleon_hash, ),
            vtx=txs,
            chfs=(chameleon_hash_function, ),
        )
        # Initialize Chameleon hash values
        msg = block_obj.serialize_for_chameleon_hashing()
        h, r, s = chameleon_hash_function.get_hash(msg)
        block_obj.checkValueR = int(r).to_bytes(bit_length // 8, 'little')
        block_obj.checkValueS = int(s).to_bytes(bit_length // 8, 'little')

        prev_block_hash = block_obj.GetHash()
        prev_block_chameleon_hash = h
        assert h == block_obj.GetChameleonHash(chameleon_hash_function=chameleon_hash_function)

        block_serialized = block_obj.serialize()
        block_test = CRedactableBlock.deserialize(block_serialized)
        assert h == block_test.GetChameleonHash(chameleon_hash_function=chameleon_hash_function)

        path_block = blockchain_folder / f'{i:05}.blk'
        if path_block.exists():
            raise RuntimeError(f'Final blockchain file for block {i} already exists.')
        with open(path_block, 'wb') as f_block_out:
            f_block_out.write(block_serialized)

        with open(path_validation_file, 'a') as f_val:
            f_val.write(f'{i};{b2lx(block_obj.GetHash())};{b2lx(block_obj.hashPrevBlock)};{b2lx(h)};{b2lx(block_obj.hashesValidity[0])};{tx_large};{tx_opreturn}\n')

    with open(path_redaction_txs_final, 'w') as f_redaction_txs_out:
        json.dump(redaction_txs, f_redaction_txs_out, sort_keys=False)


def load_blockchain(blockchain_folder: pathlib.Path):
    if not blockchain_folder.exists():
        raise RuntimeError('Blockchain folder does not exist.')

    blocks = list()
    block_index = dict()
    tx_index = dict()

    for i, block_file in enumerate(sorted(list(blockchain_folder.glob('*.blk')))):
        with open(block_file, 'rb') as f_block_in:
            block = CRedactableBlock.deserialize(f_block_in.read())
        block_id = b2lx(block.GetHash())
        blocks.append(block)
        block_index[block_id] = i

        for j, tx in enumerate(block.vtx):
            txid = b2lx(tx.GetTxid())
            tx_index[txid] = (block_id, j)

    return blocks, block_index, tx_index


def redact_tx(tx, action):
    if action not in valid_redaction_claims:
        raise RuntimeError(f'Unknown redaction action {action}.')

    tx_redacted = CMutableTransaction.from_tx(tx)

    if action == 'opreturn':
        i_out = None
        for i, vout in enumerate(tx_redacted.vout):
            if CScriptOp(vout.scriptPubKey[0]) == OP_RETURN:
                i_out = i
                break
        if i_out is None:
            raise RuntimeError('Was asked to redact OP_RETURN from TX without OP_RETURN!')
        tx_redacted.vout = tx_redacted.vout[:i_out] + tx_redacted.vout[(i_out + 1):]
    elif action == 'obfuscate':
        vout_new = list()
        for i, out in enumerate(tx_redacted.vout):
            if CScriptOp(out.scriptPubKey[0]) == OP_DUP:
                old_script_ops = list(out.scriptPubKey.raw_iter())
                pubkey_hash = old_script_ops[2][1]
                log.debug(f'Pubkey hash: lx({b2lx(pubkey_hash)})')
                commitment = Hash(pubkey_hash)
                log.debug(f'Commitment: lx({b2lx(commitment)})')
                new_script = CScript([OP_DUP, OP_HASH160, OP_HASH256, commitment, OP_EQUALVERIFY, OP_CHECKSIG])
                vout_new.append(CMutableTxOut(out.nValue, new_script))
            else:
                vout_new.append(out)
        tx_redacted.vout = vout_new
    else:
        raise RuntimeError('Unexpected error in redact_tx.')

    return tx_redacted


def redact_tx_in_block(block, tx_pos, action):

    tx = redact_tx(block.vtx[tx_pos], action)
    vtx = block.vtx[:tx_pos] + (tx, ) + block.vtx[(tx_pos + 1):]
    block_updated = CRedactableBlock(
        nVersion=block.nVersion,
        hashPrevBlock=block.hashPrevBlock,
        hashOriginalMerkleRoot=block.hashOriginalMerkleRoot,
        nTime=block.nTime,
        nBits=block.nBits,
        nNonce=block.nNonce,
        hashesRedactionLog=tuple(h for h in block.hashesRedactionLog),
        hashesValidity=tuple(h for h in block.hashesValidity),
        checkValueR=b'\x00' * (bit_length // 8),  # Will be set subsequently
        checkValueS=b'\x00' * (bit_length // 8),  # Will be set subsequently
        hashMerkleRoot=b'\x00' * 32,  # We want to update the Merkle tree via this redaction
        hashHistoryRoot=block.hashHistoryRoot,
        vtx=vtx
    )
    return block_updated, tx


def cmd_generate(args):
    number_blocks = args.number_blocks
    txs_per_block = args.txs_per_block
    outputs_per_tx = args.outputs_normal
    outputs_per_redact_tx = args.outputs_redact
    number_accounts = args.number_accounts
    blockchain_folder = pathlib.Path(args.blockchain_folder)
    if blockchain_folder.exists():
        raise RuntimeError('Target folder already exists.')

    blockchain, txs_large, txs_opreturn = generate_new_blockchain(
        number_blocks,
        txs_per_block,
        outputs_per_tx,
        outputs_per_redact_tx,
        number_accounts,
    )

    store_planned_blockchain(
        blockchain,
        txs_large,
        txs_opreturn,
        blockchain_folder
    )


def cmd_implement(args):
    config_file = pathlib.Path(args.conf_file)
    if not config_file.exists():
        raise RuntimeError('Configuration file does not exist.')

    blockchain_folder = pathlib.Path(args.blockchain_folder)
    if not blockchain_folder.exists():
        raise RuntimeError('Blockchain folder does not yet exist.')

    implement_blockchain(
        config_file,
        blockchain_folder
    )


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    arg_parser = argparse.ArgumentParser()
    arg_parser.set_defaults(func=None)
    cmd_parser = arg_parser.add_subparsers()

    cmd_generate_parser = cmd_parser.add_parser('generate')
    cmd_generate_parser.add_argument(
        'number_blocks',
        type=int,
        default=DEFAULT_BLOCKCHAIN_LENGTH,
        help=f'Number of blocks to be "mined" (default: {DEFAULT_BLOCKCHAIN_LENGTH}).'
    )
    cmd_generate_parser.add_argument(
        'txs_per_block',
        type=int,
        default=DEFAULT_TXS_PER_BLOCK,
        help=f'Number of total transactions created for each block (default: {DEFAULT_TXS_PER_BLOCK})'
    )
    cmd_generate_parser.add_argument(
        '--outputs-normal', '-o',
        type=int,
        default=DEFAULT_OUTPUTS_PER_TX,
        help=f'Number of outputs per transaction (default: {DEFAULT_OUTPUTS_PER_TX})'
    )
    cmd_generate_parser.add_argument(
        '--outputs-redact', '-O',
        type=int,
        default=DEFAULT_OUTPUTS_PER_REDACT_TX,
        help=f'Number of outputs per transaction that will be redacted (default: {DEFAULT_OUTPUTS_PER_REDACT_TX})'
    )
    cmd_generate_parser.add_argument(
        '--number-accounts', '-a',
        type=int,
        default=DEFAULT_NUMBER_ACCOUNTS,
        help=f'Number of different accounts that are sending transactions (default: {DEFAULT_NUMBER_ACCOUNTS})'
    )
    cmd_generate_parser.add_argument(
        '--conf-file', '-f',
        type=str,
        default=config.DEFAULT_CONF_FILE,
        help=f'File to read config from (default: {config.DEFAULT_CONF_FILE})'
    )
    cmd_generate_parser.add_argument(
        '--blockchain-folder', '-F',
        type=str,
        default=DEFAULT_BLOCKCHAIN_FOLDER,
        help=f'File to write blockchain data to (default: {DEFAULT_BLOCKCHAIN_FOLDER})'
    )
    cmd_generate_parser.set_defaults(func=cmd_generate)

    cmd_implement_parser = cmd_parser.add_parser('implement')
    cmd_implement_parser.add_argument(
        '--conf-file', '-f',
        type=str,
        default=config.DEFAULT_CONF_FILE,
        help=f'File to read config from (default: {config.DEFAULT_CONF_FILE})'
    )
    cmd_implement_parser.add_argument(
        '--blockchain-folder', '-F',
        type=str,
        default=DEFAULT_BLOCKCHAIN_FOLDER,
        help=f'File to write blockchain data to (default: {DEFAULT_BLOCKCHAIN_FOLDER})'
    )
    cmd_implement_parser.set_defaults(func=cmd_implement)

    args = arg_parser.parse_args()

    if args.func is None:
        log.error('No (known) command given.')
        arg_parser.print_help()
        sys.exit(1)

    args.func(args)
