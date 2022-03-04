#!/usr/bin/env python3
import logging
import math
import asyncio
import struct
from hashlib import sha256

from gmpy2 import mpz, invert, powmod, f_mod as mod
from Cryptodome.Random import random

from config import global_config
from parameters import p, q, g, h, bit_length
import msg_handler
import chf
import blockchain
import eval


log = logging.getLogger('smc')
log.setLevel(logging.INFO)


transaction_manager = dict()


def SmcIdIterator(start: int):
    """ Assign IDs to different SMC objects (probably
        distributed redaction states exclusively)
        similarly to msg_handler.MessageIdIterator. """

    sequence_number = start % ((1 << 64) - 1)
    while True:
        sequence_number_bin = struct.pack('!Q', sequence_number)
        yield (sequence_number_bin).hex()
        sequence_number = (sequence_number + 1) % ((1 << 64) - 1)


# Functionality from below is taken from the source code of CoinParty, a
# former open-source proof-of-concept implementation created by the first
# author of RedactChain. We highlight code fractions in essence taken from
# CoinParty accordingly.
# CoinParty is available at https://github.com/COMSYS/coinparty

# Taken from CoinParty
""" Caching of "participating player signatures", meaning: Keep track of the
    recombination vectors used for different sets of considered shares.
    Idea taken from VIFF. Addition to VIFF: the used order is part of the
    caching key as well. In VIFF, viff.field.GF handles this implicitly. """
_recombination_vectors = {}


# Taken from CoinParty
class FE(object):
    """ Helper class, which is probably very similar to VIFF's class """

    def __init__(self, v, order=q):
        self.order = mpz(abs(order))
        if isinstance(v, FE):
            v = int(v)
        self.v = mod(mpz(v), self.order)

    def __eq__(self, x):
        if isinstance(x, FE):
            return self.v == x.v and self.order == x.order
        elif isinstance(x, int):
            return self.v == mod(x, self.order)
        else:
            return NotImplemented

    def __ne__(self, x):
        return not self.__eq__(x)

    def __neg__(self):
        return FE(-self.v, self.order)

    def __add__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(self.v + v2, self.order)
    __radd__ = __add__

    def __sub__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(self.v - v2, self.order)

    def __rsub__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(v2 - self.v, self.order)

    def __mul__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(self.v * v2, self.order)
    __rmul__ = __mul__

    def __truediv__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(self.v * invert(v2, self.order), self.order)
    __floordiv__ = __truediv__

    def __rtruediv__(self, x):
        v2 = x.v if isinstance(x, FE) else x
        return FE(invert(self.v, self.order) * v2, self.order)
    __rfloordiv__ = __rtruediv__

    def __lt__(self, x):
        v2 = x if isinstance(x, FE) else FE(x, self.order)
        return self.v < v2.v

    def __le__(self, x):
        return self < x or self == x

    def __gt__(self, x):
        v2 = x if isinstance(x, FE) else FE(x, self.order)
        return self.v > v2.v

    def __ge__(self, x):
        return self > x or self == x

    def __repr__(self):
        return 'FE(' + str(self.v) + ')'

    def __str__(self):
        return 'FE(' + str(self.v) + ')'

    def __format__(self, _):
        return self.__str__()

    def __int__(self):
        return int(self.v)


class Share(object):

    def __init__(self, share: FE, player: int):
        if not isinstance(share, FE):
            raise ValueError('All shares must be FEs!')
        self.share = share
        self.player = player

    def __eq__(self, x):
        if not isinstance(x, Share):
            return False
        return self.share == x.share and self.player == x.player

    def __ne__(self, x):
        return not self.__eq__(x)

    def __neg__(self):
        return Share(-self.share, self.player)

    def __add__(self, x):
        if not isinstance(x, Share):
            raise NotImplementedError()
        if self.player != x.player:
            raise ValueError('Cannot add shares for different players.')
        return Share(self.share + x.share, self.player)
    __radd__ = __add__

    def __sub__(self, x):
        return self.__add__(-x)

    def __rsub__(self, x):
        return -self.__sub__(x)

    def __mul__(self, x):
        if isinstance(x, Share):
            raise NotImplementedError()
        constant = x.v if isinstance(x, FE) else x
        return Share(constant * self.share, self.player)
    __rmul__ = __mul__

    def __repr__(self):
        return f'Share({self.player}, {self.share})'

    def __str__(self):
        return f'Share({self.player}, {self.share})'

    def __int__(self):
        return int(self.share)


# Taken from CoinParty code
def shamir_share(s: FE, n, t=None, order=q, return_factors=False):
    """ Split the secret s into n-many shares, of which any set of t+1 shares
        is sufficient to reconstruct s.
        s                 Secret to be secret-shared.
        n                 Total number of players (total number of shares
                          created).
        t                 Threshold of the sharing. (t+1) correct shares
                          needed for recombination.
        order             Shamir polynomials are created over the Galois
                          field of order "order". "order" must be prime,
                          and s < order must hold.
        return_factors    If true, the return value will be (shares, factors),
                          otherwise only shares are returned. """

    def _horner(factors, x):
        """ Horner scheme. Factors must be in this order:
            f(x) = a_0 + x * a_1 + x^2 * a_2 + ... + x^n * a_n """
        result = mpz(0)
        for f in factors:
            result = mod(x * result + f, order)
        return FE(result, order)

    if t is None:
        t = int(math.floor((2. * n) / 3.))

    # factors in reversed order for horner scheme
    factors = [mpz(random.randint(1, int(order)))] * t + [s.v]
    shares = [Share(_horner(factors, x + 1), x) for x in range(n)]
    if return_factors:
        return (shares, factors[::-1])  # reversed(factors) does not yield a list, but an iterator
    else:
        return shares


# Taken from CoinParty
def shamir_recombine(unf_shares: list, t=None, x=0, order=q, robust=True):
    """ Recombine shamir sharings.
        It is assumed that only valid shares are passed to this function.
        This can be achieved via Pedersen VSS, for instance.
        unf_shares The shares to be used for recombination
        t          Threshold for recombination. First (t+1) shares are used.
        x          [opt] Point that should be interpolated. Default: 0
                       (Recombine the secret value).
        order      [opt] Order of the finite field of the polynomial to be
                       interpolated. Default: order of secp256k1. """

    if t is None:
        t = int(math.floor((2. * len(unf_shares)) / 3.))

    if robust:
        replaced_shares = list()
        if len([s for s in unf_shares if s is not None]) < (t + 1):
            return None
        for i in range(len(unf_shares)):
            if unf_shares[i] is None:
                replaced_shares.append(Share(FE(0, order=order), i))
            else:
                replaced_shares.append(unf_shares[i])
        replaced_shares.sort(key=lambda x: x.player)
        return _iterative_berlekamp_welch(replaced_shares, len(unf_shares) - (t + 1), order)

    def _filter_shares(shares):
        return [s for s in shares if s is not None][:t + 1]

    filtered_shares = _filter_shares(unf_shares)
    if len(filtered_shares) != t + 1:
        return None

    players, shares = list(), list()
    for filtered_share in filtered_shares:
        players.append(filtered_share.player + 1)
        shares.append(filtered_share.share)
    cache_key = (int(order),) + tuple(players) + (x, )

    try:
        lagranges = _recombination_vectors[cache_key]
        secret = FE(sum(map(lambda x, y: (x * y), shares, lagranges)), order)
    except KeyError:
        lagranges = []
        for i in players:
            lagrange_factors = [
                mod((k - x) * invert(k - i, order), order)
                for k
                in players if k != i
            ]
            lagrange_reduced = FE(lagrange_factors[0], order=order)
            for lagrange_factor in lagrange_factors[1:]:
                lagrange_reduced = lagrange_reduced * FE(lagrange_factor, order=order)
            lagranges.append(lagrange_reduced)
        _recombination_vectors[cache_key] = lagranges
        secret = FE(sum(map(lambda x, y: (x * y), shares, lagranges)), order=order)
    return secret


# Taken from CoinParty
def _iterative_berlekamp_welch(shares, t, secret_order=q):
    for n_err in list(range(t))[::-1]:
        res = _berlekamp_welch(shares, n_err, secret_order)
        if res is not None:
            return res
    return None


def _berlekamp_welch(shares, n_err, secret_order=q):

    def _split_factors(coeffs, n_err):
        n = len(coeffs)
        Q, E = list(), list()
        for i, coeff in enumerate(coeffs):
            if i < n - n_err:
                Q.append(coeff)
            else:
                E.append(coeff)
        E.append(FE(1, secret_order))
        return (Q, E)

    def _get_P(Q, E, n_err):
        """ Division of two polynomials. """
        Pt = list()
        Qt = Q[::-1]
        Et = E[::-1]
        # Remove leading 0s of Qt (except Qt = 0)
        while len(Qt) > 1 and Qt[0] == FE(0, secret_order):
            Qt = Qt[1:]
        while len(Qt) >= len(Et):
            c = Qt[0] / Et[0]
            for i in range(len(E)):
                Qt[i] -= c * Et[i]
            if Qt[0] == 0:
                Qt = Qt[1:]
                Pt.append(c)
            else:
                raise ValueError('Error in polynomial division.')
        remainder = Qt[::-1]
        while len(remainder) > 0 and remainder[0] == FE(0, secret_order):
            remainder = remainder[1:]
        while len(Pt) > n_err and Pt[0] == 0:  # Remove leading 0s from result
            Pt = Pt[1:]
        P = Pt[::-1]
        return (P, remainder)

    x = None

    (matrix, b) = _construct_equation_system(shares, n_err, secret_order)
    x = _solve_equation_system(matrix, b)
    if x is None:
        return None

    (Q, E) = _split_factors(x, n_err)
    (P, remainder) = _get_P(Q, E, n_err)
    if len(remainder) == 0:
        secret = P[0]
        return secret


# Taken from CoinParty
def _construct_equation_system(shares, e, order=q):
    n = len(shares)
    matrix = list()
    for i in range(n):
        row = list()
        for j in range(n):
            if j < (n - e):
                row.append(FE((i + 1)**j, order))
            else:
                row.append(shares[i].share * FE(-((i + 1)**(j - (n - e))), order))
        matrix.append(row)
    solution = [shares[i].share * FE((i + 1)**e, order) for i in range(n)]
    return (matrix, solution)


# Taken from CoinParty
def _solve_equation_system(matrix, solution, order=q):
    n = len(matrix)
    Ab = [[matrix[i][j] for j in range(n)] + [solution[i]] for i in range(n)]
    assert len(Ab[0]) == len(Ab) + 1

    for i in range(n):
        p = FE(0, order)
        p_ind = -1
        for k in range(i, n):
            if Ab[k][i] > p:
                p = Ab[k][i]
                p_ind = k
        if p_ind == -1:
            return None
        Ab[i], Ab[p_ind] = Ab[p_ind], Ab[i]
        Ab[i] = [Ab[i][j] / p for j in range(n + 1)]
        for k in range(i + 1, n):
            Ab[k] = [Ab[k][j] - (Ab[k][i] * Ab[i][j]) for j in range(n + 1)]

    for i in list(range(n))[::-1]:
        for k in range(i):
            Ab[k] = [Ab[k][j] - (Ab[k][i] * Ab[i][j]) for j in range(n + 1)]

    x = [Ab[i][-1] for i in range(n)]
    return x


def check_message(msg: dict):
    msg_keys = msg.keys()

    if 'smc_id' not in msg_keys or len(msg['smc_id']) != 16:
        log.debug('SMC ID missing or of wrong length.')
        return False

    if 'sender' not in msg_keys:
        log.debug('SMC message sender missing.')
        return False

    if 'smc_typ' not in msg_keys:
        log.debug('SMC message type missing.')
        return False

    if 'smc_value' not in msg_keys:
        return False

    return True


class RecombineState(object):

    def __init__(self, number_peers: int):
        loop = asyncio.get_running_loop()
        self.recombined_secret = loop.create_future()

        self._number_peers = number_peers
        self._shares_received = [None] * number_peers

    def share_received(self, share: Share):
        self._shares_received[share.player] = share
        if self.recombined_secret.done():
            return

        number_received_shares = len([s for s in self._shares_received if s is not None])
        if not self.recombined_secret.done() and (3 * number_received_shares) > (2 * self._number_peers):
            attempted_recombine = shamir_recombine(
                unf_shares=self._shares_received,
                t=None,
                robust=True
            )
            if number_received_shares == self._number_peers and attempted_recombine is None:
                self.recombined_secret.cancel()
            elif attempted_recombine is not None:
                self.recombined_secret.set_result(int(attempted_recombine))


class DkgState(object):

    def __init__(self, smc_id: str, number_peers: int, my_id: int, threshold=None, msg_endpoint=''):
        self._smc_id = smc_id
        self._number_peers = number_peers
        self._id = my_id
        self._p = p
        self._q = q
        self._g = g
        self._h = h
        self._msg_endpoint = msg_endpoint

        if threshold is None:
            self._threshold = int(math.floor((2. * number_peers) / 3.))
        else:
            self._threshold = threshold

        loop = asyncio.get_running_loop()

        self._step_1_shares_sent = [None] * self._number_peers
        self._step_1_shares_received = [None] * self._number_peers
        self._step_1_all_shares_received = loop.create_future()
        self._step_1_factors = None
        self._step_1_commitments_sent = [None] * (self._threshold + 1)
        self._step_1_commitments_received = [None] * self._number_peers
        self._step_1_all_commitments_received = loop.create_future()
        self._step_1_complaint_messages = [None] * self._number_peers  # Each peer will send one message containing a (potentially empty) list of complaints; store them here
        self._step_1_complaints_against_me = list()
        self._step_1_all_complaints_received = loop.create_future()
        self._step_1_complaint_reactions_expected = dict()
        self._step_1_complaint_reactions = [None] * self._number_peers
        self._step_1_all_complaint_reactions_received = loop.create_future()
        self._step_1_qualified = loop.create_future()
        self.prv_share = loop.create_future()

        self._step_2_public_shares = [None] * self._number_peers
        self._step_2_all_public_shares_received = loop.create_future()
        self._step_2_complaint_messages = [None] * self._number_peers
        self._step_2_all_complaints_received = loop.create_future()
        self.pub = loop.create_future()

    async def perform_dkg(self):

        # Step 1: Create shares of a mutually agreed secret key

        # Send shares to other players, and broadcast commitments "in parallel"
        await self._step_1_distribution_phase()
        # Wait for all shares and commitments to arrive, validate, and complain if necessary
        await self._step_1_complaint_phase()
        # Wait for all the other complaint messages, react where required
        await self._step_1_complaint_reaction_phase()
        # After reaction phase concludes, determine who gets disqualified
        await self._step_1_disqualification_phase()
        # After the set of qualified players is determined, obtain the peer's share of the secret key
        await self._step_1_set_secret_key_share()

        # Step 2: Extracting the public key

        # All qualified peers expose g^aik
        await self._step_2_distribution_phase()
        # Verify values sent in the distribution phase, complain against cheaters
        await self._step_2_complaint_phase()
        # Reconstruct values for players that equivocated in Step 2
        await self._step_2_reconstruct_phase()
        # Derive public value
        await self._step_2_set_public_key()

        return await self.prv_share, await self.pub

    async def get_final_result(self):
        return await self.prv_share, await self.pub

    async def msg_received(self, msg: dict):
        sender = msg['sender']
        log.debug(f'Received a message from Player {sender}: {msg["smc_typ"]}.')
        if msg['smc_typ'] == 'dkg_step_1_share':
            share_f = Share(FE(msg['smc_value'][0], order=self._q), sender)
            share_f_prime = Share(FE(msg['smc_value'][1], order=self._q), sender)
            self._step_1_shares_received[sender] = (share_f, share_f_prime)
            if self._step_1_all_shares_received.done():
                return
            if len([s for s in self._step_1_shares_received if s is None]) == 0:
                self._step_1_all_shares_received.set_result(True)
        elif msg['smc_typ'] == 'dkg_step_1_commitments':
            commitments = [mpz(c) for c in msg['smc_value']]
            self._step_1_commitments_received[sender] = tuple(commitments)
            if self._step_1_all_commitments_received.done():
                return
            if len([c for c in self._step_1_commitments_received if c is None]) == 0:
                self._step_1_all_commitments_received.set_result(True)
        elif msg['smc_typ'] == 'dkg_step_1_complaints':
            complained_against_players = set(msg['smc_value'])
            self._step_1_complaint_messages[sender] = complained_against_players
            if self._step_1_all_complaints_received.done():
                return
            # If all complaint messages are received, the set of complained-against players
            # has been finalized and we can then check for their reactions
            if len([c for c in self._step_1_complaint_messages if c is None]) == 0:
                self._step_1_all_complaints_received.set_result(True)
        elif msg['smc_typ'] == 'dkg_step_1_complaint_reactions':
            complaint_reaction = msg['smc_value']
            self._step_1_complaint_reactions[sender] = complaint_reaction
            if self._step_1_all_complaint_reactions_received.done():
                return
            expected_complaint_reactions = [self._step_1_complaint_reactions[i] for i in self._step_1_complaint_reactions_expected.keys()]
            if len([r for r in expected_complaint_reactions if r is None]) == 0:
                self._step_1_all_complaint_reactions_received.set_result(True)
        elif msg['smc_typ'] == 'dkg_step_2_public_values':
            public_factors = msg['smc_value']
            self._step_2_public_shares[sender] = public_factors
            if self._step_2_all_public_shares_received.done():
                return
            qualified = await self._step_1_qualified
            log.debug(f'Reference qualified set: {qualified}')
            expected_public_shares = [self._step_2_public_shares[i] for i in qualified]
            log.debug(f'Expected public shares received: {", ".join([str(v is not None) for v in expected_public_shares])}')
            if len([s for s in expected_public_shares if s is None]) == 0:
                log.debug('Received all public shares, I think at least')
                self._step_2_all_public_shares_received.set_result(True)
        elif msg['smc_typ'] == 'dkg_step_2_complaints':
            complained_against_players = msg['smc_value']
            self._step_2_complaint_messages[sender] = complained_against_players
            if self._step_2_all_complaints_received.done():
                return
            qualified = await self._step_1_qualified
            expected_complaint_messages = [self._step_2_complaint_messages[i] for i in qualified]
            if len([c for c in expected_complaint_messages if c is None]) == 0:
                self._step_2_all_complaints_received.set_result(True)

    def __validate_commitment(self, owner: int, receiver: int, share_f=None, share_f_prime=None):
        i = owner
        j = receiver + 1  # Paper goes from j = 1..n; index shift matters here

        if share_f is None and share_f_prime is None:
            share_f = int(self._step_1_shares_received[i][0].share)
            share_f_prime = int(self._step_1_shares_received[i][1].share)
        commitment_opened = mod(powmod(self._g, share_f, self._p) * powmod(self._h, share_f_prime, self._p), self._p)
        commitment_control = mpz(1)
        for k in range(self._threshold + 1):
            Cik = self._step_1_commitments_received[i][k]
            commitment_control = mod(commitment_control * powmod(Cik, j**k, self._p), self._p)

        return commitment_opened == commitment_control

    def __validate_public_shares(self, owner: int, receiver: int, share_f=None):
        i = owner
        j = receiver + 1  # Paper goes from j = 1..n; index shift matters here

        if share_f is None:
            share_f = int(self._step_1_shares_received[i][0].share)
        public_share = powmod(self._g, share_f, self._p)
        public_share_control = mpz(1)
        for k in range(self._threshold + 1):
            Aik = self._step_2_public_shares[i][k]
            public_share_control = mod(public_share_control * powmod(Aik, j**k, self._p), self._p)

        return public_share == public_share_control

    async def __reconstruct_cheater_values(self, i):
        # This prototype does not implement this case as it does not occur during evaluation
        # Instead, this stub returns "successfully" immediately
        # If this was to be implemented: _step_2_set_public_key would then
        # expect that this function overwrites the necessary values as if
        # they were received correctly
        loop = asyncio.get_running_loop()
        result = loop.create_future()
        result.set_result(True)
        return result

    async def _step_1_distribution_phase(self):
        # Player i chooses two random polynomials fi(z), fi'(z) over Zq of degree t
        log.debug('Starting Step 1 Distribution Phase')
        f = FE(random.randint(0, int(q - 1)), order=self._q)
        f_prime = FE(random.randint(0, int(q - 1)), order=self._q)
        shares_f, factors_f = shamir_share(
            s=f,
            n=self._number_peers,
            t=self._threshold,
            order=self._q,
            return_factors=True
        )
        shares_f_prime, factors_f_prime = shamir_share(
            s=f_prime,
            n=self._number_peers,
            t=self._threshold,
            order=self._q,
            return_factors=True
        )

        # Create shares sij, sij'
        log.debug('\n    Sent shares:')
        for j in range(self._number_peers):
            log.debug(f'        to Player {j:3}:')
            log.debug(f'            share_f =       {int(shares_f[j].share)}')
            log.debug(f'            share_f_prime = {int(shares_f_prime[j].share)}')
            self._step_1_shares_sent[j] = (shares_f[j], shares_f_prime[j])

        # Create public commitments Cik
        log.debug('\n    Broadcast commitments (Cik: Ci0..Cit):')
        self._step_1_factors = factors_f
        for k in range(self._threshold + 1):
            Cik = mod(powmod(g, factors_f[k], p) * powmod(h, factors_f_prime[k], p), p)
            self._step_1_commitments_sent[k] = Cik
            log.debug(f'        C_i,{k:02} = {int(Cik)}')

        # Send & broadcast values
        log.debug('    Sending out values to other peers...')

        # Send sij, sij' to every Player j == self._id
        msgs_shares = list()
        for j in range(self._number_peers):
            msgs_shares.append({
                'smc_id': self._smc_id,
                'sender': self._id,
                'smc_typ': 'dkg_step_1_share',
                'smc_value': [int(shares_f[j].share), int(shares_f_prime[j].share)],
            })
        msg_id = next(msg_handler.msg_id_gen)
        msg_own, _ = await msg_handler.eachcast_msg(
            msg_id=msg_id,
            sender=self._id,
            datas=msgs_shares,
            target_endpoint=self._msg_endpoint
        )
        await self.msg_received(msg_own['msg'])

        # Reliably broadcast Cik
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'dkg_step_1_commitments',
            'smc_value': [int(c) for c in self._step_1_commitments_sent],
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        log.debug('Waiting for Step 1 Distribution Phase to conclude')
        # We could validate and complain for each player individually, but
        # doing it in distinct phases makes it a bit easier.
        await asyncio.gather(self._step_1_all_shares_received, self._step_1_all_commitments_received)
        return

    async def _step_1_complaint_phase(self):
        # In the paper, Player j now executes the check and complains against Player i
        log.debug('Starting Step 1 Complaint Phase')
        log.debug(f'Received shares from players: {", ".join([str(s is not None) for s in self._step_1_shares_received])}.')
        log.debug(f'Received commitments from players: {", ".join([str(c is not None) for c in self._step_1_commitments_received])}.')
        complaints = list()
        for i in range(self._number_peers):
            if not self.__validate_commitment(owner=i, receiver=self._id):
                log.debug(f'    Complaining against Player {i}.')
                complaints.append(i)

        if len(complaints) == 0:
            log.debug('    No complaints, I\'ll still send an empty complaint message.')
        else:
            log.debug('    Complaining against these players: {", ".join(complaints)}')

        log.debug('    Broadcasting complaint message...')
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'dkg_step_1_complaints',
            'smc_value': complaints,
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        log.debug('Waiting for Step 1 Complaint Phase to conclude')
        await self._step_1_all_complaints_received
        return

    async def _step_1_complaint_reaction_phase(self):
        log.debug('Starting Step 1 Complaint Reaction Phase')
        # Collect a list of players that accused this peer to react in a single Bracha broadcast
        my_accusers = list()

        # Player j accuses Players i1..ix
        for j, accused in enumerate(self._step_1_complaint_messages):
            for i in accused:
                # Maintain a key-value table of accusations;
                # key: players complained against, value: list of accusers
                if i not in self._step_1_complaint_reactions_expected.keys():
                    self._complaint_reactions_expected[i] = list()
                # Expect that Player i reacts to accusation by Player j in the next phase
                self._complaint_reactions_expected[i].append(j)

                if i == self._id:
                    log.debug(f'    Player {j} complained against me!')
                    my_accusers.append(j)

        if len(my_accusers) == 0:
            log.debug('    Nobody accused me, but I\'ll send an empty reaction.')
        else:
            log.debug('    I was accused by these players: {", ".join(my_accusers)}')

        reactions = dict()
        for accuser in my_accusers:
            share_f = int(self._step_1_shares_sent[accuser][0].share)
            share_f_prime = int(self._step_1_shares_sent[accuser][1].share)
            reactions[accuser] = [share_f, share_f_prime]

        log.debug('    Broadcasting complaint reaction message...')
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'dkg_step_1_complaint_reactions',
            'smc_value': reactions,
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        log.debug('Waiting for Step 1 Complaint Reaction Phase to conclude')
        await self._step_1_all_complaint_reactions_received
        return

    async def _step_1_disqualification_phase(self):
        # Disqualify players if necessary
        log.debug('Starting Step 1 Disqualification Phase.')
        qualified = list()
        accuser_dict = self._step_1_complaint_reactions_expected
        for i in range(self._number_peers):
            accusers = accuser_dict[i] if i in accuser_dict.keys() else list()
            if len(accusers) > self._threshold:
                continue
            elif len(accusers) > 0:
                # Peer must have reacted to complaint
                complaint_reaction = self._step_1_complaint_reactions[i]
                for accuser in accusers:
                    if accuser not in complaint_reaction.keys():
                        continue
                    share_f, share_f_prime = complaint_reaction[accuser]
                    if not self.__validate_commitment(
                            owner=i,
                            receiver=accuser,
                            share_f=share_f,
                            share_f_prime=share_f_prime
                    ):
                        continue
            qualified.append(i)

        log.debug(f'   Players in QUAL: {", ".join([str(q) for q in qualified])}')
        self._step_1_qualified.set_result(qualified)
        log.debug('Concluding Step 1 Disqualification Phase')
        await self._step_1_qualified
        return

    async def _step_1_set_secret_key_share(self):
        log.debug('Starting Step 1 Secret Key Share Derivation')
        secret_key_share = mpz(0)
        for j in await self._step_1_qualified:
            share_f = int(self._step_1_shares_received[j][0].share)
            secret_key_share = mod(secret_key_share + share_f, self._q)

        secret_key_share = Share(FE(secret_key_share, order=self._q), self._id)
        log.debug(f'    My secret key share: {secret_key_share}')
        self.prv_share.set_result(secret_key_share)

        log.debug('Concluding Step 1 Secret Key Share Derivation')
        return await self.prv_share

    async def _step_2_distribution_phase(self):
        log.debug('Starting Step 2 Distribution Phase')
        factors_f = self._step_1_factors

        # Obtain public values g^aik
        public_factors = list()
        log.debug('    Public values (Aik: Ai0..Ait):')
        for k in range(self._threshold + 1):
            public_factor = powmod(self._g, factors_f[k], p)
            log.debug(f'        A_i,{k:02} = {int(public_factor)}')
            public_factors.append(int(public_factor))

        # Reliably broadcast g^aik
        log.debug('    Broadcasting public factors...')
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'dkg_step_2_public_values',
            'smc_value': public_factors,
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        log.debug('Waiting for Step 2 Distribution Phase to conclude')
        await self._step_2_all_public_shares_received
        return

    async def _step_2_complaint_phase(self):
        log.debug('Starting Step 2 Complaint Phase')
        log.debug(f'Received public shares from players: {", ".join([str(v is not None) for v in self._step_2_public_shares])}')
        complaints = dict()
        for i in await self._step_1_qualified:
            if not self.__validate_public_shares(owner=i, receiver=self._id):
                complaints[i] = self._step_1_shares_received[i]

        if len(complaints.keys()) == 0:
            log.debug('    Not complaining against anybody, but I\'ll still send an empty complaint.')
        else:
            log.debug(f'    Complaining against these players: {", ".join(complaints.keys())}')

        log.debug('    Sending complaint messages...')
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'dkg_step_2_complaints',
            'smc_value': complaints,
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        log.debug('Waiting for Step 2 Complaint Phase to conclude')
        await self._step_2_all_complaints_received
        return

    async def _step_2_reconstruct_phase(self):
        # Check for received complaints whether they are valid
        log.debug('Starting Step 2 Reconstruction Phase')
        valid_complaints = list()
        for j in await self._step_1_qualified:  # Check complaint messages by other Player j
            log.debug(f'Complaints by Player {j}: {self._step_2_complaint_messages[j]}')
            for i, complaint in self._step_2_complaint_messages[j].items():  # Validate any complaint by Player j against Player i
                share_f, share_f_prime = complaint
                commitment_valid = self.__validate_commitment(
                    owner=i,
                    receiver=j,
                    share_f=share_f,
                    share_f_prime=share_f_prime
                )
                public_value_valid = self.__validate_public_shares(
                    owner=i,
                    receiver=j,
                    share_f=share_f
                )
                if commitment_valid and not public_value_valid:
                    valid_complaints.append(i)

        if len(valid_complaints) == 0:
            log.debug('    No complaints, nothing needs reconstruction.')
        else:
            log.debug(f'    Reconstruction WOULD be necessary for these players: {", ".join(valid_complaints)}')

        reconstructions = list()
        for i in valid_complaints:
            reconstructions.append(self.__reconstruct_cheater_values(i))

        log.debug('Waiting for Step 2 Reconstruction Phase to conclude')
        await asyncio.gather(*reconstructions)
        return

    async def _step_2_set_public_key(self):
        log.debug('Starting Step 2 Public Key Derivation')
        public_key = mpz(1)
        for i in await self._step_1_qualified:
            y = self._step_2_public_shares[i][0]
            public_key = mod(public_key * y, p)
        self.pub.set_result(int(public_key))
        log.debug(f'    Public key: {int(public_key)}')
        log.debug('Concluded Step 2 Public Key Derivation')
        return await self.pub


class DistributedRedactionState(DkgState):

    def __init__(
            self,
            block: blockchain.CRedactableBlock,
            tx_index: int,  # Position of transaction to be redacted in the block's vtx
            claim: str,
            chf_pub: mpz,
            chf_prv_share: Share,
            smc_id: str,
            number_peers: int,
            my_id: int,
            threshold=None,
            msg_endpoint=''
    ):
        super(DistributedRedactionState, self).__init__(
            smc_id=smc_id,
            number_peers=number_peers,
            my_id=my_id,
            threshold=threshold,
            msg_endpoint=msg_endpoint
        )
        if claim is not None and claim not in blockchain.valid_redaction_claims:
            raise RuntimeError('Invalid redaction claim, not supported.')

        loop = asyncio.get_running_loop()

        self._block_unredacted = block
        self._block_redacted = None
        self._tx_redacted = None
        self._tx_index = tx_index
        self._claim = claim
        self._chf_pub = chf_pub
        self._chf_prv_share = chf_prv_share
        self._chf = chf.ChameleonHashFunction(public_key=self._chf_pub)

        self._shares_s_received = [None] * self._number_peers
        self._s_redacted_recombined = loop.create_future()
        self.redacted_block = loop.create_future()
        self.redacted_tx = loop.create_future()

    def set_missing_info(
            self,
            block: blockchain.CRedactableBlock,
            tx_index: int,  # Position of transaction to be redacted in the block's vtx
            claim: str,
            chf_pub: mpz,
            chf_prv_share: Share,
    ):
        self._block_unredacted = block
        self._tx_index = tx_index
        self._claim = claim
        self._chf_pub = chf_pub
        self._chf_prv_share = chf_prv_share
        self._chf = chf.ChameleonHashFunction(public_key=self._chf_pub)

    def _check_for_all_msgs_received(self):
        if self.redacted_block.done():
            del transaction_manager[self._smc_id]

    async def perform_redaction(self):
        # Replicate ChameleonHashFunction.compute_collision while knowing that
        # the message to redact is a CRedactableBlock

        eval.get_eval().start('redaction_inner')

        eval.get_eval().start('redaction_prepare')
        # Get both the unredacted and redacted block, and in serialized form for chameleon-hashing
        block_serialized_unredacted = self._block_unredacted.serialize_for_chameleon_hashing()
        self._block_redacted, self._tx_redacted = blockchain.redact_tx_in_block(
            self._block_unredacted,
            self._tx_index,
            self._claim
        )
        block_serialized_redacted = self._block_redacted.serialize_for_chameleon_hashing()

        # Obtain original r, s values
        r_unredacted_bytes = self._block_unredacted.checkValueR
        r_unredacted = mpz(int.from_bytes(r_unredacted_bytes, 'little'))
        s_unredacted_bytes = self._block_unredacted.checkValueS
        s_unredacted = mpz(int.from_bytes(s_unredacted_bytes, 'little'))

        # Recompute the block's original hash value
        hash_unredacted, _, _ = self._chf.get_hash(
            msg=block_serialized_unredacted,
            r=r_unredacted,
            s=s_unredacted
        )
        hash_unredacted = mod(mpz(int.from_bytes(hash_unredacted, 'little')), self._q)
        eval.get_eval().stop('redaction_prepare')

        # Choose a randomly in a distributed fashion
        eval.get_eval().start('a_per_dkg')
        share_a, g_a = await self.perform_dkg()
        eval.get_eval().stop('a_per_dkg')

        # Get r'
        eval.get_eval().start('update_r')
        r_redacted = mod(hash_unredacted + g_a, self._q)
        r_redacted_bytes = int(r_redacted).to_bytes(bit_length // 8, 'little')
        self._block_redacted.checkValueR = r_redacted_bytes
        eval.get_eval().stop('update_r')

        # Get new inner hash value sha256(M'||r')
        eval.get_eval().start('update_inner_hash')
        sha = sha256()
        sha.update(block_serialized_redacted)
        sha.update(r_redacted_bytes)
        inner_hash_value = mod(mpz(int.from_bytes(sha.digest(), 'little')), self._q)
        eval.get_eval().stop('update_inner_hash')

        # Get share [s'] of s'
        eval.get_eval().start('update_s')
        s_redacted_share = share_a - (inner_hash_value * self._chf_prv_share)
        log.debug(f'    s_redacted_share = {s_redacted_share}')

        # Recombine [s'] using Bracha broadcast
        log.debug('    Broadcasting my s\' share for recombination...')
        msg_id = next(msg_handler.msg_id_gen)
        msg = {
            'smc_id': self._smc_id,
            'sender': self._id,
            'smc_typ': 'rec_s_share',
            'smc_value': int(s_redacted_share.share),
        }
        msg_agreed_upon_waiter = await msg_handler.bracha_broadcast_msg(
            msg_id=msg_id,
            sender=self._id,
            data=msg,
            target_endpoint=self._msg_endpoint
        )
        msg_agreed_upon = await msg_agreed_upon_waiter
        await self.msg_received(msg_agreed_upon)

        s_redacted = await self._s_redacted_recombined
        s_redacted = int(s_redacted)
        s_redacted_bytes = s_redacted.to_bytes(bit_length // 8, 'little')

        self._block_redacted.checkValueS = s_redacted_bytes

        eval.get_eval().stop('update_s')

        # Avoid measuring asserting the correctness, but don't take out that code to be sure
        log.debug(f'CURRENT MEASUREMENT: {eval.get_eval()._measurements}')
        eval.get_eval().stop('redaction_inner')

        # Validate that chameleon hash value has not changed due to the redaction
        chameleon_hash_unredacted = self._block_unredacted.GetChameleonHash(chameleon_hash_function=self._chf)
        chameleon_hash_redacted = self._block_redacted.GetChameleonHash(chameleon_hash_function=self._chf)
        assert chameleon_hash_unredacted == chameleon_hash_redacted

        self.redacted_block.set_result(self._block_redacted)
        self.redacted_tx.set_result(self._tx_redacted)

        return await self.redacted_block, await self.redacted_tx

    async def msg_received(self, msg: dict):
        if msg['smc_typ'][:3] == 'dkg':
            await super(DistributedRedactionState, self).msg_received(msg)
            return

        sender = msg['sender']
        if msg['smc_typ'] == 'rec_s_share':
            share_f = Share(FE(msg['smc_value'], order=self._q), sender)
            self._shares_s_received[sender] = share_f
            if self._s_redacted_recombined.done():
                return
            if len([s for s in self._shares_s_received if s is None]) == 0:
                self._s_redacted_recombined.set_result(
                    shamir_recombine(
                        unf_shares=self._shares_s_received,
                        order=self._q,
                        robust=True
                    )
                )


async def distributed_key_generation(smc_id: str, target_endpoint=''):
    dkg_state = DkgState(
        smc_id=smc_id,
        number_peers=global_config()['number_peers'],
        my_id=global_config()['peer_id'],
        msg_endpoint=target_endpoint
    )
    if smc_id in transaction_manager.keys():
        raise RuntimeError('SMC ID for new DKG instance already in transaction manager.')
    transaction_manager[smc_id] = dkg_state
    await dkg_state.perform_dkg()
    return await dkg_state.get_final_result()


async def distributed_redaction(
        block: blockchain.CRedactableBlock,
        tx_ind: int,
        claim: str,
        smc_id: str,
        target_endpoint=''
):
    number_peers = global_config()['number_peers']
    my_id = global_config()['peer_id']
    chf_pub = mpz(global_config()['chf_pub'])
    chf_prv_share = Share(FE(global_config()['chf_prv_share'], q), my_id)

    if smc_id in transaction_manager.keys():
        redaction_state = transaction_manager[smc_id]
        redaction_state.set_missing_info(
            block=block,
            tx_index=tx_ind,
            claim=claim,
            chf_pub=chf_pub,
            chf_prv_share=chf_prv_share,
        )
    else:
        redaction_state = DistributedRedactionState(
            block=block,
            tx_index=tx_ind,
            claim=claim,
            chf_pub=chf_pub,
            chf_prv_share=chf_prv_share,
            smc_id=smc_id,
            number_peers=number_peers,
            my_id=my_id,
            msg_endpoint=target_endpoint
        )
        transaction_manager[smc_id] = redaction_state
    return await redaction_state.perform_redaction()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    order = 17
    v = 10

    order = q
    v = 9247

    log.debug('Testing FE operations')
    x = FE(v, order=order)
    x_neg = FE(order - v, order=order)
    log.debug(f' x = {x}\n-x = {-x}')
    assert -x == x_neg
    log.debug('FE negation test passed')

    log.debug('Testing Shamir')
    shares = shamir_share(x, 4, order=order)
    log.debug(f'Shares of secret {v}: {shares}')
    recombined = shamir_recombine(shares, robust=True, order=order)
    log.debug(f'Recomination of shares: {repr(recombined)}')
    recombined_again = shamir_recombine(shares, robust=True, order=order)
    log.debug(f'Second recomination of shares: {repr(recombined)}')

    # Determine 2 random shares to tamper with
    kill_inds = random.sample(range(len(shares)), 2)

    # Delete one random share, recombine
    shares[kill_inds[0]] = None
    recombined_kill_one = shamir_recombine(shares, robust=False, order=order)
    log.debug(f'Recombination after deleting Player {kill_inds[0]}\' share: {recombined_kill_one}')

    # Replace first deleted share with random new share
    # Should give random output if robust=False and recombine
    # correctly using Welch-Berlekamp algorithm if robust=True
    shares[kill_inds[0]] = Share(
        share=FE(random.randint(0, int(order)), order=order),
        player=kill_inds[0]
    )
    recombined_malicious_naive = shamir_recombine(shares, robust=False, order=order)
    log.debug(f'Recombination after Player {kill_inds[0]} submits wrong share: {recombined_malicious_naive}')

    recombined_malicious_robust = shamir_recombine(shares, robust=True, order=order)
    log.debug(f'Recombination after Player {kill_inds[0]} submits wrong share with fixing: {recombined_malicious_robust}')

    # Delete second share; non-robust should produce random output,
    # Robust should yield None
    shares[kill_inds[1]] = None
    recombined_kill_two = shamir_recombine(shares, robust=False, order=order)
    log.debug(f'Non-Robust Recombination after deleting Player {kill_inds[1]}\' share: {recombined_kill_two}')
    recombined_kill_two_robust = shamir_recombine(shares, robust=True, order=order)
    log.debug(f'Recombination after Player {kill_inds[1]} submits wrong share with fixing: {recombined_kill_two_robust}')

    # Redelete first share, now non-robust should also produce None:
    shares[kill_inds[0]] = None
    recombined_kill_one = shamir_recombine(shares, robust=False, order=order)
    log.debug(f'Recombination after deleting Player {kill_inds[0]}\' share: {recombined_kill_one}')
    recombined_kill_one = shamir_recombine(shares, robust=True, order=order)
    log.debug(f'Recombination after deleting Player {kill_inds[0]}\' share with fixing: {recombined_kill_one}')
