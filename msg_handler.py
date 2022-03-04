import logging
import asyncio
import struct
import json
from hashlib import sha256
import base64

from Cryptodome.Random.random import getrandbits
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA384

from config import global_config


log = logging.getLogger('msg_handler')
log.setLevel(logging.INFO)

available_msg_typs = ['singlecast', 'broadcast', 'bracha_broadcast']


msg_id_gen = None
transaction_manager = dict()
app = None


def set_app(a):
    global app
    app = a


def MessageIdIterator(peer_id: int, start=None):
    """ This generator keeps track of the last used message ID by this peer and obtains the next one.
        For simplicity reasons, we use incrementing sequence numbers prefixed with the peer's ID.
        Security is not a factor for this prototype, only distinguishing different messages. """
    if start is None:
        sequence_number = getrandbits(56)  # Sequence numbers will be prepended with an additional byte for the (original) sender ID
    else:
        sequence_number = start % ((1 << 56) - 1)

    peer_id_bin = struct.pack('!B', (peer_id % 256))

    while True:
        sequence_number_bin = struct.pack('!Q', sequence_number)[1:]
        yield (peer_id_bin + sequence_number_bin).hex()
        sequence_number = (sequence_number + 1) % ((1 << 56) - 1)


def sign_msg(msg: dict):
    sign_string = json.dumps(msg, sort_keys=True).encode('utf-8')
    signer = pkcs1_15.new(global_config()['sign_prv'])
    hasher = SHA384.new()
    hasher.update(sign_string)
    signature = signer.sign(hasher)
    signature = base64.b64encode(signature).decode('utf-8')
    msg['sig'] = signature
    return msg


def verify_msg(msg: dict):
    signature = msg['sig']
    signature = base64.b64decode(signature.encode('utf-8'))
    del msg['sig']
    sign_string = json.dumps(msg, sort_keys=True).encode('utf-8')
    signer = pkcs1_15.new(global_config()['peers'][msg['sender']]['pub'])
    hasher = SHA384.new()
    hasher.update(sign_string)
    signer.verify(hasher, signature)
    return msg


def prepare_msg(msg_id: str, sender: int, data: dict, msg_typ: str):
    assert msg_typ in available_msg_typs
    msg = {
        'msg_id': msg_id,
        'typ': msg_typ,
        'sender': sender,
        'msg': data,
    }
    return msg


def check_message(msg: dict):
    msg_keys = msg.keys()
    if 'msg_id' not in msg_keys or len(msg['msg_id']) != 16:
        log.debug('Message ID missing or of wrong length.')
        raise RuntimeError('Message ID missing or of wrong length.')
    try:
        bytes.fromhex(msg['msg_id'])
    except ValueError:
        log.debug('Message ID not valid hex.')
        raise RuntimeError('Message ID not valid hex.')

    if 'typ' not in msg_keys:
        log.debug('Message type missing.')
        raise RuntimeError('Message type missing.')
    if msg['typ'] not in available_msg_typs:
        log.debug('Invalid message type.')
        raise RuntimeError('Invalid message type.')

    if 'sender' not in msg_keys:
        log.debug('Message sender missing.')
        raise RuntimeError('Message sender missing.')

    if 'msg' not in msg_keys:
        log.debug('Message payload missing.')
        raise RuntimeError('Message payload missing.')

    # Check signature
    if 'sig' not in msg_keys:
        log.debug('Signature missing.')
        raise RuntimeError('Signature missing.')
    try:
        msg = verify_msg(msg)
    except ValueError:
        log.debug('Invalid signature.')
        raise RuntimeError('Invalid signature.')

    return msg


async def accept_message(msg: dict, from_endpoint=''):
    """ Assumption: check_message() has been called before; validation not necessary again. """
    if msg['typ'] == 'bracha_broadcast':
        if msg['msg_id'] not in transaction_manager.keys():
            bracha_state = BrachaState(
                msg_id=msg['msg_id'],
                number_peers=global_config()['number_peers'],
                target_endpoint=from_endpoint
            )
            transaction_manager[msg['msg_id']] = bracha_state
            bracha_state.msg_received(msg)
            accepted_message = await bracha_state.get_message()
        else:
            bracha_state = transaction_manager[msg['msg_id']]
            bracha_state.msg_received(msg)
            accepted_message = None  # We are in the middle of accepting the real message, another "instance" of the msg_handler was tasked with accepting the message
    else:
        loop = asyncio.get_running_loop()
        accepted_message = loop.create_future()
        accepted_message.set_result(msg['msg'])

    return accepted_message


def get_message_hash(msg: dict):
    repr_for_hashing = json.dumps(msg, sort_keys=True).encode('utf-8')
    hasher = sha256()
    hasher.update(repr_for_hashing)
    return hasher.hexdigest()


def get_most_frequent_msg(container: list):
    """ This function iterates over all messages in the container to determine which one was
        received most often until this point. Returns the message count, number of outstanding
        responses, and the currently most frequent message. """
    hist = dict()
    for msg in container:
        if msg is None:
            continue
        msg_hash = get_message_hash(msg)
        if msg_hash not in hist.keys():
            hist[msg_hash] = {'msg': msg, 'count': 0}  # Merge equivalent messages (ignore reordering), return first repr observed
        hist[msg_hash]['count'] += 1
    count_max = 0
    msg = None
    for entry in hist.values():
        if entry['count'] > count_max:
            count_max = entry['count']
            msg = entry['msg']
    open_responses = sum(x is None for x in container)
    return count_max, open_responses, msg


class BrachaState(object):

    def __init__(self, msg_id: str, number_peers: int, target_endpoint=''):
        loop = asyncio.get_running_loop()
        self._msg_id = msg_id  # Equivocations regarding the message ID should "naturally" sort themselves out - only leave a polluted transaction store
        self._number_peers = number_peers
        self._target_endpoint = target_endpoint

        self._send_received = None
        self._echoes_received = [None] * number_peers
        self._accepts_received = [None] * number_peers

        self.accepted_msg_for_echoes = loop.create_future()
        loop.create_task(self._broadcast_echoes())

        self.accepted_msg_for_accepts = loop.create_future()
        loop.create_task(self._broadcast_accepts())

        self.accepted_message = loop.create_future()

    async def get_message(self):
        return self.accepted_message

    def _send_envelope_received(self, env: dict):
        if self._send_received is not None:
            raise RuntimeError('Received additional Bracha send.')
        self._send_received = env['msg']

    def _echo_envelope_received(self, env: dict):
        self._echoes_received[env['sender']] = env['msg']

    def _accept_envelope_received(self, env: dict):
        self._accepts_received[env['sender']] = env['msg']

    def _check_for_all_msgs_received(self):
        # Remove myself from transaction manager once state becomes irrelevant
        if self._send_received is not None and len([m for m in self._echoes_received if m is None]) == 0 and len([m for m in self._accepts_received if m is None]) == 0:
            del transaction_manager[self._msg_id]

    def _check_for_actions(self):
        # Get the number and content of most echoed message this peer received, and number of open slots
        n_most_echoes, n_open_echoes, msg_echo = get_most_frequent_msg(self._echoes_received)
        n_most_accepts, n_open_accepts, msg_accept = get_most_frequent_msg(self._accepts_received)

        log.debug(f'Bracha testing for action.')
        log.debug(f'Send message: {self._send_received}')
        log.debug(f'Echoes: {n_most_echoes} echoes ({n_open_echoes} open slots) for msg {msg_echo}.')
        log.debug(f'Accept: {n_most_accepts} accept ({n_open_accepts} open slots) for msg {msg_accept}.')

        # Decide about echoing
        if not self.accepted_msg_for_echoes.done():
            msg = None
            if self._send_received is not None:
                msg = self._send_received
            elif (3 * n_most_echoes) > (2 * self._number_peers):
                msg = msg_echo
            elif (3 * n_most_accepts) > self._number_peers:
                msg = msg_accept

            if msg is not None:
                self.accepted_msg_for_echoes.set_result(msg)

        # Decide about accepting
        if not self.accepted_msg_for_accepts.done():
            # Check whether we can accept
            msg = None
            if (3 * n_most_echoes) > (2 * self._number_peers):
                msg = msg_echo
            elif (3 * n_most_accepts) > self._number_peers:
                msg = msg_accept

            if msg is not None:
                self.accepted_msg_for_accepts.set_result(msg)

        # Decide about concluding acceptance
        if not self.accepted_message.done():
            if (3 * n_most_accepts) > (2 * self._number_peers):
                self.accepted_message.set_result(msg_accept)

        # Decide about cancelling
        # Note: Cancelling does not affect Futures that are already done (set_result() was called)
        #       Hence, it's okay to just cancel any phase we did not accept in this function call
        #       and know we won't ever enter due to the lack of pending responses.
        # Note: Since by design no peer accepts the msg without seeing > n/3 accepts, and no honest
        #       peer sends any accept without having seen > 2n/3 echoes, we can cancel one phase
        #       *and* all its following phases immediately.
        cancel_everything = False

        # We can never receive enough echoes
        if (3 * (n_most_echoes + n_open_echoes)) <= (2 * self._number_peers):
            cancel_everything = True
        # We can never receive enough accepts
        elif (3 * (n_most_accepts + n_open_accepts)) <= self._number_peers:
            cancel_everything = True

        if cancel_everything:
            self.accepted_msg_for_echoes.cancel()
            self.accepted_msg_for_accepts.cancel()
            self.accepted_message.cancel()

    async def _broadcast_helper(self, bracha_typ: str, data: dict):
        msg = prepare_msg(
            msg_id=self._msg_id,
            sender=global_config()['peer_id'],
            data=data,
            msg_typ='bracha_broadcast'
        )
        msg['bracha_typ'] = bracha_typ
        msg = sign_msg(msg)
        log.debug(f'Bracha: Broadcasting {msg}.')
        self.msg_received(msg)
        await broadcast_prepared_msg(msg, self._target_endpoint)
        return msg

    async def broadcast_send(self, data: dict):
        return await self._broadcast_helper('send', data)

    async def _broadcast_echoes(self):
        return await self._broadcast_helper('echo', await self.accepted_msg_for_echoes)

    async def _broadcast_accepts(self):
        return await self._broadcast_helper('accept', await self.accepted_msg_for_accepts)

    def msg_received(self, msg: dict):
        if 'bracha_typ' not in msg.keys():
            raise RuntimeError('Bracha message type missing.')
        elif msg['bracha_typ'] not in ['send', 'echo', 'accept']:
            raise RuntimeError('Invalid Bracha message type.')

        if msg['bracha_typ'] == 'send':
            self._send_envelope_received(msg)
        elif msg['bracha_typ'] == 'echo':
            self._echo_envelope_received(msg)
        elif msg['bracha_typ'] == 'accept':
            self._accept_envelope_received(msg)

        self._check_for_actions()
        self._check_for_all_msgs_received()


async def _singlecast_prepared_msg(msg: dict, receiver_id: int, target_endpoint=''):
    global app
    receiver_endpoint = global_config().get_endpoint(receiver_id)
    endpoint = f'{receiver_endpoint}{target_endpoint}'
    async with app['PERSISTENT_SESSION'].post(endpoint, json=msg) as resp:
        log.debug(f'Sent request to {endpoint}: {msg}')
        result = await resp.json()
        log.debug(f'Received response: {result}.')
    return result


async def singlecast_msg(msg_id: str, sender: int, data: dict, receiver_id: int, target_endpoint=''):
    """ This function sends a single message to the receiver's targeted endpoint, e.g. /smc. """
    msg = prepare_msg(msg_id, sender, data, msg_typ='singlecast')
    msg['typ'] = 'singlecast'
    msg = sign_msg(msg)
    return await asyncio.ensure_future(_singlecast_prepared_msg(msg, receiver_id, target_endpoint))


async def eachcast_msg(msg_id: str, sender: int, datas: list, target_endpoint=''):
    """ This function sends a list of messages to each peer *EXCEPT* the sender.
        The idea is, that each peer should receive some message for the same context, but with
        different payloads (e.g., distributing Shamir shares).
        Returns the message the peer would have sent to itself. """
    peer_ids = global_config()['peers'].keys()
    msg_own = None
    responses = list()
    for receiver_id, data in zip(peer_ids, datas):
        msg = prepare_msg(msg_id, sender, data, msg_typ='singlecast')
        msg = sign_msg(msg)
        if receiver_id == global_config()['peer_id']:
            msg_own = msg
            continue
        responses.append(asyncio.create_task(_singlecast_prepared_msg(msg, receiver_id, target_endpoint)))
    return msg_own, await asyncio.gather(*responses)


async def broadcast_prepared_msg(msg: dict, target_endpoint=''):
    """ Do the sending of a fully (otherwise) prepared message.
        To be used by normal and Bracha broadcasts. """
    receiver_ids = [p for p in global_config()['peers'].keys() if p != global_config()['peer_id']]
    responses = list()
    for receiver_id in receiver_ids:
        responses.append(asyncio.create_task(_singlecast_prepared_msg(msg, receiver_id, target_endpoint)))
    return msg, await asyncio.gather(*responses)


async def broadcast_msg(msg_id: str, sender: int, data: dict, target_endpoint=''):
    """ This function sends a broadcast to each peer *EXCEPT* the sender.
        Returns the message the peer would have sent to itself. """
    msg = prepare_msg(msg_id, sender, data, msg_typ='broadcast')
    msg = sign_msg(msg)
    return await broadcast_prepared_msg(msg, target_endpoint)


async def bracha_broadcast_msg(msg_id: str, sender: int, data: dict, target_endpoint=''):
    """ This function sends a Bracha broadcast to each peer *EXCEPT* the sender.
        Returns the message the peer would have sent to itself. """
    bracha_state = BrachaState(
        msg_id=msg_id,
        number_peers=global_config()['number_peers'],
        target_endpoint=target_endpoint
    )
    if msg_id in transaction_manager.keys():
        raise RuntimeError('Message ID for new Bracha broadcast already in transaction manager.')
    transaction_manager[msg_id] = bracha_state
    await bracha_state.broadcast_send(data)
    return await bracha_state.get_message()
