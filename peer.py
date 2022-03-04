#!/usr/bin/env python3

import logging
import argparse
import pathlib

import asyncio
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.connector import TCPConnector

import config
import msg_handler
from blockchain import load_blockchain, b2x, b2lx, redact_tx, redact_tx_in_block, DEFAULT_BLOCKCHAIN_FOLDER
import chf
import smc
import eval
from parameters import bit_length


log = logging.getLogger('peer')

log_aiohttp = logging.getLogger('timeout-tests')
log_aiohttp.setLevel(logging.DEBUG)
log_access = logging.getLogger('access-timeout-tests')
log_access.setLevel(logging.DEBUG)


routes = web.RouteTableDef()
report_msg_id_gen = None

blocks = None
block_index = None
tx_index = None

# Collect Timeouts here
TCP_KEEPALIVE_TIMEOUT = 36000
TCP_LIMIT_CONNECTIONS_TOTAL = 1000
TCP_LIMIT_CONNECTIONS_PER_HOST = 10
CLIENT_TIMEOUT_TOTAL = 36000

SERVER_KEEPALIVE_TIMEOUT = 36000
SERVER_SHUTDOWN_TIMEOUT = 60.0  # The default value
SERVER_MAX_CLIENT_REQUEST_SIZE = 1024**4


async def persistent_session(app):
    connector = TCPConnector(
        limit=TCP_LIMIT_CONNECTIONS_TOTAL,
        limit_per_host=TCP_LIMIT_CONNECTIONS_PER_HOST,
        keepalive_timeout=TCP_KEEPALIVE_TIMEOUT
    )
    app['PERSISTENT_SESSION'] = session = ClientSession(
        connector=connector,
        timeout=ClientTimeout(total=CLIENT_TIMEOUT_TOTAL)
    )
    yield
    await session.close()


def get_endpoint(peer_id=None):
    if peer_id is None:
        host, port = config.global_config()['host'], config.global_config()['port']
    else:
        assert 0 <= peer_id < len(config.global_config()['peers'])
        host, port = config.global_config()['peers'][peer_id]['host'], config.global_config()['peers'][peer_id]['port']
    endpoint = f'http://{host}:{port}'
    return endpoint


async def execute_distributed_redaction(
        block_id: str,
        txid: str,
        tx_ind: int,
        claim: str,
        smc_id: str
):
    global blocks, block_index, tx_index
    block_ind = block_index[block_id]
    block = blocks[block_ind]
    # Redact block
    redacted_block, redacted_tx = await smc.distributed_redaction(
        block=block,
        tx_ind=tx_ind,
        claim=claim,
        smc_id=smc_id,
        target_endpoint='/smc'
    )
    # Update block index
    redacted_txid = b2lx(redacted_tx.GetTxid())
    blocks[block_ind] = redacted_block
    tx_index[redacted_txid] = tx_index[txid]
    # We deliberately don't delete the old entry in case that a belated transaction spending an only-obfuscated output arrives


@routes.get('/')
async def online_check(request):
    return web.json_response({'online': True})


@routes.post('/test_echo')
async def test_msg_handler(request):
    msg = await request.json()

    try:
        msg = msg_handler.check_message(msg)
    except RuntimeError:
        return web.json_response({'success': False, 'error': 'validation_error'})
    msg_future = await msg_handler.accept_message(msg, from_endpoint='/test_echo')
    if asyncio.isfuture(msg_future):
        sender = msg['sender']
        payload = await msg_future
        log.info(f'I accepted a message from Peer #{sender}: {payload}')
    return web.json_response({'success': True})


@routes.post('/test_echo_singlecast')
async def test_singlecaster(request):
    data = await request.json()
    msg = data['msg']
    receiver_id = data['receiver_id']
    response = await msg_handler.singlecast_msg(
        msg_id=next(msg_handler.msg_id_gen),
        sender=config.global_config()['peer_id'],
        data=msg,
        receiver_id=receiver_id,
        target_endpoint='/test_echo'
    )
    log.debug(f'Type of response: {response}')
    return web.json_response({
        'response': response
    })


@routes.post('/test_echo_eachcast')
async def test_eachcaster(request):
    data = await request.json()
    base_value = data['base_value']
    msgs = [{'your_value': base_value + i} for i in range(config.global_config()['number_peers'])]
    msg, responses = await msg_handler.eachcast_msg(
        msg_id=next(msg_handler.msg_id_gen),
        sender=config.global_config()['peer_id'],
        datas=msgs,
        target_endpoint='/test_echo'
    )
    log.debug(f'My own message: {msg}')
    log.debug(f'List of responses: {responses}.')
    return web.json_response({
        'own_value': msg,
        'responses': responses
    })


@routes.post('/test_echo_broadcast')
async def test_broadcaster(request):
    msg, responses = await msg_handler.broadcast_msg(
        msg_id=next(msg_handler.msg_id_gen),
        sender=config.global_config()['peer_id'],
        data=await request.json(),
        target_endpoint='/test_echo'
    )
    log.debug(f'My own message: {msg}')
    log.debug(f'List of responses: {responses}.')
    return web.json_response({
        'own_value': msg,
        'responses': responses
    })


@routes.post('/test_echo_bracha')
async def test_bracha_broadcaster(request):
    try:
        msg = await msg_handler.bracha_broadcast_msg(
            msg_id=next(msg_handler.msg_id_gen),
            sender=config.global_config()['peer_id'],
            data=await request.json(),
            target_endpoint='/test_echo'
        )
        log.debug(f'Accepted Bracha message: {msg.result()}')
        response = {'success': True, 'accepted_message': msg.result()}
    except asyncio.CancelledError:
        response = {'success': False, 'error': 'bracha_broadcast_cancelled'}

    return web.json_response(response)


@routes.post('/gettx')
async def get_transaction_handler(request):
    """ This is a *test* function that returns a tranaction.
        Optionally, by setting the requests 'redact' key to either 'opreturn'
        or 'obfuscate', you can check that preparing the transaction for a
        block redaction works properly. """
    msg = await request.json()
    if 'transaction_id' not in msg.keys():
        web.json_response({'success': False, 'error': 'validation_error'})
    redact_action = msg['claim'] if 'claim' in msg.keys() else None
    try:
        block_id, i = tx_index[msg['transaction_id']]
        tx = blocks[block_index[block_id]].vtx[i]
        if redact_action is not None:
            tx = redact_tx(tx, redact_action)
        tx = b2x(tx.serialize())
        response = {'success': True, 'tx': tx}
    except:
        response = {'success': False, 'error': 'transaction_not_found'}
        raise
    return web.json_response(response)


@routes.post('/redactcentral')
async def centralized_redaction_handler(request):
    """ This is a *test* function that redacts a transaction from a block.
        It is the centralized counterpart to the decentralized redaction
        provided by RedactChain and serves as means to test the functionality. """
    msg = await request.json()
    if 'transaction_id' not in msg.keys() or 'claim' not in msg.keys():
        web.json_response({'success': False, 'error': 'validation_error'})

    redact_action = msg['claim']

    # As this is only a test function, the peer is allowed to "cheat" and read the
    # private key from the config file that would otherwise not be visible to them
    # in real deployments
    chameleon_hash_function = chf.ChameleonHashFunction(
        private_key=config.global_config()['chf_prv'],
        public_key=config.global_config()['chf_pub']
    )

    try:
        block_id, i = tx_index[msg['transaction_id']]
        block = blocks[block_index[block_id]]
        h_test = block.GetChameleonHash(chameleon_hash_function=chameleon_hash_function)
        r = int.from_bytes(block.checkValueR, 'little')
        s = int.from_bytes(block.checkValueS, 'little')
    except KeyError:
        response = {'success': False, 'error': 'transaction_not_found'}
        return web.json_response(response)
    msg_unredacted = block.serialize_for_chameleon_hashing()
    block_updated, tx = redact_tx_in_block(block, i, redact_action)
    msg_updated = block_updated.serialize_for_chameleon_hashing()
    r_new, s_new = chameleon_hash_function.compute_collision(
        msg=msg_unredacted,
        msg_new=msg_updated,
        r=r,
        s=s
    )
    block_updated.checkValueR = int(r_new).to_bytes(bit_length // 8, 'little')
    block_updated.checkValueS = int(s_new).to_bytes(bit_length // 8, 'little')
    assert block_updated.serialize_for_chameleon_hashing() == msg_updated
    assert chameleon_hash_function.validate_hash(h_test, msg_unredacted, r, s)

    chameleon_hash_reference = blocks[block_index[block_id] + 1].hashesValidity[0]
    chameleon_hash_updated = block_updated.GetChameleonHash(chameleon_hash_function=chameleon_hash_function)

    if chameleon_hash_updated == chameleon_hash_reference and block_updated.GetHash() == block.GetHash():
        blocks[block_index[block_id]] = block_updated
        tx = b2x(tx.serialize())
        response = {'success': True, 'tx': tx}
    else:
        response = {'success': False, 'error': 'redaction_failed'}
    return web.json_response(response)


@routes.post('/test_dkg')
async def test_dkg_handler(request):
    msg = await request.json()
    # Important: To start a new DKG instance, send this "start_dkg" command to each peer
    # In our implementation, the peers will automatically synchronize for redactions via
    # the Bracha broadcast containing the report.
    if 'start_dkg' in msg.keys() and msg['start_dkg']:
        smc_id = next(report_msg_id_gen)
        prv_share, pub = await smc.distributed_key_generation(
            smc_id=smc_id,
            target_endpoint='/test_dkg'
        )
        log.info(f'CONCLUDED DKG!\n    My private key share: {int(prv_share.share)}\n    Public key: {pub}')
        return web.json_response({'success': True})

    try:
        msg = msg_handler.check_message(msg)
    except RuntimeError:
        return web.json_response({'success': False, 'error': 'validation_error'})
    if not smc.check_message(msg['msg']):
        return web.json_response({'success': False, 'error': 'smc_validation_error'})
    if msg['sender'] != msg['msg']['sender'] and not (msg['typ'] == 'bracha_broadcast' and msg['bracha_typ'] in ['echo', 'accept']):
        return web.json_response({'success': False, 'error': 'smc_sender_equivocation_error'})

    # Extract SMC payload, possibly a Bracha broadcast
    smc_msg_waiter = await msg_handler.accept_message(msg, from_endpoint='/test_dkg')

    if asyncio.isfuture(smc_msg_waiter):
        smc_msg = await smc_msg_waiter
        if smc_msg['smc_id'] not in smc.transaction_manager.keys():
            dkg_state = smc.DkgState(
                smc_id=smc_msg['smc_id'],
                number_peers=config.global_config()['number_peers'],
                my_id=config.global_config()['peer_id'],
                msg_endpoint='/test_dkg'
            )
            smc.transaction_manager[smc_msg['smc_id']] = dkg_state
        else:
            dkg_state = smc.transaction_manager[smc_msg['smc_id']]
        await dkg_state.msg_received(smc_msg)
    return web.json_response({'success': True})


@routes.post('/smc')
async def smc_handler(request):
    msg = await request.json()

    try:
        msg = msg_handler.check_message(msg)
    except RuntimeError:
        return web.json_response({'success': False, 'error': 'validation_error'})
    if not smc.check_message(msg['msg']):
        return web.json_response({'success': False, 'error': 'smc_validation_error'})
    if msg['sender'] != msg['msg']['sender'] and not (msg['typ'] == 'bracha_broadcast' and msg['bracha_typ'] in ['echo', 'accept']):
        return web.json_response({'success': False, 'error': 'smc_sender_equivocation_error'})

    # Extract SMC payload, possibly a Bracha broadcast
    smc_msg_waiter = await msg_handler.accept_message(msg, from_endpoint='/smc')

    if asyncio.isfuture(smc_msg_waiter):
        smc_msg = await smc_msg_waiter
        # We need to accept premature messages in good faith and will fill up the incomplete state once we accept the report
        if smc_msg['smc_id'] not in smc.transaction_manager.keys():
            redaction_state = smc.DistributedRedactionState(
                block=None,
                tx_index=None,
                claim=None,
                chf_pub=config.global_config()['chf_pub'],
                chf_prv_share=config.global_config()['chf_prv_share'],
                smc_id=smc_msg['smc_id'],
                number_peers=config.global_config()['number_peers'],
                my_id=config.global_config()['peer_id'],
                msg_endpoint='/smc'
            )
            smc.transaction_manager[smc_msg['smc_id']] = redaction_state
        else:
            redaction_state = smc.transaction_manager[smc_msg['smc_id']]
        await redaction_state.msg_received(smc_msg)
    return web.json_response({'success': True})


@routes.post('/report')
async def report_handler(request):
    global tx_index

    def check_report(msg):
        if 'transaction_id' not in msg.keys():
            return False
        if msg['transaction_id'] not in tx_index.keys():
            return False
        if 'claim' not in msg.keys():
            return False
        return True

    async def kickoff_redaction(msg_future):
        try:
            report = await msg_future
            log.debug(f'Accepted report: {report}')

            eval.get_eval().stop('accept_report')

            eval.get_eval().start('redaction')

            txid = report['transaction_id']
            block_id, tx_ind = tx_index[txid]
            await execute_distributed_redaction(
                block_id=block_id,
                txid=txid,
                tx_ind=tx_ind,
                claim=report['claim'],
                smc_id=next(report_msg_id_gen)
            )

            eval.get_eval().stop('redaction')

            eval.get_eval().stop('everything')

            eval.get_eval().writerun()

            response = {'success': True, 'report': report}
        except asyncio.CancelledError:
            response = {'success': False, 'error': 'report_declined'}

        return response

    msg = await request.json()
    if check_report(msg):
        block_id, _ = tx_index[msg['transaction_id']]
        block_ind = block_index[block_id]
        claim = msg['claim']

        eval.get_eval().setrun(block_ind, claim)

        eval.get_eval().start('everything')

        eval.get_eval().start('accept_report')

        # Transform user report into Bracha message
        bracha_msg = msg_handler.prepare_msg(
            msg_id=next(report_msg_id_gen),
            sender=None,  # It was sent by some user, not a jury member
            data=msg,
            msg_typ='bracha_broadcast'
        )
        bracha_msg['bracha_typ'] = 'send'
        bracha_msg = msg_handler.sign_msg(bracha_msg)
        # Await acceptance of the report
        msg_future = await msg_handler.accept_message(bracha_msg, from_endpoint='/report')
        if asyncio.isfuture(msg_future):
            response = await kickoff_redaction(msg_future)
    else:
        try:
            msg = msg_handler.check_message(msg)
        except RuntimeError:
            response = {'success': False, 'error': 'validation_error'}
            return web.json_response(response)

        report_future = await msg_handler.accept_message(msg, from_endpoint='/report')
        if asyncio.isfuture(report_future):
            response = await kickoff_redaction(msg_future)
        response = {'success': True}

    return web.json_response(response)


async def main():
    app = web.Application(client_max_size=SERVER_MAX_CLIENT_REQUEST_SIZE)
    app.add_routes(routes)

    app.cleanup_ctx.append(persistent_session)
    msg_handler.set_app(app)

    runner = web.AppRunner(
        app=app,
        logger=log_aiohttp,
        access_log=log_access,
        keepalive_timeout=SERVER_KEEPALIVE_TIMEOUT
    )
    await runner.setup()
    site = web.TCPSite(
        runner=runner,
        host=config.global_config()['host'],
        port=config.global_config()['port'],
        shutdown_timeout=SERVER_SHUTDOWN_TIMEOUT
    )
    log.info(f'Starting server at {get_endpoint()}')
    await site.start()

    while True:
        await asyncio.sleep(3600)

    await runner.cleanup()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('peer_id', type=int, help='ID of the peer to be started')
    arg_parser.add_argument('number_peers', type=int, help='Number of peers expected to be booted (must have form n=3x+1)')
    arg_parser.add_argument('--conf-file', '-f', type=str, default=config.DEFAULT_CONF_FILE, help=f'Configuration to load (default: {config.DEFAULT_CONF_FILE})')
    arg_parser.add_argument('--blockchain-folder', '-b', type=str, default=DEFAULT_BLOCKCHAIN_FOLDER, help=f'Blockchain data to load (default: {DEFAULT_BLOCKCHAIN_FOLDER})')
    arg_parser.add_argument('--eval-folder', '-e', type=str, default=eval.DEFAULT_EVAL_FOLDER, help=f'Folder to store eval to (default: {eval.DEFAULT_EVAL_FOLDER})')
    arg_parser.add_argument('--debug', '-D', action='store_true', help='Enable debug mode')

    args = arg_parser.parse_args()

    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

    config.set_global_config(
        config_file=args.conf_file,
        number_peers=args.number_peers,
        peer_id=args.peer_id
    )
    log.debug(f'Loaded configuration:\n{config.global_config()}')

    msg_handler.msg_id_gen = msg_handler.MessageIdIterator(config.global_config()['peer_id'])
    report_msg_id_gen = msg_handler.MessageIdIterator(0xFF, start=0)  # Reserve largest peer ID for user requests

    log.debug('Loading blockchain data')
    blocks, block_index, tx_index = load_blockchain(pathlib.Path(args.blockchain_folder))

    eval.initialize_eval(
        peer_id=config.global_config()['peer_id'],
        eval_folder=args.eval_folder
    )

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
