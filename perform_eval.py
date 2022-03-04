#!/usr/bin/env python3

import asyncio
import pathlib
import logging
import json
from datetime import datetime
import shutil


import aiohttp


import config
import peerctl


blockchain_folder = 'blockchain_eval'
path_blockchain = pathlib.Path(blockchain_folder)

eval_folder = 'eval_results'
path_eval = pathlib.Path(eval_folder) / f'{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}_eval'

conf_file = config.DEFAULT_CONF_FILE
path_config = pathlib.Path(conf_file)

# Evaluation parameters
number_txs = 30  # Number of blocks to redact the large and opreturn transaction from (first ones are chosen)
jury_sizes = [4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52, 55, 58][::-1]


for j in jury_sizes:
    if divmod(j, 3)[1] != 1:
        raise RuntimeError(f'Invalid jury size {j}.')


conf = None
txids_large = None
txids_opreturn = None


log = logging.getLogger('perform_eval')
log.setLevel(logging.DEBUG)


async def get_online_status(session, peer_id: int):
    endpoint = f'{conf.get_endpoint(peer_id)}/'
    try:
        async with session.get(endpoint) as response:
            response = await response.json()
            return response
    except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientOSError, aiohttp.client_exceptions.ClientConnectionError):
        return None


async def send_report(session, peer_id: int, report: dict):
    endpoint = f'{conf.get_endpoint(peer_id)}/report'
    try:
        async with session.post(endpoint, json=report) as response:
            response = await response.json()
            return response
    except (aiohttp.client_exceptions.ClientConnectorError, aiohttp.client_exceptions.ClientOSError, aiohttp.client_exceptions.ClientConnectionError):
        return None


async def eval_scenario(jury_size: int):
    # Start jury, each peer individually with dedicated eval folder! path_eval/jury_size
    path_eval_scenario = path_eval / f'{jury_size:03}_peers_{number_txs:04}_txsperblock'
    path_eval_scenario.mkdir()

    shutil.rmtree('logs/')
    pathlib.Path('logs/').mkdir()

    log.info(f'Starting new scenario with jury_size = {jury_size}.')

    log.info('Stopping all peers.')
    peerctl.stop_all()

    log.info('Starting required peers.')
    peerctl.start_all(
        number_peers=jury_size,
        conf_file=conf_file,
        blockchain_folder=blockchain_folder,
        eval_folder=str(path_eval_scenario),
        debug=False
    )

    connector = aiohttp.TCPConnector(limit=200, keepalive_timeout=72000)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=72000)) as session:

        # Ensure that jury is online completely
        log.info('Waiting for all peers to get online.')
        while True:
            responses = list()
            log.info('Going to sleep for 10 seconds, then checking online status.')
            await asyncio.sleep(10)
            for peer_id in range(jury_size):
                responses.append(get_online_status(session, peer_id))
            results = await asyncio.gather(*responses)
            number_online_peers = len([r for r in results if r is not None])
            if number_online_peers == jury_size:
                log.info('Everyone is online. Continuing.')
                break
            else:
                log.info(f'{number_online_peers}/{jury_size} peers online.')

        # Create and broadcast report
        for i in range(number_txs):
            log.info(f'Starting to redact block {i + 1}/{number_txs}.')
            for claim in ['obfuscate', 'opreturn']:
                txid = txids_large[i] if claim == 'obfuscate' else txids_opreturn[i]
                report = {
                    'transaction_id': txid,
                    'claim': claim
                }
                responses = list()
                for peer_id in range(jury_size):
                    responses.append(send_report(session, peer_id, report))
                results = await asyncio.gather(*responses)

    log.info('Stopping all peers.')
    peerctl.stop_all()
    await asyncio.sleep(10)

    log.info('Copying log files.')
    for peer_id in range(jury_size):
        shutil.copy(f'logs/{peer_id:03}.err', str(path_eval_scenario / f'{peer_id:03}.log'))


if __name__ == '__main__':
    logging.basicConfig(
        filename='eval.log',
        filemode='w',
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if not path_blockchain.exists():
        raise RuntimeError(f'Blockchain folder {path_blockchain} does not exist!')
    log.info(f'Using blockchain {path_blockchain} for measurements.')

    if not path_config.exists():
        raise RuntimeError(f'Config file {path_config} does not exist!')
    log.info(f'Reading config file {path_config}')

    if path_eval.exists():
        raise RuntimeError(f'Eval folder {path_eval} already exists!')
    log.info(f'Storing results to {path_eval}.')
    path_eval.mkdir(parents=True)

    # Load config for peers
    conf = config.RedactChainConfiguration(
        config_file=path_config,
        number_peers=100
    )

    # Load TXIDs to be redacted
    path_redaction_txs = path_blockchain / 'redaction_txs.json'
    if not path_redaction_txs.exists():
        raise RuntimeError('Missing list of transactions I have to redact')
    with open(path_redaction_txs, 'r') as f_in:
        redaction_txs = json.load(f_in)
        txids_large = redaction_txs['txs_large'][:number_txs]
        txids_opreturn = redaction_txs['txs_opreturn'][:number_txs]
        log.info(f'Going to redact the relevant transactions from the first {number_txs} blocks for each scenario.')

    # Perform actual redactions
    log.info(f'Jury sizes to consider: {jury_sizes}')
    loop = asyncio.get_event_loop()
    for jury_size in jury_sizes:
        loop.run_until_complete(eval_scenario(jury_size))
