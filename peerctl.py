#!/usr/bin/env python3
""" This script controls a whole network of RedactChain peers. """

import logging
import argparse
import pathlib
import subprocess
import signal
import os
import sys
import requests

import config
from blockchain import DEFAULT_BLOCKCHAIN_FOLDER
from eval import DEFAULT_EVAL_FOLDER

path_base = pathlib.Path(__file__).parent
path_log = path_base / 'logs'
path_pids = path_base / 'pids'

log = logging.getLogger('peerctl')


def start_peer(peer_id: int, number_peers: int, conf_file=config.DEFAULT_CONF_FILE, blockchain_folder=DEFAULT_BLOCKCHAIN_FOLDER, eval_folder=DEFAULT_EVAL_FOLDER, debug=False):
    path_pid = path_pids / f'{peer_id:03}.pid'
    if path_pid.exists():
        log.warning(f'First trying to stop Peer #{peer_id} due to existing PID file.')
        stop_peer(peer_id)
        raise RuntimeError(f'PID file for {peer_id} does not exist.')
    executable = path_base / 'peer.py'
    cmd = ['python3', str(executable)]
    if debug:
        cmd.append('--debug')
    cmd += [
        '--conf-file',
        conf_file,
        '--blockchain-folder',
        blockchain_folder,
        '--eval-folder',
        eval_folder,
        str(peer_id),
        str(number_peers)
    ]
    if not path_log.exists():
        path_log.mkdir(parents=True)
    stdout = path_log / f'{peer_id:03}.out'
    stderr = path_log / f'{peer_id:03}.err'

    with open(stdout, 'w') as f_stdout, open(stderr, 'w') as f_stderr:
        proc = subprocess.Popen(cmd, stdout=f_stdout, stderr=f_stderr, start_new_session=True)

    if not path_pids.exists():
        path_pids.mkdir(parents=True)
    with open(path_pid, 'w') as f_pid:
        f_pid.write(str(proc.pid))
    log.debug(f'Started peer {peer_id} with PID {proc.pid}.')


def stop_peer(peer_id):
    path_pid = path_pids / f'{peer_id:03}.pid'
    if not path_pid.exists():
        raise RuntimeError(f'PID file for {peer_id} does not exist.')

    with open(path_pid, 'r') as f_pid:
        pid = int(f_pid.read())

    try:
        os.kill(pid, signal.SIGKILL)
        log.debug(f'Killed peer {peer_id} with PID {pid} using SIGKILL.')
    except ProcessLookupError:
        log.warning(f'Could not stop Peer #{peer_id} using PID {pid}.')
    finally:
        path_pid.unlink()


def peer_online(peer_id, conf_file=config.DEFAULT_CONF_FILE):
    conf = config.RedactChainConfiguration(config_file=conf_file)
    endpoint = conf.get_endpoint(peer_id)
    if endpoint is None:
        return False

    try:
        response = requests.get(endpoint)
    except requests.exceptions.RequestException:
        return False
    if response.status_code != 200:
        return False
    data = response.json()
    if 'online' not in data.keys() or not data['online']:
        return False

    return True


def all_online(number_peers: int, conf_file=config.DEFAULT_CONF_FILE):
    offline = list()
    for peer_id in range(number_peers):
        if not peer_online(peer_id, conf_file):
            offline.append(peer_id)

    if len(offline) == 0:
        log.info('All peers are online.')
        return True

    log.error(f'The following peers are offline: {offline}')
    return False


def start_all(number_peers: int, conf_file=config.DEFAULT_CONF_FILE, blockchain_folder=DEFAULT_BLOCKCHAIN_FOLDER, eval_folder=DEFAULT_EVAL_FOLDER, debug=False):
    if divmod(number_peers, 3)[1] != 1:
        log.error(f'Invalid network size {number_peers} is not of the form n = 3x + 1.')
        sys.exit(1)

    for peer_id in range(number_peers):
        start_peer(
            conf_file=conf_file,
            blockchain_folder=blockchain_folder,
            eval_folder=eval_folder,
            peer_id=peer_id,
            number_peers=number_peers,
            debug=debug
        )


def stop_all():
    peer_ids = sorted([int(path_pid.stem, 10) for path_pid in path_pids.glob('*.pid')])
    log.debug(f'Peers IDs with PID files: {", ".join([str(peer_id) for peer_id in peer_ids])}.')

    for peer_id in peer_ids:
        stop_peer(peer_id)


def cmd_start_peer(args):
    conf_file = args.conf_file
    peer_id = args.peer_id
    number_peers = args.number_peers
    blockchain_folder = args.blockchain_folder
    eval_folder = args.eval_folder

    if divmod(number_peers, 3)[1] != 1:
        log.error(f'Invalid network size {number_peers} is not of the form n = 3x + 1.')
        sys.exit

    if not 0 <= peer_id < number_peers:
        log.error(f'Invalid peer ID {peer_id} for network of size {number_peers}.')
        sys.exit(1)

    start_peer(
        conf_file=conf_file,
        blockchain_folder=blockchain_folder,
        eval_folder=eval_folder,
        peer_id=peer_id,
        number_peers=number_peers,
        debug=args.debug
    )


def cmd_start_all(args):
    conf_file = args.conf_file
    number_peers = args.number_peers
    blockchain_folder = args.blockchain_folder
    eval_folder = args.eval_folder
    debug = args.debug

    start_all(number_peers, conf_file, blockchain_folder, eval_folder, debug)


def cmd_peer_online(args):
    conf_file = args.conf_file
    peer_id = args.peer_id

    res = peer_online(peer_id, conf_file)
    if res:
        log.info(f'Peer #{peer_id} is online.')
    else:
        log.error(f'Peer #{peer_id} is NOT online.')
    return res


def cmd_all_online(args):
    conf_file = args.conf_file
    number_peers = args.number_peers

    if divmod(number_peers, 3)[1] != 1:
        log.error(f'Invalid network size {number_peers} is not of the form n = 3x + 1.')
        sys.exit(1)

    return all_online(number_peers, conf_file)


def cmd_stop_all(args):
    stop_all()


def cmd_stop_peer(args):
    peer_id = args.peer_id

    stop_peer(peer_id)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.set_defaults(func=None)

    arg_parser.add_argument('--conf-file', '-f', type=str, default=config.DEFAULT_CONF_FILE, help=f'Configuration to load (default: {config.DEFAULT_CONF_FILE})')
    arg_parser.add_argument('--blockchain-folder', '-b', type=str, default=DEFAULT_BLOCKCHAIN_FOLDER, help=f'Blockchain folder to load (default: {DEFAULT_BLOCKCHAIN_FOLDER})')
    arg_parser.add_argument('--eval-folder', '-e', type=str, default=DEFAULT_EVAL_FOLDER, help=f'Eval folder to write to (default: {DEFAULT_EVAL_FOLDER})')
    arg_parser.add_argument('--debug', '-D', action='store_true', help='Enable debug mode')

    cmd_parser = arg_parser.add_subparsers()

    cmd_start_peer_parser = cmd_parser.add_parser('start_peer')
    cmd_start_peer_parser.add_argument(
        'peer_id',
        type=int,
        help='ID of the peer to start'
    )
    cmd_start_peer_parser.add_argument(
        'number_peers',
        type=int,
        help='Number of peers to configure for'
    )
    cmd_start_peer_parser.set_defaults(func=cmd_start_peer)

    cmd_start_all_parser = cmd_parser.add_parser('start_all')
    cmd_start_all_parser.add_argument(
        'number_peers',
        type=int,
        help='Number of peers to configure for'
    )
    cmd_start_all_parser.set_defaults(func=cmd_start_all)

    cmd_peer_online_parser = cmd_parser.add_parser('peer_online')
    cmd_peer_online_parser.add_argument(
        'peer_id',
        type=int,
        help='ID of the peer to start'
    )
    cmd_peer_online_parser.set_defaults(func=cmd_peer_online)

    cmd_all_online_parser = cmd_parser.add_parser('all_online')
    cmd_all_online_parser.add_argument(
        'number_peers',
        type=int,
        help='Number of peers to configure for'
    )
    cmd_all_online_parser.set_defaults(func=cmd_all_online)

    cmd_stop_peer_parser = cmd_parser.add_parser('stop_peer')
    cmd_stop_peer_parser.add_argument(
        'peer_id',
        type=int,
        help='ID of the peer to stop'
    )
    cmd_stop_peer_parser.set_defaults(func=cmd_stop_peer)

    cmd_stop_all_parser = cmd_parser.add_parser('stop_all')
    cmd_stop_all_parser.set_defaults(func=cmd_stop_all)

    args = arg_parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.func is None:
        log.error('No (known) command given.')
        arg_parser.print_help()
        sys.exit(1)

    args.func(args)
