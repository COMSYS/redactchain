#!/usr/bin/env python3

import sys
import argparse
import logging
import pathlib

import base64
import yaml
from progressbar import progressbar

from Cryptodome.Random import random
from Cryptodome.PublicKey import RSA
from gmpy2 import mpz, powmod

from config import DEFAULT_CONF_FILE, RedactChainConfiguration
from parameters import bit_length, p, q, g
from smc import FE, Share, shamir_share, shamir_recombine


DEFAULT_START_PORT = 12000


log = logging.getLogger('configgen')


def generate_credentials():
    key_whole = RSA.generate(bit_length)
    key_pub = key_whole.publickey()
    key_whole_serialized = base64.b64encode(key_whole.export_key(format='DER')).decode('utf-8')
    key_pub_serialized = base64.b64encode(key_pub.export_key(format='DER')).decode('utf-8')
    return key_whole_serialized, key_pub_serialized


def generate_config_file(target_file: pathlib.Path, num_peers=4, port_start=DEFAULT_START_PORT):
    config = dict()
    config['peers'] = dict()
    private_key_chf = mpz(random.randint(2, int(q - 1)))
    public_key_chf = powmod(g, private_key_chf, p)
    config['chf'] = {
        'priv': int(private_key_chf),
        'pub': int(public_key_chf),
    }
    log.info('Creating peer credentials.')
    for peer_id in progressbar(range(num_peers), redirect_stdout=True):
        private_key, public_key = generate_credentials()
        peer = {
            'host': 'localhost',
            'port': port_start + peer_id,
            'priv': private_key,
            'pub': public_key,
        }
        config['peers'][peer_id] = peer

    # Create list of lists containing the shamir shares of each peer for growing network sizes
    log.info('Creating Shamir shares of CHF private key for different network sizes.')
    config['shares'] = dict()
    for network_size in progressbar(range(4, num_peers + 1, 3), redirect_stdout=True):
        config['shares'][network_size] = dict()
        shares = shamir_share(FE(private_key_chf), network_size)
        for share in shares:
            config['shares'][network_size][share.player] = int(share.share)
        # Test
        shares = list()
        for player, share in config['shares'][network_size].items():
            shares.append(Share(FE(share), player))
        assert int(shamir_recombine(shares, robust=False)) == private_key_chf

    yaml_config = yaml.dump(config, sort_keys=False)
    with open(target_file, 'w') as f_out:
        f_out.write(yaml_config)


def cmd_generate(args):
    conf_file = pathlib.Path(args.conf_file)
    if conf_file.exists():
        log.error(f'File {conf_file} already exists. Not writing new config.')
        sys.exit(1)

    num_peers = args.number_peers
    if divmod(num_peers, 3)[1] != 1:
        log.error(f'Desired number of peers {num_peers} is not of form n = 3x + 1. Not writing new config.')
        sys.exit(1)

    port_start = args.start_port
    if port_start < 10000:  # Safe boundary for starting port
        log.error(f'Start port {port_start} is below 10000. Not writing new config.')
        sys.exit(1)

    generate_config_file(
        target_file=conf_file,
        num_peers=num_peers,
        port_start=port_start
    )


def cmd_read(args):
    conf_file = pathlib.Path(args.conf_file)
    if not conf_file.exists():
        log.error(f'File {conf_file} does not exist.')
        sys.exit(1)

    conf = RedactChainConfiguration(config_file=conf_file)
    print(str(conf))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    arg_parser = argparse.ArgumentParser()
    arg_parser.set_defaults(func=None)
    cmd_parser = arg_parser.add_subparsers()

    cmd_generate_parser = cmd_parser.add_parser('generate')
    cmd_generate_parser.add_argument(
        'number_peers',
        type=int,
        help='Number of peers to configure for'
    )
    cmd_generate_parser.add_argument(
        '--start-port', '-P',
        type=int,
        default=DEFAULT_START_PORT,
        help=f'First port to assign to Peer #0 (is incremented for each subsequent peer, default: {DEFAULT_START_PORT})'
    )
    cmd_generate_parser.add_argument(
        '--conf-file', '-f',
        type=str,
        default=DEFAULT_CONF_FILE,
        help=f'File to write config to (default: {DEFAULT_CONF_FILE})'
    )
    cmd_generate_parser.set_defaults(func=cmd_generate)

    cmd_read_parser = cmd_parser.add_parser('read')
    cmd_read_parser.add_argument(
        '--conf-file', '-f',
        type=str,
        default=DEFAULT_CONF_FILE,
        help=f'File to write config to (default: {DEFAULT_CONF_FILE})'
    )
    cmd_read_parser.set_defaults(func=cmd_read)

    args = arg_parser.parse_args()

    if args.func is None:
        log.error('No (known) command given.')
        arg_parser.print_help()
        sys.exit(1)

    args.func(args)
