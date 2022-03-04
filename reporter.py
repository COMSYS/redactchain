#!/usr/bin/env python3
import argparse
import asyncio

import config
import msg_handler


async def send_report(report: dict):
    _, responses = await msg_handler.broadcast_prepared_msg(report, '/report')

    count, _, overall_response = msg_handler.get_most_frequent_msg(responses)
    number_peers = config.global_config()['number_peers']

    print(f'Number peers: {number_peers}')
    print(f'Count of aff: {count}\n')

    error = None
    success = True
    if 'success' not in overall_response.keys():  # Should not happen
        error = 'Success state missing from received accepted response.'
        success = False
    if not overall_response['success']:
        error = 'Response did not yield success.'
        success = False
    if msg_handler.get_message_hash(overall_response['report']) != msg_handler.get_message_hash(report):
        error = 'Acknowledged report differs from submitted report.'
        success = False

    if (3 * count) <= (2 * number_peers):
        error = 'Too few peers sent the same result.'
        success = False

    if success:
        print('Report was accepted! :)')
        print(f'Report:\n{report}')
    else:
        print('Report was declined! :(')
        print(f'Error:\n{error}')


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('number_peers', type=int, help='Number of peers in jury (must have form n=3x+1)')
    arg_parser.add_argument('transaction_id', type=str, help='ID of the transaction to be reported')
    arg_parser.add_argument('--claim', type=str, default='X' * 200, help='Reason for the redaction')
    arg_parser.add_argument('--conf-file', '-f', type=str, default=config.DEFAULT_CONF_FILE, help=f'Configuration to load (default: {config.DEFAULT_CONF_FILE})')
    args = arg_parser.parse_args()

    config.set_global_config(
        config_file=args.conf_file,
        number_peers=args.number_peers,
        peer_id=None
    )

    report = {
        'transaction_id': args.transaction_id,
        'claim': args.claim,
    }

    asyncio.run(send_report(report))
