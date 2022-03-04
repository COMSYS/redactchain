import pathlib
import base64
import yaml

from Cryptodome.PublicKey import RSA


DEFAULT_CONF_FILE = 'config.yaml'


_global_config = None


class RedactChainConfiguration(object):
    __slots__ = ['peers', 'number_peers', 'peer_id', 'host', 'port', 'endpoint', 'sign_prv', 'chf_pub', 'chf_prv', 'chf_prv_share']

    def __init__(self, config_file=None, number_peers=None, network_config=None, peer_id=None):
        if network_config is None and config_file is None:
            raise RuntimeError('Either give preread config or config file for reading.')
        if network_config is not None and config_file is not None:
            raise RuntimeError('Only give preread config or config file for reading, not both.')

        if network_config is not None:
            final_network_config = network_config
        elif config_file is not None:
            final_network_config = read_config_file(pathlib.Path(config_file), number_peers=number_peers)
        else:
            raise RuntimeError(f'Unexpected mode for loading {self.__class__.__name__}')

        self.peers = final_network_config['peers']
        self.number_peers = len(self.peers)
        self.peer_id = peer_id
        self.host = self.peers[self.peer_id]['host'] if self.peer_id is not None else None
        self.port = self.peers[self.peer_id]['port'] if self.peer_id is not None else None
        self.endpoint = f'http://{self.host}:{self.port}' if self.peer_id is not None else None

        # Load own RSA private key, then import all peers' public keys and destroy the private keys
        self.sign_prv = RSA.import_key(base64.b64decode(self.peers[self.peer_id]['priv'].encode('utf-8'))) if self.peer_id is not None else None
        for peer in self.peers.keys():
            self.peers[peer]['pub'] = RSA.import_key(base64.b64decode(self.peers[peer]['pub'].encode('utf-8')))
            del self.peers[peer]['priv']

        self.chf_pub = final_network_config['chf']['pub']
        self.chf_prv = final_network_config['chf']['priv']  # Only for testing purposes!
        self.chf_prv_share = final_network_config['shares'][self.number_peers][self.peer_id] if self.peer_id is not None else None

    def get_endpoint(self, peer_id=None):
        if peer_id is None:
            return self.endpoint
        if peer_id not in self.peers.keys():
            return None
        peer = self.peers[peer_id]
        return f'http://{peer["host"]}:{peer["port"]}'

    def __getitem__(self, item):
        if item not in self.__slots__:
            raise RuntimeError(f'Invalid attribute access ({item}) from {self.__class__.__name__}')
        return getattr(self, item)

    def __str__(self):
        res_lines = list()
        res_lines.append(f'My peer ID: {self.peer_id}')
        res_lines.append(f'My endpoint: {self.endpoint}')
        res_lines.append(f'Number of available peers: {len(self.peers)}')
        res_lines.append(f'Public CHF key: {self.chf_pub}')
        res_lines.append(f'Share of private CHF key: {self.chf_prv_share}')
        res_lines.append('Network configuration:')
        for peer_id, peer in self.peers.items():
            res_lines.append(f'    Peer #{peer_id}: {peer["host"]}:{peer["port"]}')
        return '\n'.join(res_lines)


def set_global_config(config_file=None, number_peers=None, network_config=None, peer_id=None):
    global _global_config
    _global_config = RedactChainConfiguration(config_file, number_peers, network_config, peer_id)


def global_config():
    global _global_config
    return _global_config


def read_config_file(conf_file: pathlib.Path, number_peers=None):
    if not conf_file.exists():
        raise RuntimeError(f'Config file {conf_file} does not exist.')
    with open(conf_file, 'r') as f_in:
        network_config = yaml.load(f_in.read(), Loader=yaml.SafeLoader)
    if number_peers is not None:
        for peer_id in list(network_config['peers'].keys()):  # Convert to list to avoid "dictionary changed size during iteration" error
            if peer_id > number_peers - 1:
                del network_config['peers'][peer_id]
    return network_config
