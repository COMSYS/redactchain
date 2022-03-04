from time import perf_counter_ns
import pathlib
import json
import logging


_eval = None


DEFAULT_EVAL_FOLDER = 'last_eval'


log = logging.getLogger('eval')


class Eval(object):

    def __init__(self, peer_id: int, path: pathlib.Path):
        if path.exists():
            raise RuntimeError('Eval file already exists!!!')
        self._path = path
        self._path.touch()

        self._peer_id = peer_id
        self._block_ind = None
        self._claim = None

    def _initialize_measurements(self):
        if self._block_ind is None or self._claim is None:
            raise RuntimeError('Invalid eval run.')
        self._measurements = {'block_index': self._block_ind, 'claim': self._claim, 'measurements': dict()}

    def start(self, name):
        self._measurements['measurements'][name] = dict()
        self._measurements['measurements'][name]['start'] = perf_counter_ns()

    def stop(self, name):
        self._measurements['measurements'][name]['end'] = perf_counter_ns()

    def setrun(self, block_ind, claim):
        self._block_ind = block_ind
        self._claim = claim
        self._initialize_measurements()

    def writerun(self):
        with open(self._path, 'a') as f_out:
            f_out.write(json.dumps(self._measurements, sort_keys=False))
            f_out.write('\n')


def initialize_eval(peer_id: int, eval_folder: str):
    global _eval
    eval_path = pathlib.Path(eval_folder)
    if not eval_path.exists():
        eval_path.mkdir(parents=True)
    _eval = Eval(peer_id, eval_path / f'{peer_id:03}.json')


def get_eval():
    global _eval
    return _eval
