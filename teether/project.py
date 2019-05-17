import logging
from collections import defaultdict

from teether.cfg.cfg import CFG
from teether.cfg.disassembly import generate_BBs
from teether.cfg.opcodes import external_data
from teether.evm.evm import run, run_symbolic
from teether.evm.exceptions import IntractablePath, ExternalData
from teether.explorer.forward import ForwardExplorer
from teether.slicing import interesting_slices, slice_to_program
from teether.util.z3_extra_util import concrete


def load(path):
    with open(path) as infile:
        return Project(bytes.fromhex(infile.read().strip()))


def load_json(path):
    import json
    with open(path) as infile:
        return Project.from_json(json.load(infile))


class Project(object):
    def __init__(self, code, cfg=None):
        self.code = code
        self._prg = None
        self._cfg = cfg
        self._writes = None

    @property
    def writes(self):
        if not self._writes:
            self._analyze_writes()
        return self._writes

    @property
    def symbolic_writes(self):
        return self.writes[None]

    @property
    def cfg(self):
        if not self._cfg:
            self._cfg = CFG(generate_BBs(self.code))
        return self._cfg

    @property
    def prg(self):
        if not self._prg:
            self._prg = {ins.addr: ins for bb in self.cfg.bbs for ins in bb.ins}
        return self._prg

    def to_json(self):
        return {'code': self.code.hex(), 'cfg': self.cfg.to_json()}

    @staticmethod
    def from_json(json_dict):
        code = bytes.fromhex(json_dict['code'])
        cfg = CFG.from_json(json_dict['cfg'], code)
        return Project(code, cfg)

    def run(self, program):
        return run(program, code=self.code)

    def run_symbolic(self, path, inclusive=False):
        return run_symbolic(self.prg, path, self.code, inclusive=inclusive)

    def get_constraints(self, instructions, args=None, inclusive=False, find_sstore=False):
        # only check instructions that have a chance to reach root
        instructions = [ins for ins in instructions if 0 in ins.bb.ancestors | {ins.bb.start}]
        if not instructions:
            return
        imap = {ins.addr: ins for ins in instructions}

        exp = ForwardExplorer(self.cfg)
        if args:
            slices = [s + (ins,) for ins in instructions for s in interesting_slices(ins, args, reachable=True)]
        else:
            # Are we looking for a state-changing path?
            if find_sstore:
                sstores = self.cfg.filter_ins('SSTORE', reachable=True)
                slices = [(sstore, ins) for sstore in sstores for ins in instructions]
            else:
                slices = [(ins,) for ins in instructions]
        for path in exp.find(slices, avoid=external_data):
            logging.debug('Path %s', ' -> '.join('%x' % p for p in path))
            try:
                ins = imap[path[-1]]
                yield ins, path, self.run_symbolic(path, inclusive)
            except IntractablePath as e:
                bad_path = [i for i in e.trace if i in self.cfg._bb_at] + [e.remainingpath[0]]
                dd = self.cfg.data_dependence(self.cfg._ins_at[e.trace[-1]])
                if not any(i.name in ('MLOAD', 'SLOAD') for i in dd):
                    ddbbs = set(i.bb.start for i in dd)
                    bad_path_start = next((j for j, i in enumerate(bad_path) if i in ddbbs), 0)
                    bad_path = bad_path[bad_path_start:]
                logging.info("Bad path: %s" % (', '.join('%x' % i for i in bad_path)))
                exp.add_to_blacklist(bad_path)
                continue
            except ExternalData:
                continue
            except Exception as e:
                logging.exception('Failed path due to %s', e)
                continue

    def _analyze_writes(self):
        sstore_ins = self.filter_ins('SSTORE')
        self._writes = defaultdict(set)
        for store in sstore_ins:
            for bs in interesting_slices(store):
                bs.append(store)
                prg = slice_to_program(bs)
                path = sorted(prg.keys())
                try:
                    r = run_symbolic(prg, path, self.code, inclusive=True)
                except IntractablePath:
                    logging.exception('Intractable Path while analyzing writes')
                    continue
                addr = r.state.stack[-1]
                if concrete(addr):
                    self._writes[addr].add(store)
                else:
                    self._writes[None].add(store)
        self._writes = dict(self._writes)

    def get_writes_to(self, addr):
        concrete_writes = set()
        if concrete(addr) and addr in self.writes:
            concrete_writes = self.writes[addr]
        return concrete_writes, self.symbolic_writes
