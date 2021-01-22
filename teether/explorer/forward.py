import logging
from queue import PriorityQueue

from teether.util.utils import is_subseq, is_substr


class ForwardExplorerState(object):
    def __init__(self, bb, path=None, branches=None, slices=None):
        self.bb = bb
        self.path = list(path) + [bb.start] or []
        self.seen = set(self.path)
        self.branches = branches or 0
        self.slices = []
        self.finished = set()
        for slice in slices:
            last_pc = None
            while slice and slice[0].bb.start == self.bb.start:
                if last_pc is None or slice[0].addr > last_pc:
                    last_pc = slice[0].addr
                    if len(slice) == 1:
                        self.finished.add(last_pc)
                    slice = slice[1:]
                else:
                    break
            self.slices.append(slice)

    def next_states(self):
        possible_succs = []
        for succ in self.bb.succ:
            pths = succ.pred_paths[self.bb]
            for pth in pths:
                if not set(pth).issubset(self.seen):
                    continue
                if not is_subseq(pth, self.path):
                    continue
                break
            else:
                continue
            possible_succs.append(succ)
        next_states = []
        branches = self.branches
        if len(possible_succs) > 1:
            branches += 1
        for succ in possible_succs:
            next_slices = tuple(
                s for s in self.slices if set(i.bb.start for i in s).issubset(succ.descendants | {succ.start}))
            if next_slices:
                next_states.append(ForwardExplorerState(succ, self.path, branches, next_slices))
        return next_states

    def __lt__(self, other):
        return self.weight < other.weight

class ForwardExplorer(object):
    def __init__(self, cfg, avoid=frozenset()):
        self.dist_map = dict()
        self.cfg = cfg
        self.blacklist = set()

    def add_to_blacklist(self, path):
        self.blacklist.add(tuple(path))

    def weight(self, state):
        if state.finished:
            return state.branches
        else:
            return state.branches + min(self.dist_map[s[0].bb.start][state.bb] for s in state.slices)

    def find(self, slices, looplimit=3, avoid=frozenset(), prefix=None):
        avoid = frozenset(avoid)
        slices = tuple(tuple(i for i in s if i.bb) for s in slices)
        if not slices:
            return
        # distance from a BB to instruction
        for slice in slices:
            for i in slice:
                if i.bb.start not in self.dist_map:
                    self.dist_map[i.bb.start] = self.cfg.distance_map(i)

        if prefix is None:
            state = ForwardExplorerState(self.cfg.root, [], 0, slices)
        else:
            state = ForwardExplorerState(self.cfg._ins_at[prefix].bb, prefix, 0, slices)
        state.weight = self.weight(state)

        todo = PriorityQueue()
        todo.put(state)

        while not todo.empty():
            state = todo.get()
            if any(is_substr(pth, state.path) for pth in self.blacklist):
                logging.info("BLACKLIST hit for %s" % (', '.join('%x' % i for i in state.path)))
                continue
            if set(i.name for i in state.bb.ins) & avoid:
                continue
            if state.finished:
                for last_pc in state.finished:
                    yield state.path + [last_pc]
                state.finished = set()
                state.slices = tuple(s for s in state.slices if s)
                if not state.slices:
                    continue
            if state.path.count(state.bb.start) > looplimit:
                continue
            for next_state in state.next_states():
                next_state.weight = self.weight(next_state)
                todo.put(next_state)
