import logging
from collections import deque

from teether.cfg.bb import BB


class CFG(object):
    def __init__(self, bbs, fix_xrefs=True, fix_only_easy_xrefs=False):
        self.bbs = sorted(bbs)
        self._bb_at = {bb.start: bb for bb in self.bbs}
        self._ins_at = {i.addr: i for bb in self.bbs for i in bb.ins}
        self.root = self._bb_at[0]
        self.valid_jump_targets = frozenset({bb.start for bb in self.bbs if bb.ins[0].name == 'JUMPDEST'})
        if fix_xrefs or fix_only_easy_xrefs:
            self._xrefs(fix_only_easy_xrefs)
        self._dominators = None
        self._dd = dict()

    @property
    def bb_addrs(self):
        return frozenset(self._bb_at.keys())

    def filter_ins(self, names, reachable=False):
        if isinstance(names, str):
            names = [names]
        if not reachable:
            return [ins for bb in self.bbs for ins in bb.ins if ins.name in names]
        else:
            return [ins for bb in self.bbs for ins in bb.ins if ins.name in names and 0 in bb.ancestors | {bb.start}]

    def _xrefs(self, fix_only_easy_xrefs=False):
        # logging.debug('Fixing Xrefs')
        self._easy_xrefs()
        # logging.debug('Easy Xrefs fixed, turning to hard ones now')
        if not fix_only_easy_xrefs:
            self._hard_xrefs()
            # logging.debug('Hard Xrefs also fixed, good to go')

    def _easy_xrefs(self):
        for pred in self.bbs:
            for succ_addr in pred.get_succ_addrs(self.valid_jump_targets):
                if succ_addr and succ_addr in self._bb_at:
                    succ = self._bb_at[succ_addr]
                    pred.add_succ(succ, {pred.start})

    def _hard_xrefs(self):
        new_link = True
        links = set()
        while new_link:
            new_link = False
            for pred in self.bbs:
                if not pred.jump_resolved:
                    succ_addrs, new_succ_addrs = pred.get_succ_addrs_full(self.valid_jump_targets)
                    for new_succ_path, succ_addr in new_succ_addrs:
                        if succ_addr not in self._bb_at:
                            logging.warning(
                                'WARNING, NO BB @ %x (possible successor of BB @ %x)' % (succ_addr, pred.start))
                            continue
                        succ = self._bb_at[succ_addr]
                        pred.add_succ(succ, new_succ_path)
                        if not (pred.start, succ.start) in links:
                            # logging.debug('found new link from %x to %x', pred.start, succ.start)
                            # with open('cfg-tmp%d.dot' % len(links), 'w') as outfile:
                            #    outfile.write(self.to_dot())
                            new_link = True
                            links.add((pred.start, succ.start))

    def data_dependence(self, ins):
        if not ins in self._dd:
            from teether.slicing import backward_slice
            self._dd[ins] = set(i for s in backward_slice(ins) for i in s if i.bb)
        return self._dd[ins]

    @property
    def dominators(self):
        if not self._dominators:
            self._compute_dominators()
        return self._dominators

    def _compute_dominators(self):
        import networkx
        g = networkx.DiGraph()
        for bb in self.bbs:
            for succ in bb.succ:
                g.add_edge(bb.start, succ.start)
        self._dominators = {self._bb_at[k]: self._bb_at[v] for k, v in networkx.immediate_dominators(g, 0).items()}

    def __str__(self):
        return '\n\n'.join(str(bb) for bb in self.bbs)

    def to_dot(self, minimal=False):
        s = 'digraph g {\n'
        s += '\tsplines=ortho;\n'
        s += '\tnode[fontname="courier"];\n'
        for bb in sorted(self.bbs):
            from_block = ''
            if self._dominators:
                from_block = 'Dominated by: %x<br align="left"/>' % self.dominators[bb].start
            from_block += 'From: ' + ', '.join('%x' % pred.start for pred in sorted(bb.pred))
            if bb.estimate_constraints is not None:
                from_block += '<br align="left"/>Min constraints from root: %d' % bb.estimate_constraints
            if bb.estimate_back_branches is not None:
                from_block += '<br align="left"/>Min back branches to root: %d' % bb.estimate_back_branches
            to_block = 'To: ' + ', '.join('%x' % succ.start for succ in sorted(bb.succ))
            ins_block = '<br align="left"/>'.join(
                '%4x: %02x %s %s' % (ins.addr, ins.op, ins.name, ins.arg.hex() if ins.arg else '') for ins in bb.ins)
            # ancestors = 'Ancestors: %s'%(', '.join('%x'%addr for addr in sorted(a for a in bb.ancestors)))
            # descendants = 'Descendants: %s' % (', '.join('%x' % addr for addr in sorted(a for a in bb.descendants)))
            # s += '\t%d [shape=box,label=<<b>%x</b>:<br align="left"/>%s<br align="left"/>%s<br align="left"/>%s<br align="left"/>>];\n' % (
            #    bb.start, bb.start, ins_block, ancestors, descendants)
            if not minimal:
                s += '\t%d [shape=box,label=<%s<br align="left"/><b>%x</b>:<br align="left"/>%s<br align="left"/>%s<br align="left"/>>];\n' % (
                    bb.start, from_block, bb.start, ins_block, to_block)
            else:
                s += '\t%d [shape=box,label=<%s<br align="left"/>>];\n' % (
                    bb.start, ins_block)
        s += '\n'
        for bb in sorted(self.bbs):
            for succ in sorted(bb.succ):
                pths = succ.pred_paths[bb]
                if not minimal:
                    s += '\t%d -> %d [xlabel="%s"];\n' % (
                        bb.start, succ.start, '|'.join(' -> '.join('%x' % a for a in p) for p in pths))
                else:
                    s += '\t%d -> %d;\n' % (bb.start, succ.start)
        if self._dd:
            inter_bb = {}
            for k, v in self._dd.items():
                jbb = k.bb.start
                vbbs = {i.bb.start for i in v if i.bb.start != k.bb.start}
                if vbbs:
                    inter_bb[jbb] = vbbs
            l = len(inter_bb)
            for i, (k, v) in enumerate(inter_bb.items()):
                for j in v:
                    s += '\t%d -> %d[color="%.3f 1.0 1.0", weight=10];\n' % (j, k, (1.0 * i) / l)
                s += '\n'
        s += '}'
        return s

    def trim(self):
        keep = set(self.root.descendants)
        self.bbs = [bb for bb in self.bbs if bb.start in keep]
        delete = set(self._bb_at.keys()) - keep
        for addr in delete:
            del self._bb_at[addr]

    def to_json(self):
        return {'bbs': [{'start': bb.start,
                         'succs': [{'start': succ.start, 'paths': list(succ.pred_paths[bb])} for succ in
                                   sorted(bb.succ)]} for bb in sorted(self.bbs)]}

    @staticmethod
    def from_json(json_dict, code):
        from .disassembly import disass
        bbs = list()
        for bb_dict in json_dict['bbs']:
            bbs.append(BB(list(disass(code, bb_dict['start']))))
        cfg = CFG(bbs, fix_xrefs=False)
        for bb_dict in json_dict['bbs']:
            bb = cfg._bb_at[bb_dict['start']]
            for succ_dict in bb_dict['succs']:
                succ = cfg._bb_at[succ_dict['start']]
                for path in succ_dict['paths']:
                    bb.add_succ(succ, path)
        return cfg

    @staticmethod
    def distance_map(ins):
        dm = dict()
        todo = deque()
        todo.append((ins.bb, 0))
        while todo:
            bb, d = todo.pop()
            if not bb in dm or dm[bb] > d:
                dm[bb] = d
                for p in bb.pred:
                    todo.append((p, d + 1 if len(p.succ) > 1 else d))
        return dm
