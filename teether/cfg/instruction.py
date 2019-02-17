from teether.cfg.opcodes import opcodes


class Instruction(object):
    def __init__(self, addr, op, arg=None):
        if not (arg is None or isinstance(arg, bytes)):
            raise ValueError('Instruction arg must be bytes or None')
        assert arg is None or isinstance(arg, bytes)
        opinfo = opcodes[op]
        inslen = (op - 0x5f) + 1 if 0x60 <= op <= 0x7f else 1
        self.addr = addr
        self.next_addr = self.addr + inslen
        self.op = op
        self.name = opinfo[0]
        self.arg = arg
        self.ins = opinfo[1]
        self.outs = opinfo[2]
        self.gas = opinfo[3]
        self.delta = self.outs - self.ins
        self.bb = None

    def __str__(self):
        return '(%5d) %4x:\t%02x\t-%d +%d = %d\t%s%s' % (
            self.addr, self.addr, self.op, self.ins, self.outs, self.delta, self.name,
            '(%d) %s' % (int.from_bytes(self.arg, byteorder='big'), '\t%s' % self.arg.hex()) if self.arg else '')

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return 17 * self.addr + 19 * self.op + 23 * hash(self.arg)

    def __eq__(self, other):
        return (self.addr == other.addr and
                self.op == other.op and
                self.arg == other.arg)
