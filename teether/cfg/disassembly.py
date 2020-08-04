import logging
from collections import deque

from teether.cfg.bb import BB
from teether.cfg.instruction import Instruction
from teether.cfg.opcodes import opcodes


class ArgumentTooShort(Exception):
    pass


def disass(code, i=0):
    assert isinstance(code, bytes)
    while i < len(code):
        loc = i
        op = code[i]
        arg = None
        inslen = 1
        if not op in opcodes:
            break
            # raise IllegalInstruction('%02x at %d'%(op, i))
        if 0x60 <= op <= 0x7f:
            arglen = op - 0x5f
            inslen += arglen
            arg = code[i + 1:i + 1 + arglen]
            if len(arg) < arglen:
                raise ArgumentTooShort
            i += arglen
        i += 1
        yield Instruction(loc, op, arg)
        # End basic block on STOP, JUMP, JUMPI, RETURN, REVERT, RAISE, or if the following instruction is a JUMPDEST
        if op in (0x00, 0x56, 0x57, 0xf3, 0xfd, 0xfe, 0xff) or (i < len(code) and code[i] == 0x5b):
            break


def generate_BBs(code):
    fallthrough_locs = [i + 1 for i, c in enumerate(code) if c == 0x57]
    jumpdest_locs = [i for i, c in enumerate(code) if c == 0x5b]
    leader_candidates = {0} | set(fallthrough_locs) | set(jumpdest_locs)
    for l in sorted(leader_candidates):
        try:
            instructions = list(disass(code, l))
            if instructions:
                yield BB(instructions)
        except:
            continue