import datetime
import logging
from collections import defaultdict

from z3 import z3

import teether.util.utils
from teether.evm.exceptions import ExternalData, SymbolicError, IntractablePath, VMException
from teether.evm.results import SymbolicResult, gen_exec_id
from teether.evm.state import SymRead, EVMState, SymbolicEVMState
from teether.util.z3_extra_util import concrete, is_true


class Context(object):
    def __init__(self):
        self.address = 0
        self.balance = dict()
        self.origin = 0
        self.caller = 0
        self.callvalue = 0
        self.calldata = []
        self.gasprice = 0
        self.coinbase = 0
        self.timestamp = 0
        self.number = 0
        self.difficulty = 0
        self.gaslimit = 0
        self.storage = defaultdict(int)


def run(program, state=None, code=None, ctx=None, check_initialized=False, trace=False):
    ctx = ctx or Context()
    state = state or EVMState(code)
    state.memory.set_enforcing(check_initialized)
    while state.pc in program:
        if trace:
            state.trace.append(state.pc)
        ins = program[state.pc]
        opcode = ins.op
        op = ins.name
        stk = state.stack
        mem = state.memory
        # Valid operations
        # Pushes first because they are very frequent
        if 0x60 <= opcode <= 0x7f:
            stk.append(int.from_bytes(ins.arg, byteorder='big'))
            state.pc += opcode - 0x5f  # Move 1 byte forward for 0x60, up to 32 bytes for 0x7f
        # Arithmetic
        elif opcode < 0x10:
            if op == 'STOP':
                state.success = True
                return state
            elif op == 'ADD':
                stk.append(stk.pop() + stk.pop())
            elif op == 'SUB':
                stk.append(stk.pop() - stk.pop())
            elif op == 'MUL':
                stk.append(stk.pop() * stk.pop())
            elif op == 'DIV':
                s0, s1 = stk.pop(), stk.pop()
                stk.append(0 if s1 == 0 else s0 // s1)
            elif op == 'MOD':
                s0, s1 = stk.pop(), stk.pop()
                stk.append(0 if s1 == 0 else s0 % s1)
            elif op == 'SDIV':
                s0, s1 = teether.util.utils.to_signed(stk.pop()), teether.util.utils.to_signed(stk.pop())
                stk.append(0 if s1 == 0 else abs(s0) // abs(s1) *
                                             (-1 if s0 * s1 < 0 else 1))
            elif op == 'SMOD':
                s0, s1 = teether.util.utils.to_signed(stk.pop()), teether.util.utils.to_signed(stk.pop())
                stk.append(0 if s1 == 0 else abs(s0) % abs(s1) *
                                             (-1 if s0 < 0 else 1))
            elif op == 'ADDMOD':
                s0, s1, s2 = stk.pop(), stk.pop(), stk.pop()
                stk.append((s0 + s1) % s2 if s2 else 0)
            elif op == 'MULMOD':
                s0, s1, s2 = stk.pop(), stk.pop(), stk.pop()
                stk.append((s0 * s1) % s2 if s2 else 0)
            elif op == 'EXP':
                base, exponent = stk.pop(), stk.pop()
                stk.append(pow(base, exponent, teether.util.utils.TT256))
            elif op == 'SIGNEXTEND':
                s0, s1 = stk.pop(), stk.pop()
                if s0 <= 31:
                    testbit = s0 * 8 + 7
                    if s1 & (1 << testbit):
                        stk.append(s1 | (teether.util.utils.TT256 - (1 << testbit)))
                    else:
                        stk.append(s1 & ((1 << testbit) - 1))
                else:
                    stk.append(s1)
        # Comparisons
        elif opcode < 0x20:
            if op == 'LT':
                stk.append(1 if stk.pop() < stk.pop() else 0)
            elif op == 'GT':
                stk.append(1 if stk.pop() > stk.pop() else 0)
            elif op == 'SLT':
                s0, s1 = teether.util.utils.to_signed(stk.pop()), teether.util.utils.to_signed(stk.pop())
                stk.append(1 if s0 < s1 else 0)
            elif op == 'SGT':
                s0, s1 = teether.util.utils.to_signed(stk.pop()), teether.util.utils.to_signed(stk.pop())
                stk.append(1 if s0 > s1 else 0)
            elif op == 'EQ':
                stk.append(1 if stk.pop() == stk.pop() else 0)
            elif op == 'ISZERO':
                stk.append(0 if stk.pop() else 1)
            elif op == 'AND':
                stk.append(stk.pop() & stk.pop())
            elif op == 'OR':
                stk.append(stk.pop() | stk.pop())
            elif op == 'XOR':
                stk.append(stk.pop() ^ stk.pop())
            elif op == 'NOT':
                stk.append(teether.util.utils.TT256M1 - stk.pop())
            elif op == 'BYTE':
                s0, s1 = stk.pop(), stk.pop()
                if s0 >= 32:
                    stk.append(0)
                else:
                    stk.append((s1 // 256 ** (31 - s0)) % 256)
            elif op == 'SHL':
                s0, s1 = stk.pop(), stk.pop()
                stk.append((s1 << s0))
            elif op == 'SHR':
                s0, s1 = stk.pop(), stk.pop()
                stk.append((s1 >> s0))
            elif op == 'SAR':
                s0, s1 = stk.pop(), teether.util.utils.to_signed(stk.pop())
                stk.append((s1 >> s0))
        # SHA3 and environment info
        elif opcode < 0x40:
            if op == 'SHA3':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, s1)
                data = teether.util.utils.bytearray_to_bytestr(mem[s0: s0 + s1])
                stk.append(teether.util.utils.big_endian_to_int(teether.util.utils.sha3(data)))
            elif op == 'ADDRESS':
                stk.append(ctx.address)
            elif op == 'BALANCE':
                s0 = stk.pop()
                if s0 not in ctx.balance:
                    raise ExternalData('BALANCE')
                stk.append(ctx.balance[s0])
            elif op == 'ORIGIN':
                stk.append(ctx.origin)
            elif op == 'CALLER':
                stk.append(ctx.caller)
            elif op == 'CALLVALUE':
                stk.append(ctx.callvalue)
            elif op == 'CALLDATALOAD':
                s0 = stk.pop()
                stk.append(teether.util.utils.bytearray_to_int(ctx.calldata[s0:s0 + 32]))
            elif op == 'CALLDATASIZE':
                stk.append(len(ctx.calldata))
            elif op == 'CALLDATACOPY':
                mstart, dstart, size = stk.pop(), stk.pop(), stk.pop()
                mem.extend(mstart, size)
                for i in range(size):
                    if dstart + i < len(ctx.calldata):
                        mem[mstart + i] = ctx.calldata[dstart + i]
                    else:
                        mem[mstart + i] = 0
            elif op == 'CODESIZE':
                stk.append(len(state.code))
            elif op == 'CODECOPY':
                mstart, dstart, size = stk.pop(), stk.pop(), stk.pop()
                mem.extend(mstart, size)
                for i in range(size):
                    if dstart + i < len(state.code):
                        mem[mstart + i] = state.code[dstart + i]
                    else:
                        mem[mstart + i] = 0
            elif op == 'RETURNDATACOPY':
                raise ExternalData('RETURNDATACOPY')
            elif op == 'RETURNDATASIZE':
                raise ExternalData('RETURNDATASIZE')
            elif op == 'GASPRICE':
                stk.append(ctx.gasprice)
            elif op == 'EXTCODESIZE':
                raise ExternalData('EXTCODESIZE')
            elif op == 'EXTCODECOPY':
                raise ExternalData('EXTCODECOPY')
        # Block info
        elif opcode < 0x50:
            if op == 'BLOCKHASH':
                raise ExternalData('BLOCKHASH')
            elif op == 'COINBASE':
                stk.append(ctx.coinbase)
            elif op == 'TIMESTAMP':
                stk.append(ctx.timestamp)
            elif op == 'NUMBER':
                stk.append(ctx.number)
            elif op == 'DIFFICULTY':
                stk.append(ctx.difficulty)
            elif op == 'GASLIMIT':
                stk.append(ctx.gaslimit)
        # VM state manipulations
        elif opcode < 0x60:
            if op == 'POP':
                stk.pop()
            elif op == 'MLOAD':
                s0 = stk.pop()
                mem.extend(s0, 32)
                stk.append(teether.util.utils.bytes_to_int(mem[s0: s0 + 32]))
            elif op == 'MSTORE':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, 32)
                mem[s0: s0 + 32] = teether.util.utils.encode_int32(s1)
            elif op == 'MSTORE8':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, 1)
                mem[s0] = s1 % 256
            elif op == 'SLOAD':
                s0 = stk.pop()
                stk.append(ctx.storage[s0])
            elif op == 'SSTORE':
                s0, s1 = stk.pop(), stk.pop()
                ctx.storage[s0] = s1
            elif op == 'JUMP':
                state.pc = stk.pop()
                if state.pc >= len(state.code) or not program[state.pc].name == 'JUMPDEST':
                    raise VMException('BAD JUMPDEST')
                continue
            elif op == 'JUMPI':
                s0, s1 = stk.pop(), stk.pop()
                if s1:
                    state.pc = s0
                    if state.pc >= len(state.code) or not program[state.pc].name == 'JUMPDEST':
                        raise VMException('BAD JUMPDEST')
                    continue
            elif op == 'PC':
                stk.append(state.pc)
            elif op == 'MSIZE':
                stk.append(len(mem))
            elif op == 'GAS':
                stk.append(state.gas)
        # DUPn (eg. DUP1: a b c -> a b c c, DUP3: a b c -> a b c a)
        elif op[:3] == 'DUP':
            stk.append(stk[0x7f - opcode])  # 0x7f - opcode is a negative number, -1 for 0x80 ... -16 for 0x8f
        # SWAPn (eg. SWAP1: a b c d -> a b d c, SWAP3: a b c d -> d b c a)
        elif op[:4] == 'SWAP':
            # 0x8e - opcode is a negative number, -2 for 0x90 ... -17 for 0x9f
            stk[-1], stk[0x8e - opcode] = stk[0x8e - opcode], stk[-1]
        # Logs (aka "events")
        elif op[:3] == 'LOG':
            """
            0xa0 ... 0xa4, 32/64/96/128/160 + len(data) gas
            a. Opcodes LOG0...LOG4 are added, takes 2-6 stack arguments
                    MEMSTART MEMSZ (TOPIC1) (TOPIC2) (TOPIC3) (TOPIC4)
            b. Logs are kept track of during tx execution exactly the same way as selfdestructs
               (except as an ordered list, not a set).
               Each log is in the form [address, [topic1, ... ], data] where:
               * address is what the ADDRESS opcode would output
               * data is mem[MEMSTART: MEMSTART + MEMSZ]
               * topics are as provided by the opcode
            c. The ordered list of logs in the transaction are expressed as [log0, log1, ..., logN].
            """
            depth = int(op[3:])
            mstart, msz = stk.pop(), stk.pop()
            topics = [stk.pop() for _ in range(depth)]
            mem.extend(mstart, msz)
            # Ignore external effects...
        # Create a new contract
        elif op == 'CREATE':
            raise ExternalData('CREATE')
        # Calls
        elif op in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
            raise ExternalData(op)
        # Return opcode
        elif op == 'RETURN':
            s0, s1 = stk.pop(), stk.pop()
            mem.extend(s0, s1)
            state.success = True
            return state
        # Revert opcode (Metropolis)
        elif op == 'REVERT':
            s0, s1 = stk.pop(), stk.pop()
            mem.extend(s0, s1)
            return state
        # SELFDESTRUCT opcode (also called SELFDESTRUCT)
        elif op == 'SELFDESTRUCT':
            raise ExternalData('SELFDESTRUCT')

        state.pc += 1

    state.success = True
    return state


def ctx_or_symbolic(v, ctx, xid):
    return ctx.get(v, z3.BitVec('%s_%d' % (v, xid), 256))


def addr(expr):
    return expr & (2 ** 160 - 1)


def run_symbolic(program, path, code=None, state=None, ctx=None, inclusive=False):
    MAX_CALLDATA_SIZE = 256
    xid = gen_exec_id()
    state = state or SymbolicEVMState(xid=xid, code=code)
    storage = state.storage
    constraints = []
    sha_constraints = dict()
    ctx = ctx or dict()
    min_timestamp = (datetime.datetime.now() - datetime.datetime(1970, 1, 1)).total_seconds()
    # make sure we can exploit it in the foreseable future
    max_timestamp = (datetime.datetime(2020, 1, 1) - datetime.datetime(1970, 1, 1)).total_seconds()
    ctx['CODESIZE-ADDRESS'] = len(code)
    calldata = z3.Array('CALLDATA_%d' % xid, z3.BitVecSort(256), z3.BitVecSort(8))
    calldatasize = z3.BitVec('CALLDATASIZE_%d' % xid, 256)
    instruction_count = 0
    state.balance += ctx_or_symbolic('CALLVALUE', ctx, xid)

    target_op = program[path[-1]].name

    while state.pc in program:
        state.trace.append(state.pc)
        instruction_count += 1

        # have we reached the end of our path?
        if ((inclusive and len(path) == 0)
                or (not inclusive and path == [state.pc])):
            state.success = True
            return SymbolicResult(xid, state, constraints, sha_constraints, target_op)

        # if not, have we reached another step of our path?
        elif state.pc == path[0]:
            path = path[1:]

        ins = program[state.pc]
        opcode = ins.op
        op = ins.name
        stk = state.stack
        mem = state.memory
        state.gas -= ins.gas
        # Valid operations
        # Pushes first because they are very frequent
        if 0x60 <= opcode <= 0x7f:
            stk.append(int.from_bytes(ins.arg, byteorder='big'))
            state.pc += opcode - 0x5f  # Move 1 byte forward for 0x60, up to 32 bytes for 0x7f
        # Arithmetic
        elif opcode < 0x10:
            if op == 'STOP':
                if path:
                    raise IntractablePath(state.trace, path)
                state.success = True
                return SymbolicResult(xid, state, constraints, sha_constraints)
            elif op == 'ADD':
                stk.append(stk.pop() + stk.pop())
            elif op == 'SUB':
                stk.append(stk.pop() - stk.pop())
            elif op == 'MUL':
                stk.append(stk.pop() * stk.pop())
            elif op == 'DIV':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s1):
                    stk.append(0 if s1 == 0 else s0 / s1 if concrete(s0) else z3.UDiv(s0, s1))
                else:
                    stk.append(z3.If(s1 == 0, z3.BitVecVal(0, 256), z3.UDiv(s0, s1)))
            elif op == 'MOD':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s1):
                    stk.append(0 if s1 == 0 else s0 % s1)
                else:
                    stk.append(z3.If(s1 == 0, z3.BitVecVal(0, 256), z3.URem(s0, s1)))
            elif op == 'SDIV':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    s0, s1 = teether.util.utils.to_signed(s0), teether.util.utils.to_signed(s1)
                    stk.append(0 if s1 == 0 else abs(s0) // abs(s1) *
                                                 (-1 if s0 * s1 < 0 else 1))
                elif concrete(s1):
                    stk.append(0 if s1 == 0 else s0 / s1)
                else:
                    stk.append(z3.If(s1 == 0, z3.BitVecVal(0, 256), s0 / s1))
            elif op == 'SMOD':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    s0, s1 = teether.util.utils.to_signed(s0), teether.util.utils.to_signed(s1)
                    stk.append(0 if s1 == 0 else abs(s0) % abs(s1) *
                                                 (-1 if s0 < 0 else 1))
                elif concrete(s1):
                    stk.append(0 if s1 == 0 else z3.SRem(s0, s1))
                else:
                    stk.append(z3.If(s1 == 0, z3.BitVecVal(0, 256), z3.SRem(s0, s1)))
            elif op == 'ADDMOD':
                s0, s1, s2 = stk.pop(), stk.pop(), stk.pop()
                if concrete(s2):
                    stk.append((s0 + s1) % s2 if s2 else 0)
                else:
                    stk.append(z3.If(s2 == 0, z3.BitVecVal(0, 256), z3.URem((s0 + s1), s2)))
            elif op == 'MULMOD':
                s0, s1, s2 = stk.pop(), stk.pop(), stk.pop()
                if concrete(s2):
                    stk.append((s0 * s1) % s2 if s2 else 0)
                else:
                    stk.append(z3.If(s2 == 0, z3.BitVecVal(0, 256), z3.URem((s0 * s1), s2)))
            elif op == 'EXP':
                base, exponent = stk.pop(), stk.pop()
                if concrete(base) and concrete(exponent):
                    stk.append(pow(base, exponent, teether.util.utils.TT256))
                else:
                    if concrete(base) and teether.util.utils.is_pow2(base):
                        l2 = teether.util.utils.log2(base)
                        stk.append(1 << (l2 * exponent))
                    else:
                        raise SymbolicError('exponentiation with symbolic exponent currently not supported :-/')
            elif op == 'SIGNEXTEND':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    if s0 <= 31:
                        testbit = s0 * 8 + 7
                        if s1 & (1 << testbit):
                            stk.append(s1 | (teether.util.utils.TT256 - (1 << testbit)))
                        else:
                            stk.append(s1 & ((1 << testbit) - 1))
                    else:
                        stk.append(s1)
                elif concrete(s0):
                    if s0 <= 31:
                        oldwidth = (s0 + 1) * 8
                        stk.append(z3.SignExt(256 - oldwidth, s1))
                    else:
                        stk.append(s1)
                else:
                    raise SymbolicError('symbolic bitwidth for signextension is currently not supported')
        # Comparisons
        elif opcode < 0x20:
            if op == 'LT':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    stk.append(1 if s0 < s1 else 0)
                else:
                    stk.append(z3.If(z3.ULT(s0, s1), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'GT':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    stk.append(1 if s0 > s1 else 0)
                else:
                    stk.append(z3.If(z3.UGT(s0, s1), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'SLT':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    s0, s1 = teether.util.utils.to_signed(s0), teether.util.utils.to_signed(s1)
                    stk.append(1 if s0 < s1 else 0)
                else:
                    stk.append(z3.If(s0 < s1, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'SGT':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    s0, s1 = teether.util.utils.to_signed(s0), teether.util.utils.to_signed(s1)
                    stk.append(1 if s0 > s1 else 0)
                else:
                    stk.append(z3.If(s0 > s1, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'EQ':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0) and concrete(s1):
                    stk.append(1 if s0 == s1 else 0)
                else:
                    stk.append(z3.If(s0 == s1, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'ISZERO':
                s0 = stk.pop()
                if concrete(s0):
                    stk.append(1 if s0 == 0 else 0)
                else:
                    stk.append(z3.If(s0 == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
            elif op == 'AND':
                stk.append(stk.pop() & stk.pop())
            elif op == 'OR':
                stk.append(stk.pop() | stk.pop())
            elif op == 'XOR':
                stk.append(stk.pop() ^ stk.pop())
            elif op == 'NOT':
                stk.append(~stk.pop())
            elif op == 'BYTE':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s0):
                    if s0 >= 32:
                        stk.append(0)
                    else:
                        if concrete(s1):
                            stk.append((s1 // 256 ** (31 - s0)) % 256)
                        else:
                            v = z3.simplify(z3.Extract((31 - s0) * 8 + 7, (31 - s0) * 8, s1))
                            if z3.is_bv_value(v):
                                stk.append(v.as_long())
                            else:
                                stk.append(z3.ZeroExt(256 - 32, v))
                else:
                    raise SymbolicError('symbolic byte-index not supported')
            elif op == 'SHL':
                s0, s1 = stk.pop(), stk.pop()
                stk.append((s1 << s0))
            elif op == 'SHR':
                s0, s1 = stk.pop(), stk.pop()
                if concrete(s1) and concrete(s0):
                    stk.append((s1 >> s0))
                else:
                    stk.append(z3.LShR(s1, s0))

            elif op == 'SAR':
                s0, s1 = stk.pop(), teether.util.utils.to_signed(stk.pop())
                stk.append((s1 >> s0))
        # SHA3 and environment info
        elif opcode < 0x40:
            if op == 'SHA3':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, s1)
                mm = mem.read(s0, s1)
                if not isinstance(mm, SymRead) and all(concrete(m) for m in mm):
                    data = teether.util.utils.bytearray_to_bytestr(mm)
                    stk.append(teether.util.utils.big_endian_to_int(teether.util.utils.sha3(data)))
                else:
                    if not isinstance(mm, SymRead):
                        sha_data = z3.simplify(z3.Concat([m if z3.is_expr(m) else z3.BitVecVal(m, 8) for m in mm]))
                        for k, v in sha_constraints.items():
                            if isinstance(v, SymRead):
                                continue
                            if v.size() == sha_data.size() and is_true(v == sha_data):
                                sha = k
                                break
                        else:
                            sha = z3.BitVec('SHA3_%x_%d' % (instruction_count, xid), 256)
                            sha_constraints[sha] = sha_data
                    else:
                        sha_data = mm
                        sha = z3.BitVec('SHA3_%x_%d' % (instruction_count, xid), 256)
                        sha_constraints[sha] = sha_data
                    stk.append(sha)
                    # raise SymbolicError('symbolic computation of SHA3 not supported')
            elif op == 'ADDRESS':
                stk.append(ctx_or_symbolic('ADDRESS', ctx, xid))
            elif op == 'BALANCE':
                s0 = stk.pop()
                if concrete(s0):
                    stk.append(ctx_or_symbolic('BALANCE-%x' % s0, ctx, xid))
                elif is_true(addr(s0) == addr(ctx_or_symbolic('ADDRESS', ctx, xid))):
                    stk.append(state.balance)
                elif is_true(addr(s0) == addr(ctx_or_symbolic('CALLER', ctx, xid))):
                    stk.append(ctx_or_symbolic('BALANCE-CALLER', ctx, xid))
                else:
                    raise SymbolicError('balance of symbolic address (%s)' % str(z3.simplify(s0)))
            elif op == 'ORIGIN':
                stk.append(ctx_or_symbolic('ORIGIN', ctx, xid))
            elif op == 'CALLER':
                stk.append(ctx_or_symbolic('CALLER', ctx, xid))
            elif op == 'CALLVALUE':
                stk.append(ctx_or_symbolic('CALLVALUE', ctx, xid))
            elif op == 'CALLDATALOAD':
                s0 = stk.pop()
                constraints.append(z3.UGE(calldatasize, s0 + 32))
                if not concrete(s0):
                    constraints.append(z3.ULT(s0, MAX_CALLDATA_SIZE))
                stk.append(z3.Concat([calldata[s0 + i] for i in range(32)]))
            elif op == 'CALLDATASIZE':
                stk.append(calldatasize)
            elif op == 'CALLDATACOPY':
                mstart, dstart, size = stk.pop(), stk.pop(), stk.pop()
                constraints.append(z3.UGE(calldatasize, dstart + size))
                if not concrete(dstart):
                    constraints.append(z3.ULT(dstart, MAX_CALLDATA_SIZE))
                if concrete(size):
                    for i in range(size):
                        mem[mstart + i] = calldata[dstart + i]
                else:
                    constraints.append(z3.ULT(size, MAX_CALLDATA_SIZE))
                    for i in range(MAX_CALLDATA_SIZE):
                        mem[mstart + i] = z3.If(size < i, mem[mstart + i], calldata[dstart + i])
            elif op == 'CODESIZE':
                stk.append(len(state.code))
            elif op == 'CODECOPY':
                mstart, dstart, size = stk.pop(), stk.pop(), stk.pop()
                if concrete(mstart) and concrete(dstart) and concrete(size):
                    mem.extend(mstart, size)
                    for i in range(size):
                        if dstart + i < len(state.code):
                            mem[mstart + i] = state.code[dstart + i]
                        else:
                            mem[mstart + i] = 0
                else:
                    raise SymbolicError('Symbolic code index @ %s' % ins)
            elif op == 'RETURNDATACOPY':
                raise ExternalData('RETURNDATACOPY')
            elif op == 'RETURNDATASIZE':
                raise ExternalData('RETURNDATASIZE')
            elif op == 'GASPRICE':
                stk.append(ctx_or_symbolic('GASPRICE', ctx, xid))
            elif op == 'EXTCODESIZE':
                s0 = stk.pop()
                if concrete(s0):
                    stk.append(ctx_or_symbolic('CODESIZE-%x' % s0, ctx, xid))
                elif is_true(s0 == addr(ctx_or_symbolic('ADDRESS', ctx, xid))):
                    stk.append(ctx_or_symbolic('CODESIZE-ADDRESS', ctx, xid))
                elif is_true(s0 == addr(ctx_or_symbolic('CALLER', ctx, xid))):
                    stk.append(ctx_or_symbolic('CODESIZE-CALLER', ctx, xid))
                else:
                    raise SymbolicError('codesize of symblic address')
            elif op == 'EXTCODECOPY':
                raise ExternalData('EXTCODECOPY')
        # Block info
        elif opcode < 0x50:
            if op == 'BLOCKHASH':
                s0 = stk.pop()
                if not concrete(s0):
                    raise SymbolicError('symbolic blockhash index')
                stk.append(ctx_or_symbolic('BLOCKHASH[%d]' % s0, xid))
            elif op == 'COINBASE':
                stk.append(ctx_or_symbolic('COINBASE', ctx, xid))
            elif op == 'TIMESTAMP':
                ts = ctx_or_symbolic('TIMESTAMP', ctx, xid)
                if not concrete(ts):
                    constraints.append(z3.UGE(ts, min_timestamp))
                    constraints.append(z3.ULE(ts, max_timestamp))
                stk.append(ts)
            elif op == 'NUMBER':
                stk.append(ctx_or_symbolic('NUMBER', ctx, xid))
            elif op == 'DIFFICULTY':
                stk.append(ctx_or_symbolic('DIFFICULTY', ctx, xid))
            elif op == 'GASLIMIT':
                stk.append(ctx_or_symbolic('GASLIMIT', ctx, xid))
        # VM state manipulations
        elif opcode < 0x60:
            if op == 'POP':
                stk.pop()
            elif op == 'MLOAD':
                s0 = stk.pop()
                mem.extend(s0, 32)
                mm = [mem[s0 + i] for i in range(32)]
                if all(concrete(m) for m in mm):
                    stk.append(teether.util.utils.bytes_to_int(mem.read(s0, 32)))
                else:
                    v = z3.simplify(z3.Concat([m if not concrete(m) else z3.BitVecVal(m, 8) for m in mm]))
                    if z3.is_bv_value(v):
                        stk.append(v.as_long())
                    else:
                        stk.append(v)
            elif op == 'MSTORE':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, 32)
                if concrete(s1):
                    mem.write(s0, 32, teether.util.utils.encode_int32(s1))
                else:
                    for i in range(32):
                        m = z3.simplify(z3.Extract((31 - i) * 8 + 7, (31 - i) * 8, s1))
                        if z3.is_bv_value(m):
                            mem[s0 + i] = m.as_long()
                        else:
                            mem[s0 + i] = m
            elif op == 'MSTORE8':
                s0, s1 = stk.pop(), stk.pop()
                mem.extend(s0, 1)
                mem[s0] = s1 % 256
            elif op == 'SLOAD':
                s0 = stk.pop()

                v = z3.simplify(storage[s0])
                if z3.is_bv_value(v):
                    stk.append(v.as_long())
                else:
                    stk.append(v)
            elif op == 'SSTORE':
                s0, s1 = stk.pop(), stk.pop()
                storage[s0] = s1
            elif op == 'JUMP':
                s0 = stk.pop()
                if not concrete(s0):
                    raise SymbolicError('Symbolic jump target')
                state.pc = s0
                if state.pc >= len(state.code) or not program[state.pc].name == 'JUMPDEST':
                    raise VMException('BAD JUMPDEST')
                continue
            elif op == 'JUMPI':
                s0, s1 = stk.pop(), stk.pop()
                next_target = path[0]
                if concrete(s1):
                    if s1:
                        if not concrete(s0):
                            raise SymbolicError('Symbolic jump target')
                        if s0 != next_target and state.pc + 1 == next_target:
                            raise IntractablePath(state.trace, path)
                        state.pc = s0
                        if state.pc >= len(state.code) or not program[state.pc].name == 'JUMPDEST':
                            raise VMException('BAD JUMPDEST')
                        continue
                    else:
                        if concrete(s0):
                            if state.pc + 1 != next_target and s0 == next_target:
                                raise IntractablePath(state.trace, path)
                else:
                    if state.pc + 1 == next_target:
                        if not (concrete(s0) and s0 == next_target):
                            constraints.append(s1 == 0)
                    elif concrete(s0) and s0 == next_target:
                        if state.pc + 1 != next_target:
                            constraints.append(s1 != 0)
                        state.pc = s0
                        if state.pc >= len(state.code) or not program[state.pc].name == 'JUMPDEST':
                            raise VMException('BAD JUMPDEST')
                        continue
                    elif not concrete(s0):
                        raise SymbolicError('Symbolic jump target')
                    else:
                        raise IntractablePath(state.trace, path)

            elif op == 'PC':
                stk.append(state.pc)
            elif op == 'MSIZE':
                stk.append(len(mem))
            elif op == 'GAS':
                stk.append(z3.BitVec('GAS_%x' % instruction_count, 256))
        # DUPn (eg. DUP1: a b c -> a b c c, DUP3: a b c -> a b c a)
        elif op[:3] == 'DUP':
            stk.append(stk[0x7f - opcode])  # 0x7f - opcode is a negative number, -1 for 0x80 ... -16 for 0x8f
        # SWAPn (eg. SWAP1: a b c d -> a b d c, SWAP3: a b c d -> d b c a)
        elif op[:4] == 'SWAP':
            # 0x8e - opcode is a negative number, -2 for 0x90 ... -17 for 0x9f
            stk[-1], stk[0x8e - opcode] = stk[0x8e - opcode], stk[-1]
        # Logs (aka "events")
        elif op[:3] == 'LOG':
            """
            0xa0 ... 0xa4, 32/64/96/128/160 + len(data) gas
            a. Opcodes LOG0...LOG4 are added, takes 2-6 stack arguments
                    MEMSTART MEMSZ (TOPIC1) (TOPIC2) (TOPIC3) (TOPIC4)
            b. Logs are kept track of during tx execution exactly the same way as selfdestructs
               (except as an ordered list, not a set).
               Each log is in the form [address, [topic1, ... ], data] where:
               * address is what the ADDRESS opcode would output
               * data is mem[MEMSTART: MEMSTART + MEMSZ]
               * topics are as provided by the opcode
            c. The ordered list of logs in the transaction are expressed as [log0, log1, ..., logN].
            """
            depth = int(op[3:])
            mstart, msz = stk.pop(), stk.pop()
            topics = [stk.pop() for _ in range(depth)]
            mem.extend(mstart, msz)
            # Ignore external effects...
        # Create a new contract
        elif op == 'CREATE':
            s0, s1, s2 = stk.pop(), stk.pop(), stk.pop()
            constraints.append(z3.UGE(state.balance, s0))
            state.balance -= s0
            stk.append(addr(z3.BitVec('EXT_CREATE_%d_%d' % (instruction_count, xid), 256)))
        # Calls
        elif op in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
            if op in ('CALL', 'CALLCODE'):
                s0, s1, s2, s3, s4, s5, s6 = stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop()
                if op == 'CALL':
                    constraints.append(z3.UGE(state.balance, s2))
                    state.balance -= s2
            elif op == 'DELEGATECALL':
                s0, s1, s3, s4, s5, s6 = stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop()
                s2 = ctx_or_symbolic('CALLVALUE', ctx, xid)
            elif op == 'STATICCALL':
                s0, s1, s3, s4, s5, s6 = stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop(), stk.pop()
                s2 = 0

            ostart = s5 if concrete(s5) else z3.simplify(s5)
            olen = s6 if concrete(s6) else z3.simplify(s6)

            if concrete(s1) and s1 <= 8:
                if s1 == 4:
                    logging.info("Calling precompiled identity contract")
                    istart = s3 if concrete(s3) else z3.simplify(s3)
                    ilen = s4 if concrete(s4) else z3.simplify(s4)
                    mem.copy(istart, ilen, ostart, olen)
                    stk.append(1)
                else:
                    raise SymbolicError("Precompiled contract %d not implemented" % s1)
            else:
                for i in range(olen):
                    mem[ostart + i] = z3.BitVec('EXT_%d_%d_%d' % (instruction_count, i, xid), 8)
                logging.info("Calling contract %s (%d_%d)" % (s1, instruction_count, xid))
                stk.append(z3.BitVec('CALLRESULT_%d_%d' % (instruction_count, xid), 256))

        elif op == 'RETURN':
            s0, s1 = stk.pop(), stk.pop()
            if concrete(s0) and concrete(s1):
                mem.extend(s0, s1)
            state.success = True
            if path:
                raise IntractablePath(state.trace, path)
            return SymbolicResult(xid, state, constraints, sha_constraints)
        # Revert opcode (Metropolis)
        elif op == 'REVERT':
            s0, s1 = stk.pop(), stk.pop()
            if not concrete(s0) or not concrete(s1):
                raise SymbolicError('symbolic memory index')
            mem.extend(s0, s1)
            if path:
                raise IntractablePath(state.trace, path)
            return SymbolicResult(xid, state, constraints, sha_constraints)
        # SELFDESTRUCT opcode (also called SELFDESTRUCT)
        elif op == 'SELFDESTRUCT':
            s0 = stk.pop()
            state.success = True
            if path:
                raise IntractablePath(state.trace, path)
            return SymbolicResult(xid, state, constraints, sha_constraints)

        state.pc += 1

    if path:
        raise IntractablePath(state.trace, path)
    state.success = True
    return SymbolicResult(xid, state, constraints, sha_constraints)
