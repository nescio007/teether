from z3 import z3

from teether.evm.exceptions import SymbolicError
from teether.memory import UninitializedRead
from teether.util.z3_extra_util import concrete, get_vars_non_recursive


class Stack(list):
    def __init__(self, *args):
        super(Stack, self).__init__(*args)

    def push(self, v):
        self.append(v)

    def append(self, v):
        if concrete(v):
            v %= 2 ** 256
        super(Stack, self).append(v)


class Memory(object):
    def __init__(self, *args):
        self.memory = bytearray(*args)
        self._check_initialized = False
        self.initialized = set()

    def __getitem__(self, index):
        if isinstance(index, slice):
            initialized = all(i in self.initialized for i in range(index.start or 0, index.stop, index.step or 1))
        else:
            initialized = index in self.initialized
        if not self._check_initialized or initialized:
            return self.memory[index]
        else:
            raise UninitializedRead(index)

    def __setitem__(self, index, v):
        if isinstance(index, slice):
            for i in range(index.start or 0, index.stop, index.step or 1):
                self.initialized.add(i)
        else:
            self.initialized.add(index)
        self.memory[index] = v

    def set_enforcing(self, enforcing=True):
        self._check_initialized = enforcing

    def extend(self, start, size):
        if len(self.memory) < start + size:
            self.memory += bytearray(start + size - len(self.memory))

    def __len__(self):
        return len(self.memory)


class SymbolicMemory(object):
    MAX_SYMBOLIC_WRITE_SIZE = 256

    def __init__(self):
        self.memory = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
        self.write_count = 0
        self.read_count = 0

    def __getitem__(self, index):
        if isinstance(index, slice):
            if index.stop is None:
                raise ValueError("Need upper memory address!")
            if (index.start is not None and not concrete(index.start)) or not concrete(index.stop):
                raise SymbolicError("Use mem.read for symbolic range reads")
            r = []
            for i in range(index.start or 0, index.stop, index.step or 1):
                r.append(self[i])
            return r
        else:
            self.read_count += 1
            v = z3.simplify(self.memory[index])
            if z3.is_bv_value(v):
                return v.as_long()
            else:
                return v

    def __setitem__(self, index, v):
        if isinstance(index, slice):
            if index.stop is None:
                raise ValueError("Need upper memory address!")
            if (index.start is not None and not concrete(index.start)) or not concrete(index.stop):
                raise SymbolicError("Use mem.write for symbolic range writes")
            for j, i in enumerate(range(index.start or 0, index.stop, index.step or 1)):
                self[i] = v[j]
        else:
            self.write_count += 1
            if isinstance(v, str):
                v = ord(v)

            if concrete(v):
                old_v = self[index]
                if not concrete(old_v) or old_v != v:
                    self.memory = z3.Store(self.memory, index, v)
            else:
                self.memory = z3.Store(self.memory, index, v)

    def read(self, start, size):
        if concrete(start) and concrete(size):
            return self[start:start + size]
        elif concrete(size):
            return [self[start + i] for i in range(size)]
        else:
            sym_mem = SymbolicMemory()
            sym_mem.memory = self.memory
            return SymRead(sym_mem, start, size)
            # raise SymbolicError("Read of symbolic length")

    def copy(self, istart, ilen, ostart, olen):
        if concrete(ilen) and concrete(olen):
            self.write(ostart, olen, self.read(istart, min(ilen, olen)) + [0] * max(olen - ilen, 0))
        elif concrete(olen):
            self.write(ostart, olen, [z3.If(i < ilen, self[istart + i], 0) for i in range(olen)])
        else:
            self.write(ostart, SymbolicMemory.MAX_SYMBOLIC_WRITE_SIZE,
                       [z3.If(i < olen, z3.If(i < ilen, self[istart + i], 0), self[ostart + i]) for i in
                        range(SymbolicMemory.MAX_SYMBOLIC_WRITE_SIZE)])

    def write(self, start, size, val):
        if not concrete(size):
            raise SymbolicError("Write of symbolic length")
        if len(val) != size:
            raise ValueError("value does not match length")
        if concrete(start) and concrete(size):
            self[start:start + size] = val
        else:  # by now we know that size is concrete
            for i in range(size):
                self[start + i] = val[i]

    def set_enforcing(self, enforcing=True):
        pass

    def extend(self, start, size):
        pass


class SymRead(object):
    def __init__(self, memory, start, size):
        self.memory = memory
        self.start = start
        if not concrete(start):
            self.start = z3.simplify(self.start)
        self.size = size
        if not concrete(size):
            self.size = z3.simplify(self.size)

    def translate(self, new_xid):
        sym_mem_mem = translate(self.memory.memory, new_xid)
        sym_mem = SymbolicMemory()
        sym_mem.memory = sym_mem_mem
        new_symread = SymRead(sym_mem, 0, 0)
        new_symread.start = self.start if concrete(self.start) else translate(self.start, new_xid)
        new_symread.size = self.size if concrete(self.size) else translate(self.size, new_xid)
        return new_symread


class SymbolicStorage(object):
    def __init__(self, xid):
        self.base = z3.Array('STORAGE_%d' % xid, z3.BitVecSort(256), z3.BitVecSort(256))
        self.storage = self.base
        self.accesses = list()

    def __getitem__(self, index):
        self.accesses.append(('read', index if concrete(index) else z3.simplify(index)))
        return self.storage[index]

    def __setitem__(self, index, v):
        self.accesses.append(('write', index if concrete(index) else z3.simplify(index)))
        self.storage = z3.Store(self.storage, index, v)

    @property
    def reads(self):
        return [a for t, a in self.accesses if t == 'read']

    @property
    def writes(self):
        return [a for t, a in self.accesses if t == 'write']

    @property
    def all(self):
        return [a for t, a in self.accesses]

    def copy(self, new_xid):
        new_storage = SymbolicStorage(new_xid)
        new_storage.base = translate(self.base, new_xid)
        new_storage.storage = translate(self.storage, new_xid)
        new_storage.accesses = [(t, a if concrete(a) else translate(a, new_xid)) for t, a in self.accesses]
        return new_storage


class AbstractEVMState(object):
    def __init__(self, code=None):
        self.code = code or bytearray()
        self.pc = 0
        self.stack = Stack()
        self.memory = None
        self.trace = list()
        self.gas = None


class EVMState(AbstractEVMState):
    def __init__(self, code=None, gas=0):
        super(EVMState, self).__init__(code)
        self.memory = Memory()
        self.gas = gas


class SymbolicEVMState(AbstractEVMState):
    def __init__(self, xid, code=None):
        super(SymbolicEVMState, self).__init__(code)
        self.memory = SymbolicMemory()
        self.storage = SymbolicStorage(xid)
        self.gas = z3.BitVec('GAS_%d' % xid, 256)
        self.start_balance = z3.BitVec('BALANCE_%d' % xid, 256)
        self.balance = self.start_balance

    def copy(self, new_xid):
        # Make a superficial copy of this state.
        # Effectively, only the storage is copied,
        # as this is sufficient to prepend a
        # result with this state to another call
        new_storage = self.storage.copy(new_xid)
        new_state = SymbolicEVMState(new_xid)
        new_state.storage = new_storage
        new_state.pc = self.pc
        new_state.trace = list(self.trace)
        new_state.start_balance = translate(self.start_balance, new_xid)
        new_state.balance = translate(self.balance, new_xid)
        return new_state


class LazySubstituteState(object):
    def __init__(self, state, substitutions):
        self._state = state
        self._substitutions = list(substitutions)
        self.memory = LazySubstituteMemory(self._state.memory, substitutions)
        self.stack = LazySubstituteStack(self._state.stack, substitutions)
        self.code = self._state.code
        self.pc = self._state.pc
        self.trace = self._state.trace
        self.balance = z3.substitute(state.balance, substitutions)


class LazySubstituteMemory(object):
    def __init__(self, memory, substitutions):
        self._memory = memory
        self._substitutions = substitutions

    def __getitem__(self, index):
        raise NotImplemented()


class LazySubstituteStack(object):
    def __init__(self, stack, substitutions):
        self._stack = stack
        self._substitutions = substitutions

    def __getitem__(self, index):
        r = self._stack[index]
        if isinstance(index, slice):
            return [x if concrete(x) else z3.substitute(x, self._substitutions) for x in r]
        else:
            return r if concrete(r) else z3.substitute(r, self._substitutions)


def translate(expr, xid):
    substitutions = dict()

    def raw(s):
        return '_'.join(s.split('_')[:-1])

    for v in get_vars_non_recursive(expr):
        if v not in substitutions:
            v_name = raw(v.decl().name())
            if v.sort_kind() == z3.Z3_INT_SORT:
                substitutions[v] = z3.Int('%s_%d' % (v_name, xid))
            elif v.sort_kind() == z3.Z3_BOOL_SORT:
                substitutions[v] = z3.Bool('%s_%d' % (v_name, xid))
            elif v.sort_kind() == z3.Z3_BV_SORT:
                substitutions[v] = z3.BitVec('%s_%d' % (v_name, xid), v.size())
            elif v.sort_kind() == z3.Z3_ARRAY_SORT:
                substitutions[v] = z3.Array('%s_%d' % (v_name, xid), v.domain(), v.range())
            else:
                raise Exception('CANNOT CONVERT %s (%d)' % (v, v.sort_kind()))
    subst = list(substitutions.items())
    return z3.substitute(expr, subst)
