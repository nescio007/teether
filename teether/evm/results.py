import itertools

from z3 import z3

from teether.evm.state import SymRead, LazySubstituteState, translate
from teether.util.z3_extra_util import get_vars_non_recursive, concrete, ast_eq


class SymbolicResult(object):
    def __init__(self, xid, state, constraints, sha_constraints, target_op):
        self.xid = xid
        self.state = state
        self.constraints = constraints
        self.sha_constraints = sha_constraints
        self.target_op = target_op
        self.calls = 1
        self._simplified = False
        self.storage_info = StorageInfo(self)

    def simplify(self):
        if self._simplified:
            return
        self.constraints = [z3.simplify(c) for c in self.constraints]
        self.sha_constraints = {sha: z3.simplify(sha_value) if not isinstance(sha_value, SymRead) else sha_value for
                                sha, sha_value in self.sha_constraints.items()}
        self._simplified = True

    def copy(self):
        new_xid = gen_exec_id()

        self.simplify()

        new_constraints = [translate(c, new_xid) for c in self.constraints]
        new_sha_constraints = {translate(sha, new_xid): translate(sha_value, new_xid) if not isinstance(sha_value,
                                                                                                        SymRead) else sha_value.translate(
            new_xid) for sha, sha_value in
                               self.sha_constraints.items()}
        new_state = self.state.copy(new_xid)

        return SymbolicResult(new_xid, new_state, new_constraints, new_sha_constraints, self.target_op)

    def may_read_from(self, other):
        return self.storage_info.may_read_from(other.storage_info)


class CombinedSymbolicResult(object):
    def __init__(self):
        self.results = []
        self._constraints = None
        self._sha_constraints = None
        self._states = None
        self._idx_dict = None
        self.calls = 0

    def _reset(self):
        self._constraints = None
        self._sha_constraints = None
        self._states = None

    def combine(self, storage=dict(), initial_balance=None):
        extra_subst = []

        storage_base = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))
        for k, v in storage.items():
            storage_base = z3.Store(storage_base, k, v)
        for result in self.results:
            extra_subst.append((result.state.storage.base, storage_base))
            storage_base = z3.substitute(result.state.storage.storage, extra_subst)

        extra_constraints = []
        if initial_balance is not None:
            balance_base = z3.BitVecVal(initial_balance, 256)
        else:
            balance_base = None
        for result in self.results:
            if balance_base is not None:
                extra_subst.append((result.state.start_balance, balance_base))
                balance_base = z3.substitute(result.state.balance, extra_subst)
            else:
                balance_base = result.state.balance

        self._states = [LazySubstituteState(r.state, extra_subst) for r in self.results]
        self._constraints = [z3.substitute(c, extra_subst) for r in self.results for c in
                             r.constraints] + extra_constraints
        self._sha_constraints = {
            sha: z3.substitute(sha_value, extra_subst) if not isinstance(sha_value, SymRead) else sha_value for r in
            self.results for sha, sha_value in r.sha_constraints.items()}

        self._idx_dict = {r.xid: i for i, r in enumerate(self.results)}

    def prepend(self, result):
        self.calls += 1
        self.results = [result] + self.results
        self._reset()

    @property
    def idx_dict(self):
        if self._idx_dict is None:
            self.combine()
        return self._idx_dict

    @property
    def constraints(self):
        if self._constraints is None:
            self.combine()
        return self._constraints

    @property
    def sha_constraints(self):
        if self._sha_constraints is None:
            self.combine()
        return self._sha_constraints

    @property
    def states(self):
        if not self._states:
            self.combine()
        return self._states

    @property
    def state(self):
        return self.states[-1]

    def simplify(self):
        self._constraints = [z3.simplify(c) for c in self.constraints]
        self._sha_constraints = {sha: (z3.simplify(sha_value) if not isinstance(sha_value, SymRead) else sha_value) for
                                 sha, sha_value in self.sha_constraints.items()}


class StorageInfo(object):
    def __init__(self, result):
        self.result = result
        self._vars = dict()
        self.concrete_reads = set()
        self.concrete_writes = set()
        self.symbolic_reads = set()
        self.symbolic_writes = set()
        self.symbolic_hash_reads = set()
        self.symbolic_hash_writes = set()
        for addr in set(result.state.storage.reads):
            if concrete(addr):
                self.concrete_reads.add(addr)
            else:
                x_vars = get_vars_non_recursive(addr, True)
                self._vars[addr] = x_vars
                if set(x_vars) & set(result.sha_constraints.keys()):
                    self.symbolic_hash_reads.add(addr)
                else:
                    self.symbolic_reads.add(addr)
        for addr in set(result.state.storage.writes):
            if concrete(addr):
                self.concrete_writes.add(addr)
            else:
                x_vars = get_vars_non_recursive(addr, True)
                self._vars[addr] = x_vars
                if set(x_vars) & set(result.sha_constraints.keys()):
                    self.symbolic_hash_writes.add(addr)
                else:
                    self.symbolic_writes.add(addr)

    def may_read_from(self, other):
        if not self.symbolic_reads and not other.symbolic_writes:
            # no side has a non-hash-based symbolic access
            # => only concrete accesses can intersect
            # (or hash-based accesses, which we will check later)
            if self.concrete_reads & other.concrete_writes:
                return True
        else:
            # at least one side has a non-hash-based symbolic access
            # => if there is at least one concrete or symbolic access
            # on the other side, the two could be equal
            # (otherwise we have to look at hash-based accesses, see below)
            if ((self.symbolic_reads or self.concrete_reads or self.symbolic_hash_reads) and
                    (other.symbolic_writes or other.concrete_writes or other.symbolic_hash_writes)):
                return True

        if self.symbolic_hash_reads and other.symbolic_hash_writes:
            for a, b in itertools.product(self.symbolic_hash_reads, other.symbolic_hash_writes):
                if not ast_eq(a, b):
                    continue
                hash_a = list(self._vars[a] & set(self.result.sha_constraints.keys()))
                hash_b = list(other._vars[b] & set(other.result.sha_constraints.keys()))
                if len(hash_a) != 1 or len(hash_b) != 1:
                    # multiple hashes on either side
                    # => assume they could be equal
                    return True
                # only one hash on either side
                # => check whether these two can actually be equal
                d_a = self.result.sha_constraints[hash_a[0]]
                d_b = other.result.sha_constraints[hash_b[0]]
                if isinstance(d_a, SymRead) or isinstance(d_b, SymRead):
                    return True
                if d_a.size() == d_b.size():
                    return True

        # at this point, we have checked every possible combination
        # => no luck this time
        return False


def gen_exec_id():
    if "xid" not in gen_exec_id.__dict__:
        gen_exec_id.xid = 0
    else:
        gen_exec_id.xid += 1
    return gen_exec_id.xid
