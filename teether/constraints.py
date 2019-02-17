import copy
import itertools
import logging
from collections import defaultdict

from z3 import z3, z3util

from teether.evm.exceptions import IntractablePath
from teether.evm.state import SymRead, concrete
from teether.util.utils import big_endian_to_int, sha3
from teether.util.z3_extra_util import get_vars_non_recursive, to_bytes, simplify_non_const_hashes


class UnresolvedConstraints(Exception):
    def __init__(self, unresolved):
        super(UnresolvedConstraints, self).__init__(unresolved)
        self.unresolved = unresolved


def array_to_array(array_model, length=0):
    l = array_model.as_list()
    entries, else_value = l[:-1], l[-1]
    length = max(max(e[0].as_long() for e in entries) + 1, length)
    arr = [else_value.as_long()] * length
    for e in entries:
        arr[e[0].as_long()] = e[1].as_long()
    return arr


def get_level(name):
    try:
        return int(name[name.rfind('_') + 1:])
    except:
        return 0


def model_to_calls(model, idx_dict):
    calls = defaultdict(dict)
    for v in model:
        name = v.name()
        if name.split('_')[0] not in ('CALLDATASIZE', 'CALLDATA', 'CALLVALUE', 'CALLER'):
            continue
        call_index = idx_dict[get_level(name)]
        call = calls[call_index]
        if name.startswith('CALLDATASIZE'):
            payload_size = model[v].as_long()
            call['payload_size'] = payload_size
        elif name.startswith('CALLDATA'):
            call['payload'] = bytes(array_to_array(model[v]))
            if 'payload_size' in call:
                call['payload'] = call['payload'][:payload_size]
                del call['payload_size']
        elif name.startswith('CALLVALUE'):
            call['value'] = model[v].as_long()
        elif name.startswith('CALLER'):
            call['caller'] = model[v].as_long()
        else:
            logging.warning('CANNOT CONVERT %s', name)

    return [v for k, v in sorted(calls.items())]


# MAX_SYM_READ_SIZE = 512
MAX_SYM_READ_SIZE = 256


def symread_eq(a, b, size=MAX_SYM_READ_SIZE):
    if not isinstance(a, SymRead) and not isinstance(b, SymRead):
        if a.size() != b.size():
            return z3.BoolVal(False)
        else:
            return a == b
    elif isinstance(a, SymRead) and isinstance(b, SymRead):
        # both have symbolic size
        return z3.And(a.size == b.size,
                      *(z3.If(z3.ULT(i, a.size), a.memory[a.start + i] == b.memory[b.start + i], True) for i in
                        range(size)))
    else:
        if isinstance(b, SymRead):
            # ensure that a is the one with symbolic size
            a, b = b, a
        return z3.And(a.size == (b.size() // 8), z3.Concat(*a.memory.read(a.start, b.size() // 8)) == b)


def symread_neq(a, b, size=MAX_SYM_READ_SIZE):
    return z3.Not(symread_eq(a, b, size))


def symread_substitute(x, subst):
    if not isinstance(x, SymRead):
        return z3.simplify(z3.substitute(x, subst))
    else:
        new_symread = copy.copy(x)
        new_symread.memory.memory = z3.simplify(z3.substitute(new_symread.memory.memory, subst))
        if not concrete(new_symread.start):
            new_symread.start = z3.simplify(z3.substitute(new_symread.start, subst))
        if not concrete(new_symread.size):
            new_symread.size = z3.simplify(z3.substitute(new_symread.size, subst))
        return new_symread


def check_model_and_resolve(constraints, sha_constraints):
    try:
        return check_model_and_resolve_inner(constraints, sha_constraints)
    except UnresolvedConstraints:
        sha_ids = {sha.get_id() for sha in sha_constraints.keys()}
        constraints = [simplify_non_const_hashes(c, sha_ids) for c in constraints]
        return check_model_and_resolve_inner(constraints, sha_constraints, second_try=True)


def check_model_and_resolve_inner(constraints, sha_constraints, second_try=False):
    # logging.debug('-' * 32)
    extra_constraints = []
    s = z3.SolverFor("QF_ABV")
    z3.set_option(model_compress=False)
    s.add(constraints)
    if s.check() != z3.sat:
        raise IntractablePath("CHECK", "MODEL")
    else:
        if not sha_constraints:
            return s.model()

    while True:
        ne_constraints = []
        for a, b in itertools.combinations(sha_constraints.keys(), 2):
            if (not isinstance(sha_constraints[a], SymRead) and not isinstance(sha_constraints[b], SymRead) and
                    sha_constraints[a].size() != sha_constraints[b].size()):
                ne_constraints.append(a != b)
                continue
            s = z3.SolverFor("QF_ABV")
            z3.set_option(model_compress=False)
            s.add(constraints + ne_constraints + extra_constraints + [a != b, symread_neq(sha_constraints[a],
                                                                                          sha_constraints[b])])
            check_result = s.check()
            # logging.debug("Checking hashes %s and %s: %s", a, b, check_result)
            if check_result == z3.unsat:
                # logging.debug("Hashes MUST be equal: %s and %s", a, b)
                subst = [(a, b)]
                extra_constraints = [z3.simplify(z3.substitute(c, subst)) for c in extra_constraints]
                extra_constraints.append(symread_eq(symread_substitute(sha_constraints[a], subst),
                                                    symread_substitute(sha_constraints[b], subst)))
                constraints = [z3.simplify(z3.substitute(c, subst)) for c in constraints]
                b_val = symread_substitute(sha_constraints[b], subst)
                sha_constraints = {z3.substitute(sha, subst): symread_substitute(sha_value, subst) for
                                   sha, sha_value in
                                   sha_constraints.items() if not sha is a or sha is b}
                sha_constraints[b] = b_val
                break
            else:
                # logging.debug("Hashes COULD be equal: %s and %s", a, b)
                pass
        else:
            break

    return check_and_model(constraints + extra_constraints, sha_constraints, ne_constraints, second_try=second_try)


def check_and_model(constraints, sha_constraints, ne_constraints, second_try=False):
    # logging.debug(' ' * 16 + '-' * 16)

    unresolved = set(sha_constraints.keys())
    sol = z3.SolverFor("QF_ABV")
    z3.set_option(model_compress=False)
    sol.add(ne_constraints)
    todo = constraints
    progress = True
    all_vars = dict()
    while progress:
        new_todo = []
        progress = False
        for c in todo:
            all_vars[c] = get_vars_non_recursive(c, include_select=True, include_indices=False)
            if any(x in unresolved for x in all_vars[c]):
                new_todo.append(c)
            else:
                progress = True
                sol.add(c)
        unresolved_vars = set(v.get_id() for c in new_todo for v in all_vars[c]) | set(v.get_id() for v in unresolved)
        # logging.debug("Unresolved vars: %s", ','.join(map(str, unresolved_vars)))
        if sol.check() != z3.sat:
            raise IntractablePath()
        m = sol.model()
        unresolved_todo = list(set(unresolved))
        while unresolved_todo:
            u = unresolved_todo.pop()
            c = sha_constraints[u]
            if isinstance(c, SymRead):
                vars = set()
                if not concrete(c.start):
                    vars |= get_vars_non_recursive(c.start, include_select=True)
                if not concrete(c.size):
                    vars |= get_vars_non_recursive(c.size, include_select=True)
                # logging.debug("Trying to resolve %s, start and size vars: %s", u, ','.join(map(str, vars)))
                if any(x.get_id() in unresolved_vars for x in vars):
                    continue
                start = c.start
                if not concrete(c.start):
                    tmp = m.eval(c.start)
                    if not z3util.is_expr_val(tmp):
                        continue
                    start = tmp.as_long()
                    sol.add(c.start == start)
                size = c.size
                if not concrete(c.size):
                    tmp = m.eval(c.size)
                    if not z3util.is_expr_val(tmp):
                        continue
                    size = tmp.as_long()
                    sol.add(c.size == size)

                data = c.memory.read(start, size)
                if isinstance(data, list):
                    if len(data) > 1:
                        data = z3.Concat(*data)
                    elif len(data) == 1:
                        data = data[0]
                    else:
                        raise IntractablePath()
                sha_constraints = dict(sha_constraints)
                sha_constraints[u] = data
                unresolved_todo.append(u)
            else:
                vars = get_vars_non_recursive(c, include_select=True)
                # logging.debug("Trying to resolve %s, vars: %s", u, ','.join(map(str, vars)))
                if any(x.get_id() in unresolved_vars for x in vars):
                    continue
                v = m.eval(c)
                if z3util.is_expr_val(v):
                    sha = big_endian_to_int(sha3(to_bytes(v)))
                    sol.add(c == v)
                    sol.add(u == sha)
                    unresolved.remove(u)
                    progress = True
        todo = new_todo
    if sol.check() != z3.sat:
        raise IntractablePath()
    if todo:
        if second_try:
            raise IntractablePath()
        raise UnresolvedConstraints(unresolved)
    return sol.model()


def dependency_summary(constraints, sha_constraints, detailed=False):
    all_dependencies = set(x for c in constraints if z3.is_expr(c) for x in
                           get_vars_non_recursive(z3.simplify(c), include_select=detailed))
    changed = True
    while changed:
        changed = False
        for x in set(all_dependencies):
            if x in sha_constraints:
                changed = True
                all_dependencies.discard(x)
                all_dependencies.update(
                    get_vars_non_recursive(z3.simplify(sha_constraints[x], include_select=detailed)))
    return all_dependencies
