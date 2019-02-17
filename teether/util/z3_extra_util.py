import numbers

import z3


def to_bytes(v):
    return v.as_long().to_bytes(length=(v.size()+7)//8, byteorder='big')


def get_vars(f, rs=set()):
    """
    shameless copy of z3util.get_vars,
    but returning select-operations as well.
    E.g.
    >>> x = z3.Array('x', z3.IntSort(), z3.IntSort())
    >>> get_vars(x[5])
    [x[5]]
    whereas
    >>> x = z3.Array('x', z3.IntSort(), z3.IntSort())
    >>> z3util.get_vars(x[5])
    [x]
    """
    if not rs:
        f = z3.simplify(f)

    if f.decl().kind() == z3.Z3_OP_SELECT:
        arr, idx = f.children()
        if z3.is_const(arr):
            if z3.z3util.is_expr_val(idx):
                return rs | {f}
            else:
                return rs | {f, idx}
    if z3.is_const(f):
        if z3.z3util.is_expr_val(f):
            return rs
        else:  # variable
            return rs | {f}

    else:
        for f_ in f.children():
            rs = get_vars(f_, rs)

        return set(rs)


def get_vars_non_recursive(f, include_select=False, include_indices=True):
    todo = [f]
    rs = set()
    seen = set()
    while todo:
        expr = todo.pop()
        if expr.get_id() in seen:
            continue
        seen.add(expr.get_id())
        if include_select and expr.decl().kind() == z3.Z3_OP_SELECT:
            arr, idx = expr.children()
            if z3.is_const(arr):
                if not include_indices or z3.z3util.is_expr_val(idx):
                    rs.add(expr)
                else:
                    rs.add(expr)
                    todo.append(idx)
            else:
                todo.extend(expr.children())
        elif z3.is_const(expr):
            if not z3.z3util.is_expr_val(expr):
                rs.add(expr)
        else:
            todo.extend(expr.children())

    return rs


def concrete(v):
    return isinstance(v, numbers.Number)


def is_false(cond):
    s = z3.SolverFor("QF_ABV")
    s.add(cond)
    return s.check() == z3.unsat


def is_true(cond):
    # NOTE: This differs from `not is_false(cond)`, which corresponds to "may be true"
    return is_false(z3.Not(cond))


def simplify_non_const_hashes(expr, sha_ids):
    while True:
        expr = z3.simplify(expr, expand_select_store=True)
        sha_subst = get_sha_subst_non_recursive(expr, sha_ids)
        if not sha_subst:
            break
        expr = z3.substitute(expr, [(s, z3.BoolVal(False)) for s in sha_subst])
    return expr


def is_simple_expr(expr):
    """
        True if expr does not contain an If, Store, or Select statement
    :param expr: the expression to check
    :return: True, iff expr does not contain If, Store, or Select
    """

    if expr.decl().kind() in {z3.Z3_OP_ITE, z3.Z3_OP_SELECT, z3.Z3_OP_STORE}:
        return False
    else:
        return all(is_simple_expr(c) for c in expr.children())


def ast_eq(e1, e2, simplified=False):
    if not simplified:
        e1 = z3.simplify(e1)
        e2 = z3.simplify(e2)
    if e1.sort() != e2.sort():
        return False
    if e1.decl().kind() != e2.decl().kind():
        return False
    if z3.z3util.is_expr_val(e1) and z3.z3util.is_expr_val(e2):
        return e1.as_long() == e2.as_long()
    return all(ast_eq(c1, c2, True) for c1, c2 in zip(e1.children(), e2.children()))


def get_sha_subst_non_recursive(f, sha_ids):
    import timeit
    start = timeit.default_timer()
    todo = [z3.simplify(f, expand_select_store=True)]
    rs = set()
    seen = set()
    subexprcount = 0
    while todo:
        expr = todo.pop()
        subexprcount += 1
        if expr.get_id() in seen:
            continue
        seen.add(expr.get_id())
        if expr.decl().kind() == z3.Z3_OP_EQ and all(is_simple_expr(c) for c in expr.children()):
            l, r = expr.children()
            lvars, rvars = [{v.get_id() for v in get_vars_non_recursive(e, True)} for e in (l, r)]

            sha_left = bool(lvars & sha_ids)
            sha_right = bool(rvars & sha_ids)

            if sha_left and sha_right:
                # both sides use a sha-expression
                # => can be equal only if ASTs are equal
                if not ast_eq(l, r):
                    rs.add(expr)

            elif sha_left ^ sha_right:
                # only one side uses a sha-expression
                # => assume not equal (e.g. SHA == 5 seems unlikely)
                rs.add(expr)

        else:
            todo.extend(expr.children())

    end = timeit.default_timer()
    # logging.info("get_sha_subst_non_recursive took %d microseconds (%d subexpressions)", (end-start)*1000000.0, subexprcount)
    return rs
