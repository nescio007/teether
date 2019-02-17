from teether.cfg.instruction import Instruction
from teether.cfg.opcodes import potentially_user_controlled
from teether.explorer.backward import traverse_back
from teether.util.intrange import Range


def slice_to_program(s):
    pc = 0
    program = {}
    for ins in s:
        program[pc] = ins
        pc += ins.next_addr - ins.addr
    return program


def adjust_stack(backward_slice, stack_delta):
    if stack_delta > 0:
        backward_slice.extend(Instruction(0x0, 0x63, b'\xde\xad\xc0\xde') for _ in range(abs(stack_delta)))
    elif stack_delta < 0:
        backward_slice.extend(Instruction(0x0, 0x50) for _ in range(abs(stack_delta)))


class SlicingState(object):
    def __init__(self, stacksize, stack_underflow, stack_delta, taintmap, memory_taint, backward_slice, instructions):
        self.stacksize = stacksize
        self.stack_underflow = stack_underflow
        self.stack_delta = stack_delta
        self.taintmap = frozenset(taintmap)
        self.memory_taint = memory_taint
        # The actual slice doesn't matter that much. What matters more is the resulting EXPRESSION of the return-address
        self.backward_slice = tuple(backward_slice)
        self.instructions = tuple(instructions)

    def __hash__(self):
        return sum(
            a * b for a, b in zip((23, 29, 31, 37, 41), (
                self.stacksize, self.stack_delta, hash(self.taintmap), hash(self.instructions),
                hash(self.backward_slice))))

    def __eq__(self, other):
        return (
                self.stacksize == other.stacksize and
                self.stack_delta == other.stack_delta and
                self.taintmap == other.taintmap and
                self.memory_taint == other.memory_taint and
                self.backward_slice == other.backward_slice and
                self.instructions == other.instructions)

    def __str__(self):
        return 'Stacksize: %d, Underflow: %d, Delta: %d, Map: %s, Slice: %s, Instructions: %s' % (
            self.stacksize, self.stack_underflow, self.stack_delta, self.taintmap,
            ','.join('%x' % i.addr for i in self.backward_slice),
            ','.join('%x' % i.addr for i in self.instructions))


def advance_slice(slicing_state, memory_info):
    stacksize = slicing_state.stacksize
    stack_underflow = slicing_state.stack_underflow
    stack_delta = slicing_state.stack_delta
    taintmap = set(slicing_state.taintmap)
    memory_taint = slicing_state.memory_taint
    backward_slice = list(slicing_state.backward_slice)
    instructions = slicing_state.instructions

    for ins in instructions[::-1]:
        slice_candidate = False
        if taintmap and stacksize - ins.outs <= max(taintmap):
            slice_candidate = True
        if memory_info and ins in memory_info and memory_info[ins].writes & memory_taint:
            slice_candidate = True
        if slice_candidate:
            add_to_slice = False
            if 0x80 <= ins.op <= 0x8f:  # Special handling for DUPa
                if stacksize - 1 in taintmap:
                    add_to_slice = True
                    in_idx = ins.op - 0x7f
                    taintmap.remove(stacksize - 1)
                    taintmap.add((stacksize - 1) - in_idx)
            elif 0x90 <= ins.op <= 0x9f:  # Special handling for SWAP
                in_idx = ins.op - 0x8f
                if stacksize - 1 in taintmap or (stacksize - 1) - in_idx in taintmap:
                    add_to_slice = True
                    if stacksize - 1 in taintmap and (stacksize - 1) - in_idx in taintmap:
                        # both tainted => taint does not change
                        pass
                    elif stacksize - 1 in taintmap:
                        taintmap.remove(stacksize - 1)
                        taintmap.add((stacksize - 1) - in_idx)
                    elif (stacksize - 1) - in_idx in taintmap:
                        taintmap.remove((stacksize - 1) - in_idx)
                        taintmap.add(stacksize - 1)
            else:  # assume entire stack is affected otherwise
                add_to_slice = True
                taintmap -= set(range(stacksize - ins.outs, stacksize))
                taintmap |= set(range(stacksize - ins.outs, stacksize - ins.delta))

            if add_to_slice:
                adjust_stack(backward_slice, stack_delta)
                stack_delta = -ins.delta
                backward_slice.append(ins)
                stack_underflow = min(stack_underflow, stacksize - ins.outs)
                if memory_info and ins in memory_info:
                    ins_info = memory_info[ins]
                    memory_taint = memory_taint - ins_info.writes + ins_info.reads

        stacksize -= ins.delta
        # no taint left? then our job here is done
        if not taintmap and not memory_taint:
            stack_adjust = stacksize - stack_underflow
            if stack_adjust > 0:
                adjust_stack(backward_slice, stack_adjust)
            return SlicingState(stacksize, stack_underflow, stack_delta, set(taintmap), memory_taint,
                                list(backward_slice),
                                [])

        stack_delta += ins.delta

    # still taint left? trace further if gas is still sufficient
    return SlicingState(stacksize, stack_underflow, stack_delta, set(taintmap), memory_taint, list(backward_slice),
                        [])


def backward_slice(ins, taint_args=None, memory_info=None, initial_gas=10, must_visits=[], reachable=False):
    # logging.debug('backward_slice called')
    if ins.ins == 0:
        return []
    if taint_args:
        taintmap = set((ins.ins - 1) - i for i in taint_args)
    else:
        taintmap = set(range(ins.ins))
    if memory_info and ins in memory_info:
        memory_taint = memory_info[ins].reads
    else:
        memory_taint = Range()

    def initial_data(ins):
        stacksize = ins.ins
        slice = []
        stack_underflow = 0
        stack_delta = 0
        idx = ins.bb.ins.index(ins)
        return SlicingState(stacksize, stack_underflow, stack_delta, taintmap, memory_taint, slice,
                            ins.bb.ins[:idx])

    def advance_data(slicing_state):
        return advance_slice(slicing_state, memory_info)

    def update_data(slicing_state, new_bb):
        return SlicingState(slicing_state.stacksize, slicing_state.stack_underflow, slicing_state.stack_delta,
                            set(slicing_state.taintmap), slicing_state.memory_taint, list(slicing_state.backward_slice),
                            new_bb.ins)

    def finish_path(slicing_state):
        return not slicing_state.taintmap and not slicing_state.memory_taint

    # logging.debug('Before loop')
    slices = [r.backward_slice[::-1] for r in
              traverse_back([ins], initial_gas, initial_data, advance_data, update_data, finish_path, must_visits)]
    if not reachable:
        return slices
    else:
        filtered_slices = []
        for slice in slices:
            first_bb = next(i.bb for i in slice if i.bb)
            if 0 in first_bb.ancestors | {first_bb.start}:
                filtered_slices.append(slice)
        return filtered_slices


def interesting_slices(instruction, args=None, reachable=False):
    return [bs for bs in backward_slice(instruction, args, reachable=reachable) if any(
        ins.name in potentially_user_controlled for ins in bs)]
