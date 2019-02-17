from collections import deque

from teether.cfg.opcodes import memory_reads, memory_writes


class InconsistentRange(Exception):
    pass


class UninitializedRead(Exception):
    def __init__(self, index, *args):
        super(UninitializedRead, self).__init__(*args)
        if isinstance(index, slice):
            self.start = index.start or 0
            self.end = index.stop
        else:
            self.start = index
            self.end = index + 1

    def __repr__(self):
        return '%s from: %d to %d' % (super(UninitializedRead, self).__repr__(), self.start, self.end)

    def __str__(self):
        return '%s from: %d to %d' % (super(UninitializedRead, self).__repr__(), self.start, self.end)


class MemoryInfo(object):
    def __init__(self, reads, writes):
        self.reads = reads
        self.writes = writes


def get_memory_info(ins, code, memory_infos=None):
    from .slicing import backward_slice, slice_to_program
    from .evm.evm import run
    from .evm.state import EVMState
    from .evm.exceptions import ExternalData
    from .util.intrange import Range
    targets = []

    read = False
    write = False

    if ins.name in memory_reads:
        read = True
        read_offset_info, read_size_info = memory_reads[ins.name]
        if read_offset_info < 0:
            targets.append(-1 - read_offset_info)
        if read_size_info < 0:
            targets.append(-1 - read_size_info)
    if ins.name in memory_writes:
        write = True
        write_offset_info, write_size_info = memory_writes[ins.name]
        if write_offset_info < 0:
            targets.append(-1 - write_offset_info)
        if write_size_info < 0:
            targets.append(-1 - write_size_info)

    if not read and not write:
        return None

    bs = backward_slice(ins, targets, memory_infos)

    read_range = None
    write_range = None
    for b in bs:
        try:
            state = run(slice_to_program(b), EVMState(code=code), check_initialized=True)
        except UninitializedRead as e:
            raise e
        except ExternalData as e:
            raise e
        if read:
            read_offset = state.stack[read_offset_info] if read_offset_info < 0 else read_offset_info
            read_size = state.stack[read_size_info] if read_size_info < 0 else read_size_info
            new_range = Range(read_offset, read_offset + read_size)
            if read_range is None:
                read_range = new_range
            elif read_range != new_range:
                raise InconsistentRange()
        if write:
            write_offset = state.stack[write_offset_info] if write_offset_info < 0 else write_offset_info
            write_size = state.stack[write_size_info] if write_size_info < 0 else write_size_info
            new_range = Range(write_offset, write_offset + write_size)
            if write_range is None:
                write_range = new_range
            elif write_range != new_range:
                raise InconsistentRange()
    return MemoryInfo(read_range or Range(), write_range or Range())


def resolve_all_memory(cfg, code):
    memory_infos = dict()
    resolve_later = deque(
        ins for bb in cfg.bbs for ins in bb.ins if ins.name in memory_reads or ins.name in memory_writes)
    todo = deque()
    progress = True
    while todo or (progress and resolve_later):
        if not todo:
            todo = resolve_later
            resolve_later = deque()
            progress = False
        ins = todo.popleft()
        try:
            mi = get_memory_info(ins, code, memory_infos)
            if mi:
                progress = True
                memory_infos[ins] = mi
        except Exception as e:
            resolve_later.append(ins)
    return memory_infos
