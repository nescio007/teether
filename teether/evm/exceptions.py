class ExternalData(Exception):
    pass


class SymbolicError(Exception):
    pass


class IntractablePath(Exception):
    def __init__(self, trace=[], remainingpath=[]):
        self.trace = tuple(trace)
        self.remainingpath = tuple(remainingpath)


class VMException(Exception):
    pass
