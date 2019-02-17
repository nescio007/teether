from collections import defaultdict


class FrontierSet(object):
    """
    A set that also maintains a partial topological ordering
    The current set of "non-blocked" items can be obtained as
    .frontier
    """

    def __init__(self, data=None):
        self._inhibiting_set = defaultdict(set)
        self._blocking_set = defaultdict(set)
        self._edges = set()
        self._frontier = set()
        self._frozenedges = None
        self._frozenfrontier = None
        self._frozenall = None
        if data:
            for d in data:
                self.add(d)

    def _invalidate(self):
        self._frozenedges = None
        self._frozenfrontier = None
        self._frozenall = None

    @property
    def edges(self):
        if self._frozenedges is None:
            self._frozenedges = frozenset(self._edges)
        return self._frozenedges

    @property
    def frontier(self):
        if self._frozenfrontier is None:
            self._frozenfrontier = frozenset(self._frontier)
        return self._frozenfrontier

    @property
    def all(self):
        if self._frozenall is None:
            self._frozenall = frozenset(set(self._blocking_set.keys()) | set(self._inhibiting_set.keys()) | self._frontier)
        return self._frozenall

    def add(self, a, b=None):
        """
        Add a to the set.
        If b is given, require that a is a necessary prerequisite for b
        :param a:
        :param b:
        :return:
        """
        self._invalidate()
        if b:
            self._edges.add((a, b))
            self._inhibiting_set[b].add(a)
            self._blocking_set[a].add(b)
            if not self._inhibiting_set[a]:
                self._frontier.add(a)
            self._frontier.discard(b)
        else:
            self._frontier.add(a)

    def remove(self, a):
        self._invalidate()
        for b in self._blocking_set[a]:
            self._edges.discard((b, a))
            self._inhibiting_set[b].discard(a)
            if not self._inhibiting_set[b]:
                self._frontier.add(b)
        for c in self._inhibiting_set[a]:
            self._edges.discard((a, c))
            self._blocking_set[c].discard(a)
        del self._blocking_set[a]
        del self._inhibiting_set[a]
        self._frontier.discard(a)

    def copy(self):
        new = FrontierSet()
        new._inhibiting_set = self._inhibiting_set.copy()
        new._blocking_set = self._blocking_set.copy()
        new._edges = self._edges.copy()
        new._frontier = self._frontier.copy()
        new._invalidate()
        return new

    def issubset(self, other):
        return self.all.issubset(other.all) and self.edges.issubset(other.edges)

    def __len__(self):
        return len(self.all)

    def __eq__(self, other):
        return self.edges == other.edges and self.all == other.all

    def __hash__(self):
        return 3 * hash(self.edges) + 7 * hash(self.all)

    def __iter__(self):
        return iter(self.all)

    def __repr__(self):
        return '{%s|%s}' % (
        ','.join('%x' % i for i in self.frontier), ','.join('%x' % i for i in self.all - self.frontier))
