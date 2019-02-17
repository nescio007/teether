class Range(object):
    START = 0
    END = 1

    def __init__(self, start=None, end=None, points=None):
        if not start is None and not end is None and start < end:
            self.points = ((start, Range.START), (end, Range.END))
        elif points:
            self.points = tuple(points)
        else:
            self.points = tuple()

    def __munch__(self, other, min_depth):
        depth = 0
        points = []
        for i, t in sorted(self.points + other.points):
            if depth == min_depth - 1 and t == Range.START:
                if points and i == points[-1][0]:
                    del points[-1]
                else:
                    points.append((i, Range.START))
            elif depth == min_depth and t == Range.END:
                if points and i == points[-1][0]:
                    del points[-1]
                else:
                    points.append((i, Range.END))
            depth += 1 if t == Range.START else -1
        return Range(points=points)

    def __add__(self, other):
        return self.__munch__(other, 1)

    def __and__(self, other):
        return self.__munch__(other, 2)

    def __sub__(self, other):
        return self + Range(points=[(i, 1 - t) for i, t in other.points])

    def __contains__(self, other):
        if not isinstance(other, Range):
            other = Range(other, other + 1)
        return not (other - self).points

    def __or__(self, other):
        return self + other

    def __xor__(self, other):
        return (self - other) + (other - self)

    def __eq__(self, other):
        return not self ^ other

    def __hash__(self):
        return hash(self.points)

    def __cmp__(self, other):
        for (a, _), (b, _) in zip(self.points, other.points):
            if a != b:
                return a - b
        else:
            l1, l2 = len(self), len(other)
            return l1 - l2

    def __len__(self):
        return sum(b - a for (a, _), (b, _) in zip(self.points[::2], self.points[1::2]))

    def __repr__(self):
        return 'Range(' + str(self) + ')'

    def __str__(self):
        return ','.join('[%d, %d)' % (a, b) for (a, _), (b, _) in zip(self.points[::2], self.points[1::2]))
