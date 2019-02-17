import unittest

from teether.util.utils import sha3


class TestKeccak(unittest.TestCase):
    def test_keccak_256(self):
        self.assertEqual(sha3(b''), bytes.fromhex('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'))