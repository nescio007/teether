import unittest

from teether import project
from teether.slicing import backward_slice


class MyTestCase(unittest.TestCase):
    def test_slicing(self):
        p = project.Project(bytes.fromhex("3460085733600b565b60005b600052"))
        last_store = p.cfg.filter_ins('MSTORE')[-1]
        slices = list(backward_slice(last_store))
        self.assertEqual(len(slices), 2)
