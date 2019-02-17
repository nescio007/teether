import json
import unittest

from teether.project import Project

test_code = '3460085733600b565b60005b600052'
test_json = '''
        {"cfg": 
            {"bbs": 
                [
                    {"start": 0, 
                    "succs": [
                        {"start": 4, 
                         "paths": [[0]]},
                        {"start": 8, 
                         "paths": [[0]]}
                     ]}, 
                    {"start": 4, 
                    "succs": [{"start": 11, "paths": [[4]]}]}, 
                    {"start": 8, "succs": [{"start": 11, "paths": [[8]]}]}, 
                    {"start": 11, "succs": []}
                ]}, 
        "code": "3460085733600b565b60005b600052"}'''

test_dot = 'digraph g {\n\tsplines=ortho;\n\tnode[fontname="courier"];\n\t0 [shape=box,label=<From: <br align="left"/>Min constraints from root: 1<br align="left"/>Min back branches to root: 0<br align="left"/><b>0</b>:<br align="left"/>   0: 34 CALLVALUE <br align="left"/>   1: 60 PUSH1 08<br align="left"/>   3: 57 JUMPI <br align="left"/>To: 4, 8<br align="left"/>>];\n\t4 [shape=box,label=<From: 0<br align="left"/>Min constraints from root: 1<br align="left"/>Min back branches to root: 0<br align="left"/><b>4</b>:<br align="left"/>   4: 33 CALLER <br align="left"/>   5: 60 PUSH1 0b<br align="left"/>   7: 56 JUMP <br align="left"/>To: b<br align="left"/>>];\n\t8 [shape=box,label=<From: 0<br align="left"/>Min constraints from root: 1<br align="left"/>Min back branches to root: 0<br align="left"/><b>8</b>:<br align="left"/>   8: 5b JUMPDEST <br align="left"/>   9: 60 PUSH1 00<br align="left"/>To: b<br align="left"/>>];\n\t11 [shape=box,label=<From: 4, 8<br align="left"/>Min constraints from root: 1<br align="left"/>Min back branches to root: 1<br align="left"/><b>b</b>:<br align="left"/>   b: 5b JUMPDEST <br align="left"/>   c: 60 PUSH1 00<br align="left"/>   e: 52 MSTORE <br align="left"/>To: <br align="left"/>>];\n\n\t0 -> 4 [xlabel="0"];\n\t0 -> 8 [xlabel="0"];\n\t4 -> 11 [xlabel="4"];\n\t8 -> 11 [xlabel="8"];\n}'


class TestImport(unittest.TestCase):
    def test_json_import(self):
        p = Project.from_json(json.loads(test_json))

        self.assertEqual(p.code, bytes.fromhex(test_code))
        self.assertEqual(p.cfg.bb_addrs, frozenset([0, 4, 8, 11]))


class TestExport(unittest.TestCase):
    def test_json_export(self):
        p = Project(bytes.fromhex(test_code))

        self.assertEqual(json.loads(json.dumps(p.to_json())), json.loads(test_json))


class TestDot(unittest.TestCase):
    def test_dot_export(self):
        p = Project(bytes.fromhex(test_code))

        self.assertEqual(p.cfg.to_dot(), test_dot)
