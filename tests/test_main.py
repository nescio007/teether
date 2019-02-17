import unittest

from teether.exploit import combined_exploit
from teether.project import Project
from teether.util.utils import denoms

target_addr = 0x1234123412341234123412341234123412341234
shellcode_addr = 0x1000000000000000000000000000000000000000
amount = 1000
amount_check = '+'
initial_storage = {}
initial_balance = 10 * denoms.ether


class TestMain(unittest.TestCase):
    def check(self, code_path):

        with open(code_path) as infile:
            inbuffer = infile.read().rstrip()
        code = bytes.fromhex(inbuffer)
        p = Project(code)

        result = combined_exploit(p, target_addr, shellcode_addr, amount, amount_check,
                                  initial_storage, initial_balance)
        self.assertIsNotNone(result)


for i in range(1, 22):
    if i == 12:
        # test12.sol is not exploitable
        continue


    def lambda_wrap(i):
        return lambda self: self.check('./data/test%d.contract.code' % i)


    setattr(TestMain, 'test_%02d' % i, lambda_wrap(i))
