#!/usr/bin/env python3
import logging
import sys

from teether.evm.exceptions import ExternalData, VMException
from teether.memory import resolve_all_memory
from teether.project import Project
from teether.slicing import backward_slice, slice_to_program


def extract_contract_code(code):
    """
    Extract actual contract code from deployment code
    :param code: deployment code (as output)
    :return: code of deployed contract
    """
    p = Project(code)
    p.cfg.trim()
    returns = p.cfg.filter_ins('RETURN')
    memory_infos = resolve_all_memory(p.cfg, code)
    for r in returns:
        if not r in memory_infos:
            continue
        rmi = memory_infos[r].reads
        if len(rmi.points) != 2:
            continue
        (start, _), (stop, _) = rmi.points
        bs = backward_slice(r, memory_info=memory_infos)
        for b in bs:
            try:
                state = p.run(slice_to_program(b))
                return state.memory[start:stop]
            except (ExternalData, VMException) as e:
                logging.exception('Exception while running', e)
                pass
    return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: %s <codefile>' % sys.argv[0])
        exit(-1)
    with open(sys.argv[1]) as infile:
        inbuffer = infile.read().rstrip()
    code = bytes.fromhex(inbuffer)
    if b'\x39' not in code:
        logging.warning('No CODECOPY in this contract!!')
    contract = extract_contract_code(code)
    if contract:
        print(contract.hex())
    else:
        logging.error('Could not find contract code')
