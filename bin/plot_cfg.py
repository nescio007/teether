#!/usr/bin/env python3
import logging
import resource

logging.basicConfig(level=logging.INFO)

import teether.project


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('code', help='deployment bytecode')
    parser.add_argument('-m', '--minimal', action='store_true', help='Omit unnecessary details from CFG')
    parser.add_argument('-t', '--trim', action='store_true', help='Trim CFG to reachable BBs')

    args = parser.parse_args()

    mem_limit = 4 * 1024 * 1024 * 1024  # 4GB
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    infile = args.code
    if infile.endswith('.json'):
        import json

        with open(infile, 'rb') as f:
            jd = json.load(f)
        p = teether.project.Project.from_json(jd)
    else:
        p = teether.project.load(infile)
    if args.trim:
        p.cfg.trim()
    print(p.cfg.to_dot(minimal=args.minimal))


if __name__ == '__main__':
    main()
