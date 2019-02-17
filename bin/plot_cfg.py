#!/usr/bin/env python3
import logging
import resource
import sys

logging.basicConfig(level=logging.INFO)

import teether.project

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: %s [flags] <code>' % sys.argv[0])
        exit(-1)

    mem_limit = 4 * 1024 * 1024 * 1024  # 4GB
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    infile = sys.argv[-1]
    if infile.endswith('.json'):
        import json

        with open(infile, 'rb') as f:
            jd = json.load(f)
        p = teether.project.Project.from_json(jd)
    else:
        p = teether.project.load(infile)
    print(p.cfg.to_dot(minimal='-m' in sys.argv or '--minimal' in sys.argv))
