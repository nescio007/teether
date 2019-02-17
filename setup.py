from setuptools import setup

setup(
    name='teether',
    version='0.1',
    packages=['teether'],
    install_requires=[
        'z3-solver>=4.8.0.0',
        'pysha3>=1.0.2'
    ],
    scripts=[
        'bin/asm.py',
        'bin/extract_contract_code.py',
        'bin/gen_exploit.py',
        'bin/plot_cfg.py',
        'bin/replay_exploit.py',
    ],
    url='https://github.com/nescio007/teether',
    python_requires='>=3.5',
    license='Apache 2.0',
    author='Johannes Krupp',
    author_email='johannes.krupp@cispa.saarland',
    description='Analysis and automatic exploitation framework for Ethereum smart contracts'
)
