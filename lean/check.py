# SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0

"""Compile from scratch with Lean4.24.0; save the command/axiom/hash receipt."""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent
log = []
def run(args, env=None):
    log.append('$ ' + ' '.join(map(str, args)))
    result = subprocess.run(args, cwd=root, env=env, text=True, capture_output=True)
    log.extend([result.stdout + result.stderr, f'exit: {result.returncode}\n'])
    if result.returncode:
        (root / 'verification.txt').write_text('\n'.join(log))
        raise SystemExit(result.returncode)
    return result.stdout

version = run(['lean', '--version'])
if 'version 4.24.0' not in version:
    raise SystemExit('This proof checkpoint pins Lean4.24.0; use lean-toolchain.')
with tempfile.TemporaryDirectory(prefix='auth-lean-') as build:
    env = dict(os.environ, LEAN_PATH=build)
    for name in ['AuthCodec', 'AuthVerifier', 'AuthReplay']:
        run(['lean', '-DwarningAsError=true', '-o', str(Path(build)/(name+'.olean')),
             str(root/(name+'.lean'))], env)
    run(['lean', '-DwarningAsError=true', str(root/'Check.lean')], env)
log.append('SHA256 of proof and reproduction inputs:')
for p in sorted(root.iterdir()):
    if p.suffix == '.lean' or p.name in ('check.py', 'lean-toolchain'):
        log.append(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name)
(root / 'verification.txt').write_text('\n'.join(log) + '\n')
print('PASS: three Lean modules, warnings as errors; twenty axiom audits. Receipt: verification.txt')
