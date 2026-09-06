#!/usr/bin/env python3
"""Disposable exact-source baseline/fixed bind acceptance; no host runtime fallback."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

BASE = 'f2f1934f4cd7e9b6d36c9677c10c21a87086f1e1'
FIXED = '85a173a298ce877725c591cf50cea5ea5fc9cb13'
TEST = 'tests/explicit_bind_acceptance.rs'
CASES = ('explicit_ipv4_port_zero_matches_kernel_and_status',
         'explicit_ipv6_port_zero_matches_kernel_and_status',
         'occupied_explicit_address_fails_without_widening')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(*args, cwd=None):
    return subprocess.check_output(['git', *args], cwd=cwd, text=True).strip()


def write(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2)
        out.write('\n')


def state():
    head = git('rev-parse', 'HEAD')
    if head != os.environ['EXPECTED_COMMIT']:
        raise RuntimeError('unexpected diagnostic commit')
    if git('status', '--porcelain'):
        raise RuntimeError('source checkout is not clean')
    if git('diff', FIXED, 'HEAD', '--', 'src', 'Cargo.toml', 'Cargo.lock'):
        raise RuntimeError('production source or dependency graph changed')
    return {'head': head, 'tree': git('rev-parse', 'HEAD^{tree}'),
            'test_sha256': digest(TEST), 'lock_sha256': digest('Cargo.lock')}


def fresh_build_env(root, variant):
    # Exclusive target roots are the boundary between the two source variants.
    target = root / f'{variant}-target'
    target.mkdir(mode=0o700)
    return target, dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0')


def artifact_custody(metadata, artifacts, cwd, target):
    manifest = (cwd / 'Cargo.toml').resolve()
    packages = [row for row in metadata['packages']
                if Path(row['manifest_path']).resolve() == manifest]
    if len(packages) != 1 or Path(metadata['target_directory']).resolve() != target.resolve():
        raise RuntimeError('unexpected package manifest or shared Cargo target')
    package = packages[0]
    selected = {}
    for name, kind, source in [('ant_quic', 'lib', cwd / 'src/lib.rs'),
                               ('explicit_bind_acceptance', 'test', cwd / TEST)]:
        rows = [row for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row['target']['name'] == name and kind in row['target']['kind']]
        if len(rows) != 1:
            raise RuntimeError('expected exactly one package library and test artifact')
        row = rows[0]
        if (row['package_id'] != package['id'] or row.get('fresh') is not False
                or Path(row['target']['src_path']).resolve() != source.resolve()):
            raise RuntimeError('artifact source identity or compilation freshness mismatch')
        paths = set(row['filenames'])
        if kind == 'test':
            if not row.get('executable'):
                raise RuntimeError('missing test executable')
            paths.add(row['executable'])
        if not paths or (kind == 'lib' and not any(path.endswith('.rlib') for path in paths)):
            raise RuntimeError('missing compiled library files')
        hashes = {}
        for raw in sorted(paths):
            path = Path(raw).resolve(strict=True)
            if not path.is_relative_to(target.resolve()) or not path.is_file():
                raise RuntimeError('artifact is outside its exclusive target')
            hashes[str(path)] = digest(path)
        selected[kind] = {'package_id': row['package_id'], 'src_path': row['target']['src_path'],
                          'fresh': row['fresh'], 'files_sha256': hashes,
                          'executable': row.get('executable')}
    return {'manifest_path': str(manifest), 'package_id': package['id'],
            'target_directory': str(target), 'artifacts': selected}


def prepare(root):
    root.mkdir(mode=0o700)
    source = state()
    baseline = root / 'baseline-source'
    subprocess.run(['git', 'worktree', 'add', '--detach', str(baseline), BASE], check=True)
    if (baseline / TEST).exists():
        raise RuntimeError('baseline already contains diagnostic test')
    shutil.copyfile(TEST, baseline / TEST)
    if git('diff', '--', 'src', 'Cargo.toml', 'Cargo.lock', cwd=baseline):
        raise RuntimeError('baseline production source changed')
    if digest(baseline / 'Cargo.lock') != source['lock_sha256']:
        raise RuntimeError('baseline/fixed dependency graphs differ')
    binaries = {}
    for variant, cwd in [('baseline', baseline), ('fixed', Path.cwd())]:
        target, env = fresh_build_env(root, variant)
        target_identity = target.stat()
        write(root / f'{variant}-disk-before.json', dict(shutil.disk_usage(root)._asdict()))
        metadata_command = ['cargo', 'metadata', '--offline', '--locked', '--no-deps', '--format-version', '1']
        with (root / f'{variant}-metadata.json').open('x') as out, (root / f'{variant}-metadata.stderr').open('x') as err:
            result = subprocess.run(metadata_command, cwd=cwd, env=env, stdout=out, stderr=err)
        write(root / f'{variant}-metadata-exit.json', {'command': metadata_command, 'exit': result.returncode})
        if result.returncode:
            raise RuntimeError(f'{variant} metadata failed; no runtime admitted')
        command = ['cargo', 'test', '--offline', '--locked', '--test', 'explicit_bind_acceptance',
                   '--no-run', '--message-format', 'json']
        with (root / f'{variant}-build.jsonl').open('x') as out, (root / f'{variant}-build.stderr').open('x') as err:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=out, stderr=err)
        write(root / f'{variant}-build-exit.json', {'command': command, 'exit': result.returncode})
        if result.returncode:
            raise RuntimeError(f'{variant} compilation failed; no runtime admitted')
        artifacts = [json.loads(line) for line in (root / f'{variant}-build.jsonl').read_text().splitlines()]
        metadata_path = root / f'{variant}-metadata.json'
        custody = artifact_custody(json.loads(metadata_path.read_text()), artifacts, cwd, target)
        custody['metadata_sha256'] = digest(metadata_path)
        custody['build_jsonl_sha256'] = digest(root / f'{variant}-build.jsonl')
        binary = root / f'{variant}-tests'
        original = custody['artifacts']['test']['executable']
        with binary.open('xb') as out, Path(original).open('rb') as source_binary:
            shutil.copyfileobj(source_binary, out)
        binary.chmod(0o700)
        if digest(binary) != custody['artifacts']['test']['files_sha256'][str(Path(original).resolve())]:
            raise RuntimeError('test snapshot hash differs from compiler artifact')
        custody['snapshot'] = {'path': str(binary), 'sha256': digest(binary)}
        write(root / f'{variant}-custody.json', custody)
        write(root / f'{variant}-disk-after.json', dict(shutil.disk_usage(root)._asdict()))
        binaries[variant] = dict(custody['snapshot'], source=git('rev-parse', 'HEAD', cwd=cwd),
                                custody_sha256=digest(root / f'{variant}-custody.json'))
        if digest(cwd / TEST) != source['test_sha256'] or digest(cwd / 'Cargo.lock') != source['lock_sha256']:
            raise RuntimeError('build input custody changed')
        if variant == 'baseline':
            # Keep the independently hashed executable and all custody evidence;
            # discard only this newly created compiler root before the second cold build.
            current = target.stat()
            if (target.is_symlink() or (current.st_dev, current.st_ino)
                    != (target_identity.st_dev, target_identity.st_ino)
                    or target != root / 'baseline-target'
                    or digest(binary) != custody['snapshot']['sha256']
                    or digest(metadata_path) != custody['metadata_sha256']
                    or digest(root / f'{variant}-build.jsonl') != custody['build_jsonl_sha256']):
                raise RuntimeError('baseline target cleanup custody mismatch')
            shutil.rmtree(target)
            write(root / 'baseline-target-cleanup.json', {'target': str(target),
                  'removed': not target.exists(), 'snapshot_sha256': digest(binary),
                  'custody_sha256': digest(root / 'baseline-custody.json'),
                  'disk_after': dict(shutil.disk_usage(root)._asdict())})
    if state() != source:
        raise RuntimeError('fixed source custody changed')
    write(root / 'provenance.json', dict(source=source, binaries=binaries,
          baseline_tree=git('rev-parse', f'{BASE}^{{tree}}'), fixed_tree=git('rev-parse', f'{FIXED}^{{tree}}')))


def observed(stdout):
    return [json.loads(line.removeprefix('BIND_OBSERVATION ')) for line in stdout.splitlines()
            if line.startswith('BIND_OBSERVATION ')]


def validate_negative(case, code, stdout, stderr):
    rows = observed(stdout)
    requested = '127.0.0.1:0' if 'ipv4' in case else '[::1]:0'
    if code != 101 or len(rows) != 1 or 'EXPLICIT_BIND_IP_MISMATCH' not in stderr:
        raise RuntimeError('baseline did not fail at the intended bind assertion')
    row = rows[0]
    actual_ip = row['actual'].rsplit(':', 1)[0].strip('[]')
    if (row['case'] != 'explicit' or row['requested'] != requested
            or not ipaddress.ip_address(actual_ip).is_unspecified
            or row['status'] != row['actual'] or row['actual'] not in row['kernel_sockets']
            or row['cleanup_sockets'] or not row['reported_port_busy']):
        raise RuntimeError('baseline outcome does not prove the expected wildcard bind defect')
    if '0 passed; 1 failed;' not in stdout:
        raise RuntimeError('baseline test count does not match')
    return row


def run(root):
    receipt = json.loads((root / 'provenance.json').read_text())
    if state() != receipt['source']:
        raise RuntimeError('source custody changed before runtime')
    for variant, binary in receipt['binaries'].items():
        if digest(root / f'{variant}-custody.json') != binary['custody_sha256']:
            raise RuntimeError('build custody receipt changed before runtime')
        if digest(binary['path']) != binary['sha256']:
            raise RuntimeError('binary custody changed before runtime')
    cases = [('baseline', case) for case in CASES[:2]] + [('fixed', case) for case in CASES]
    outcomes = []
    for index, (variant, case) in enumerate(cases):
        binary = receipt['binaries'][variant]
        if digest(binary['path']) != binary['sha256']:
            raise RuntimeError('binary custody changed')
        before = set(Path(os.environ['RUNNER_TEMP']).glob('x0x-isolation-*'))
        command = ['python3', 'scripts/ci/isolated-runtime.py', binary['path'],
                   case, '--exact', '--nocapture', '--test-threads=1']
        started = time.monotonic()
        with (root / f'case-{index}.stdout').open('x') as out, (root / f'case-{index}.stderr').open('x') as err:
            result = subprocess.run(command, stdout=out, stderr=err,
                                    env=dict(os.environ, X0X_RUNTIME_TIMEOUT_SECONDS='60'))
        created = set(Path(os.environ['RUNNER_TEMP']).glob('x0x-isolation-*')) - before
        row = {'variant': variant, 'case': case, 'command': command, 'exit': result.returncode,
               'seconds': time.monotonic()-started, 'isolation_dirs': [str(path) for path in created]}
        write(root / f'case-{index}.json', row)
        if len(created) != 1:
            raise RuntimeError('missing or ambiguous namespace receipt')
        isolation = created.pop()
        admitted = json.loads((isolation / 'admission.json').read_text())
        terminal = json.loads((isolation / 'exit.json').read_text())
        supervisor = json.loads((isolation / 'supervisor.json').read_text())
        if (admitted['no_new_privs'] != 1 or terminal['exit'] != result.returncode
                or supervisor['reason'] is not None or not supervisor['child_reaped']):
            raise RuntimeError('namespace execution/cleanup did not complete normally')
        stdout = (root / f'case-{index}.stdout').read_text()
        stderr = (root / f'case-{index}.stderr').read_text()
        if variant == 'baseline':
            validate_negative(case, result.returncode, stdout, stderr)
            row['classification'] = 'intended-wildcard-bind-regression'
        else:
            if result.returncode or '1 passed; 0 failed;' not in stdout:
                raise RuntimeError('fixed acceptance failed')
            expected = 2 if case == CASES[2] else 1
            if stdout.count('BIND_ACCEPTANCE ') != expected:
                raise RuntimeError('missing fixed acceptance observations')
            row['classification'] = 'passed'
        outcomes.append(row)
    write(root / 'outcome.json', {'outcomes': outcomes, 'runtime_attempts': len(outcomes), 'no_retries': True})


def collect(root):
    import stat
    import re
    runner = root.parent
    upload = runner / 'explicit-bind-upload'
    upload.mkdir(mode=0o700)

    def read_regular(relative):
        parts = Path(relative).parts
        if not parts or any(part in ('.', '..', '/') for part in parts):
            raise RuntimeError('invalid evidence path')
        fd = os.open(runner, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(source, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 20_000_000:
                    raise RuntimeError('unexpected evidence type or size')
                return stream.read()
        finally:
            os.close(fd)

    names = ['provenance.json', 'outcome.json', 'baseline-target-cleanup.json', 'baseline-build.jsonl', 'baseline-build.stderr',
             'baseline-build-exit.json', 'fixed-build.jsonl', 'fixed-build.stderr', 'fixed-build-exit.json']
    names += [f'{variant}-{suffix}' for variant in ('baseline', 'fixed')
              for suffix in ('metadata.json', 'metadata.stderr', 'metadata-exit.json',
                             'custody.json', 'disk-before.json', 'disk-after.json')]
    names += [f'case-{index}.{suffix}' for index in range(5) for suffix in ('json', 'stdout', 'stderr')]
    for name in names:
        path = root / name
        if path.exists() or path.is_symlink():
            with (upload / name).open('xb') as out:
                out.write(read_regular(path.relative_to(runner)))
    for directory in runner.glob('x0x-isolation-*'):
        if not re.fullmatch(r'x0x-isolation-[A-Za-z0-9_-]+', directory.name):
            raise RuntimeError('unexpected namespace directory')
        for name in ('admission.json', 'exit.json', 'supervisor.json'):
            path = directory / name
            if path.exists() or path.is_symlink():
                with (upload / f'{directory.name}-{name}').open('xb') as out:
                    out.write(read_regular(path.relative_to(runner)))
    if not any(upload.iterdir()):
        raise RuntimeError('no evidence collected')


if __name__ == '__main__':
    root = Path(os.environ['RUNNER_TEMP']).resolve() / 'explicit-bind-diagnostic'
    {'prepare': prepare, 'run': run, 'collect': collect}[sys.argv[1]](root)
