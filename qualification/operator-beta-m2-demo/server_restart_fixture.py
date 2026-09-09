#!/usr/bin/env python3
"""Bounded DISPLAY_FIXTURE: restart the observer, never an execution owner.

Uses the existing screen and browser observer. A fixed, explicitly synthetic
projection survives two actual server PIDs. This is not Docket integration,
execution recovery, a provider turn, or a new enrollment interface.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from browser_fixture import demo, Fixture, UI_SOURCE


def retain(path, value):
    pending = path.with_name(path.name + '.writing')
    with pending.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, path)  # Atomic complete publication; never overwrite.
    pending.unlink()
    directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def stop_child(child, record):
    if child.poll() is None:
        child.terminate()
    exceeded = False
    try:
        code = child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        exceeded = True
        child.kill()
        try:
            code = child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            retain(record, {'pid': child.pid, 'exit': 'NOT_OBSERVABLE',
                            'stop': 'KILL_SENT_TERMINATION_NOT_ESTABLISHED'})
            raise
    retain(record, {'pid': child.pid, 'exit': code, 'stop_bound_exceeded': exceeded})
    if exceeded:
        raise RuntimeError('observer stop exceeded bound; exact child killed')


class ReadOnlyFixture:
    def __init__(self, source, calls):
        self.source, self.calls = source, calls

    def query(self, operation):
        with self.calls.open('a') as stream:
            stream.write(operation + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        if operation != 'status':
            raise demo.Unavailable('DISPLAY_FIXTURE is read-only; no launch mechanism')
        value = json.loads(self.source.read_bytes())
        demo.validate_projection(value)
        return value


def serve(root, ordinal, port):
    server = demo.DemoServer(('127.0.0.1', port),
                            ReadOnlyFixture(root / 'projection.json', root / f'calls-{ordinal}.txt'))
    retain(root / f'server-{ordinal}.json', {
        'mode': 'DISPLAY_FIXTURE', 'pid': os.getpid(), 'origin': server.origin,
        'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
        'ui_sha256': hashlib.sha256(UI_SOURCE).hexdigest()})
    try:
        server.serve_forever()
    finally:
        server.server_close()


def run(root):
    root.mkdir(mode=0o700)  # Never overwrite an earlier occurrence.
    retain(root / 'INPUTS.json', {
        'mode': 'DISPLAY_FIXTURE', 'pid': os.getpid(), 'cwd': str(Path.cwd()),
        'invocation_id': os.environ.get('INVOCATION_ID', 'NOT_OBSERVABLE'),
        'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'ui_sha256': hashlib.sha256(UI_SOURCE).hexdigest(),
        'integration': 'NOT_RUN', 'production': 'NOT_RUN'})
    value = Fixture('success').value
    retain(root / 'projection.json', value)
    original = (root / 'projection.json').read_bytes()
    servers, port = [], 0
    try:
        for ordinal in range(2):
            with (root / f'server-{ordinal}.log').open('x') as log:
                child = subprocess.Popen([sys.executable, '-B', __file__, '--serve',
                    '--out', str(root), '--ordinal', str(ordinal), '--port', str(port)],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    ready = root / f'server-{ordinal}.json'
                    deadline = time.monotonic() + 15
                    while not ready.exists():
                        if child.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('observer server readiness unavailable')
                        time.sleep(0.05)
                    identity = json.loads(ready.read_bytes())
                    if identity['pid'] != child.pid:
                        raise RuntimeError('observer process identity differs')
                    port = int(identity['origin'].rsplit(':', 1)[1])
                    servers.append(identity)
                    command = ['node', str(Path(__file__).with_name('browser_exercise.cjs')),
                        '--url', identity['origin'] + '/', '--out', str(root / f'browser-{ordinal}'),
                        '--mode', 'DISPLAY_FIXTURE', '--action', 'observe', '--max-seconds', '35',
                        '--expect-state', 'TERMINAL', '--expect-live', 'PROCESS_EXITED']
                    subprocess.run(command, check=True, timeout=45)
                finally:
                    stop_child(child, root / f'stop-{ordinal}.json')
            if (root / 'projection.json').read_bytes() != original:
                raise RuntimeError('observer altered fixed fixture state')
            calls = (root / f'calls-{ordinal}.txt').read_text().splitlines()
            if not calls or set(calls) != {'status'}:
                raise RuntimeError('observer issued non-status operation')
        if servers[0]['pid'] == servers[1]['pid'] or servers[0]['origin'] != servers[1]['origin']:
            raise RuntimeError('expected new PID at same observer endpoint')
        for ordinal in range(2):
            captures = sorted((root / f'browser-{ordinal}').glob('*.status.json'))
            if not captures or any(json.loads(path.read_bytes()) != value for path in captures):
                raise RuntimeError('browser did not recover exact fixed projection')
        retain(root / 'RESULT.json', {'state': 'OBSERVER_RESTART_DISPLAY_FIXTURE_PASSED',
            'servers': servers, 'projection_sha256': hashlib.sha256(original).hexdigest(),
            'start_requests': 0, 'integration': 'NOT_RUN', 'execution_recovery': 'NOT_RUN',
            'meaning': 'Two actual observer PIDs rendered unchanged synthetic state without RUN'})
    except Exception as error:
        retain(root / 'REFUSAL.json', {'reason': str(error), 'integration': 'NOT_RUN'})
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--ordinal', type=int, choices=(0, 1), default=0)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    if not args.out.is_absolute():
        parser.error('absolute new fixture path required')
    if args.serve:
        serve(args.out, args.ordinal, args.port)
    else:
        run(args.out)
