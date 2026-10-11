"""Run a local two-server walkthrough; print outcomes, never credentials."""

from contextlib import ExitStack
from pathlib import Path
import os
import json
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import jwt


ROOT = Path(__file__).resolve().parents[1]


def free_ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(('127.0.0.1', 0))
        second.bind(('127.0.0.1', 0))
        return first.getsockname()[1], second.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start(stack, module, port, environment, factory=False):
    log = stack.enter_context(tempfile.TemporaryFile(mode='w+b'))
    command = [sys.executable, '-m', 'uvicorn', module, '--host', '127.0.0.1',
               '--port', str(port), '--no-access-log']
    if factory:
        command.append('--factory')
    process = subprocess.Popen(command, cwd=ROOT, env=environment,
        stdout=log, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    stack.callback(stop, process)
    return process, log


def ready(client, url, process, log):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.seek(0)
            raise RuntimeError('Demo server failed to start:\n' + log.read().decode(errors='replace'))
        try:
            if client.get(url, timeout=0.5).status_code == 200:
                return
        except httpx.RequestError:
            pass
        time.sleep(0.1)
    raise RuntimeError('Timed out waiting for a local demo server.')


def main():
    upstream_port, gateway_port = free_ports()
    upstream_url = f'http://127.0.0.1:{upstream_port}'
    gateway_url = f'http://127.0.0.1:{gateway_port}'
    secret = secrets.token_hex(32)
    environment = os.environ.copy()
    environment.update(POLICYGATE_SECRET=secret, POLICYGATE_UPSTREAM_URL=upstream_url)

    def token(role, expired=False):
        now = int(time.time())
        return jwt.encode({'sub': f'demo-{role}', 'role': role,
            'iss': 'policygate-demo', 'aud': 'policygate-api',
            'iat': now - 60, 'exp': now - 30 if expired else now + 300},
            secret, algorithm='HS256')

    reader = {'Authorization': 'Bearer ' + token('reader')}
    admin = {'Authorization': 'Bearer ' + token('admin')}
    expired = {'Authorization': 'Bearer ' + token('reader', expired=True)}
    checked = 0

    with ExitStack() as stack:
        client = stack.enter_context(httpx.Client(timeout=10, trust_env=False))
        upstream, upstream_log = start(stack, 'policygate.upstream:app', upstream_port, environment)
        ready(client, upstream_url + '/reports', upstream, upstream_log)
        gateway, gateway_log = start(stack, 'policygate.gateway:app_from_env', gateway_port, environment, factory=True)
        ready(client, gateway_url + '/health', gateway, gateway_log)

        def check(label, method, path, expected, **kwargs):
            nonlocal checked
            response = client.request(method, gateway_url + path, **kwargs)
            if response.status_code != expected:
                raise AssertionError(f'{label}: expected {expected}, got {response.status_code}')
            if not response.headers.get('X-Request-ID'):
                raise AssertionError(label + ': missing request ID')
            checked += 1
            print(f'PASS {label}: HTTP {expected}')
            return response

        check('Public liveness', 'GET', '/health', 200)
        check('Missing token rejected', 'GET', '/reports', 401)
        before = check('Reader can list', 'GET', '/reports', 200, headers=reader).json()['reports']
        check('Reader write denied', 'POST', '/reports', 403, headers=reader, json={'title': 'Blocked report'})
        after = check('Denied write left storage unchanged', 'GET', '/reports', 200, headers=admin).json()['reports']
        if before != after:
            raise AssertionError('A forbidden write changed upstream data.')
        check('Admin can create', 'POST', '/reports', 201, headers=admin, json={'title': 'Synthetic demo report'})
        created = check('Reader sees created report', 'GET', '/reports', 200, headers=reader).json()['reports']
        if len(created) != len(before) + 1 or created[-1]['title'] != 'Synthetic demo report':
            raise AssertionError('The allowed write was not persisted in the demo process.')
        check('Expired token rejected', 'GET', '/reports', 401, headers=expired)
        check('Unknown route denied', 'GET', '/admin', 403, headers=admin)
        check('Invalid report rejected', 'POST', '/reports', 422, headers=admin, json={'title': '   '})
        stop(upstream)
        check('Stopped upstream handled', 'GET', '/reports', 502, headers=reader)
        stop(gateway)
        gateway_log.seek(0)
        log_text = gateway_log.read().decode(errors='replace')
        events = [json.loads(line) for line in log_text.splitlines() if line.startswith('{')]
        if len(events) < checked:
            raise AssertionError('Audit events were not written to the server log.')
        if any(value in log_text for value in [secret, reader['Authorization'].split()[1], admin['Authorization'].split()[1]]):
            raise AssertionError('A secret or credential appeared in the server log.')
        if not {'allow', 'deny', 'error'} <= {event['decision'] for event in events}:
            raise AssertionError('Expected audit decisions are missing.')
        print('PASS Audit events recorded without demo tokens or signing secret')
    print(f'All {checked} live HTTP checks passed; both local processes stopped.')


if __name__ == '__main__':
    main()
