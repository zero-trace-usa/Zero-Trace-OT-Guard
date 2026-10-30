"""Safety policy regression tests; real socket coverage uses loopback only."""
import json
import socket
import threading
from datetime import datetime, timezone, timedelta

import pytest
from otguard import active


@pytest.fixture
def policy(tmp_path, monkeypatch):
    monkeypatch.setenv('OTGUARD_APPROVAL_KEY', 'local-test-only-' * 4)
    path = tmp_path / 'approval.json'

    def create(**overrides):
        value = dict(operator='lab', ticket='LAB-1', expires_utc='2099-01-01T00:00:00Z',
                     allowed_hosts=['127.0.0.1'], allowed_ports=[443, 8443],
                     max_connections=2, min_delay_seconds=1,
                     max_attempts_per_second=0.5, per_host_cooldown_seconds=3,
                     max_consecutive_failures=1)
        value.update(overrides)
        path.write_text(json.dumps(value))
        active.sign_approval(path)
        return path
    return create


def run(path, tmp_path, ports=(443, 8443), **kwargs):
    plan = active.connect_checks(path, ['127.0.0.1'], ports, True)
    return active.connect_checks(path, ['127.0.0.1'], ports, True, True,
                                 audit_file=tmp_path / 'audit.jsonl', plan_id=plan['plan_id'], **kwargs)


def test_plan_is_offline_and_deterministic(policy, monkeypatch):
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('network'))
    path = policy()
    first = active.connect_checks(path, ['127.0.0.1'], [8443, 443, 443], True)
    second = active.connect_checks(path, ['127.0.0.1'], [443, 8443], True)
    assert first == second
    assert [x['earliest_offset_seconds'] for x in first['checks']] == [0, 3]
    assert first['limits']['concurrency'] == 1


@pytest.mark.parametrize('field,value', [
    ('max_connections', True), ('max_connections', 1.5), ('max_connections', 101),
    ('min_delay_seconds', float('nan')), ('min_delay_seconds', float('inf')),
    ('max_attempts_per_second', 2), ('max_attempts_per_second', 0),
    ('per_host_cooldown_seconds', -1), ('max_consecutive_failures', 0),
    ('allowed_ports', [True]), ('allowed_ports', [65536]), ('operator', ''),
    ('expires_utc', 'tomorrow'), ('expires_utc', '2099-01-01T00:00:00'),
])
def test_invalid_signed_policy_fails_closed(policy, field, value):
    with pytest.raises(PermissionError):
        active.connect_checks(policy(**{field: value}), ['127.0.0.1'], [443], True)


def test_review_binding_and_audit_required(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('network'))
    path = policy()
    plan = active.connect_checks(path, ['127.0.0.1'], [443], True)
    with pytest.raises(PermissionError, match='plan-id'):
        active.connect_checks(path, ['127.0.0.1'], [443], True, True)
    with pytest.raises(PermissionError, match='audit'):
        active.connect_checks(path, ['127.0.0.1'], [443], True, True, plan_id=plan['plan_id'])
    policy(ticket='CHANGED')
    with pytest.raises(PermissionError, match='plan-id'):
        active.connect_checks(path, ['127.0.0.1'], [443], True, True,
                              audit_file=tmp_path/'audit.jsonl', plan_id=plan['plan_id'])


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_timing_audit_and_total_budget(policy, tmp_path, monkeypatch):
    clock, attempts = [100.0], []
    monkeypatch.setattr(active.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(active.time, 'sleep', lambda duration: clock.__setitem__(0, clock[0] + duration))

    def connect(*args, **kwargs):
        attempts.append(clock[0])
        assert json.loads((tmp_path/'audit.jsonl').read_text().splitlines()[-1])['event'] == 'connection_attempt'
        return Connection()
    monkeypatch.setattr(socket, 'create_connection', connect)
    result = run(policy(), tmp_path)
    assert result['stop_reason'] == 'plan_completed'
    assert len(attempts) == 2 and attempts[1] - attempts[0] >= 3
    records = [json.loads(line) for line in (tmp_path/'audit.jsonl').read_text().splitlines()]
    assert records[-1]['attempted_count'] == 2
    assert len({r['run_id'] for r in records}) == 1


def test_failure_circuit_breaker(policy, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError('simulated refusal')
    monkeypatch.setattr(socket, 'create_connection', fail)
    result = run(policy(), tmp_path)
    assert result['stop_reason'] == 'consecutive_failure_limit'
    assert result['attempted_count'] == 1


@pytest.mark.parametrize('cause', ['stop', 'expiry'])
def test_stop_during_wait(policy, tmp_path, monkeypatch, cause):
    clock = [0.0]
    baseline = datetime.now(timezone.utc)
    class ClockDateTime:
        @staticmethod
        def now(tz):
            return baseline + timedelta(seconds=clock[0])
        fromisoformat = datetime.fromisoformat
    monkeypatch.setattr(active, 'datetime', ClockDateTime)
    monkeypatch.setattr(active.time, 'monotonic', lambda: clock[0])
    stop = tmp_path/'STOP'
    def sleep(duration):
        clock[0] += duration
        if cause == 'stop':
            stop.touch()
    monkeypatch.setattr(active.time, 'sleep', sleep)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: Connection())
    result = run(policy(expires_utc=(baseline + timedelta(seconds=1)).isoformat()),
                 tmp_path, stop_file=stop)
    assert result['attempted_count'] == 1
    assert result['stop_reason'] == ('operator_stop' if cause == 'stop' else 'approval_expired')


def test_audit_failure_prevents_network(policy, tmp_path, monkeypatch):
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('network'))
    path = policy()
    plan = active.connect_checks(path, ['127.0.0.1'], [443], True)
    with pytest.raises(OSError):
        active.connect_checks(path, ['127.0.0.1'], [443], True, True,
                              audit_file=tmp_path/'missing'/'audit', plan_id=plan['plan_id'])


def test_loopback_connection(policy, tmp_path):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        if port in active.DENIED_PORTS:
            pytest.skip('OS selected a denied industrial port')
        accepted = []
        def serve():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                accepted.append(connection.recv(1))
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = run(policy(allowed_ports=[port], max_connections=1), tmp_path, ports=[port])
        finally:
            thread.join(timeout=4)
        assert not thread.is_alive()
        assert accepted == [b'']  # TCP handshake only; no application payload.
        assert result['checks'][0]['status'] == 'tcp_connected'


def test_global_rate_across_hosts(policy, tmp_path, monkeypatch):
    clock, attempts = [0.0], []
    monkeypatch.setattr(active.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(active.time, 'sleep', lambda duration: clock.__setitem__(0, clock[0] + duration))
    def connect(*args, **kwargs):
        attempts.append(clock[0])
        return Connection()
    monkeypatch.setattr(socket, 'create_connection', connect)
    path = policy(allowed_hosts=['127.0.0.1', '127.0.0.2'])
    plan = active.connect_checks(path, ['127.0.0.1', '127.0.0.2'], [443], True)
    result = active.connect_checks(path, ['127.0.0.1', '127.0.0.2'], [443], True, True,
                                   audit_file=tmp_path/'audit', plan_id=plan['plan_id'])
    assert result['attempted_count'] == 2
    assert attempts[1] - attempts[0] >= 2


def test_interrupt_reports_started_attempt(policy, tmp_path, monkeypatch):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(socket, 'create_connection', interrupt)
    result = run(policy(), tmp_path)
    assert result['stop_reason'] == 'operator_interrupt'
    assert result['attempted_count'] == 1
    assert result['checks'] == []  # An interrupted socket has no conclusive outcome.


def test_cli_review_and_stopped_execution(policy, tmp_path, monkeypatch, capsys):
    from otguard.cli import main
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('network'))
    path = policy()
    output = tmp_path/'result.json'
    args = ['active-check', '--approval', str(path), '--target', '127.0.0.1',
            '--port', '443', '--ack-authorized', '--output', str(output)]
    assert main(args) == 0
    plan = json.loads(output.read_text())
    capsys.readouterr()
    stop = tmp_path/'STOP'
    stop.touch()
    assert main(args + ['--execute', '--plan-id', plan['plan_id'], '--stop-file', str(stop),
                        '--audit-file', str(tmp_path/'audit')]) == 3
    result = json.loads(output.read_text())
    assert result['stop_reason'] == 'operator_stop' and result['attempted_count'] == 0


def test_cli_version_matches_package(capsys):
    from otguard import __version__
    from otguard.cli import main
    with pytest.raises(SystemExit) as exit_info:
        main(['--version'])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f'Zero-Trace OT Guard {__version__}'


def test_cli_help_documents_active_defaults(capsys):
    from otguard.cli import main
    with pytest.raises(SystemExit) as exit_info:
        main(['active-check', '--help'])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert 'active-audit.jsonl' in help_text
    assert '--plan-id' in help_text and '--execute' in help_text
