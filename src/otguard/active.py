"""Strictly approval-gated TCP connect checks. No OT protocol payloads."""
import hashlib
import hmac
import os
import ipaddress
import json
import math
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

DENIED_PORTS={502,102,44818,2222,20000,4840,47808,2404}

def _verify_signature(approval):
    key = os.environ.get('OTGUARD_APPROVAL_KEY', '')
    if len(key) < 32:
        raise PermissionError('OTGUARD_APPROVAL_KEY must be at least 32 characters')
    signature = approval.get('signature', '')
    if not isinstance(signature, str) or len(signature) != 64 or any(c not in '0123456789abcdef' for c in signature):
        raise PermissionError('Signed approval required')
    payload = {k: v for k, v in approval.items() if k != 'signature'}
    message = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    expected = hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError('Approval signature invalid')


def sign_approval(path):
    """Sign an approval using a separately provisioned shared key (not a PKI signature)."""
    approval = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(approval, dict):
        raise PermissionError('Approval must be a JSON object')
    approval.pop('signature', None)
    key = os.environ.get('OTGUARD_APPROVAL_KEY', '')
    if len(key) < 32:
        raise PermissionError('OTGUARD_APPROVAL_KEY must be at least 32 characters')
    message = json.dumps(approval, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    approval['signature'] = hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    Path(path).write_text(json.dumps(approval, indent=2) + '\n', encoding='utf-8')


def _number(value, name, minimum, maximum, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PermissionError(f'{name} must be a number')
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise PermissionError(f'{name} must be between {minimum} and {maximum}')
    if integer and not isinstance(value, int):
        raise PermissionError(f'{name} must be an integer')
    return value


def _expiry(approval):
    try:
        expiry = datetime.fromisoformat(approval['expires_utc'].replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise PermissionError('Invalid approval expiry') from exc
    if expiry.tzinfo is None:
        raise PermissionError('Approval expiry requires a timezone')
    return expiry


def validate_approval(path, targets, ports, acknowledged):
    if not acknowledged:
        raise PermissionError('Active checks require --ack-authorized')
    approval = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(approval, dict):
        raise PermissionError('Approval must be a JSON object')
    _verify_signature(approval)
    required = ('operator', 'ticket', 'expires_utc', 'allowed_hosts', 'allowed_ports',
                'max_connections', 'min_delay_seconds')
    if any(k not in approval for k in required):
        raise PermissionError('Approval is missing required fields')
    for field in ('operator', 'ticket'):
        if not isinstance(approval[field], str) or not approval[field].strip():
            raise PermissionError(f'{field} must be a nonempty string')
    if _expiry(approval) <= datetime.now(timezone.utc):
        raise PermissionError('Approval expired')
    if not isinstance(approval['allowed_hosts'], list) or not isinstance(approval['allowed_ports'], list):
        raise PermissionError('Approved hosts and ports must be lists')
    try:
        allowed = {str(ipaddress.ip_address(x)) for x in approval['allowed_hosts'] if isinstance(x, str)}
        selected = {str(ipaddress.ip_address(x)) for x in targets}
    except ValueError as exc:
        raise PermissionError('Targets must be literal IP addresses') from exc
    if not selected or not selected <= allowed:
        raise PermissionError('Target outside approved host list')
    for port in [*approval['allowed_ports'], *ports]:
        _number(port, 'port', 1, 65535, integer=True)
    if not ports or not set(ports) <= set(approval['allowed_ports']):
        raise PermissionError('Port outside approved list')
    if set(ports) & DENIED_PORTS:
        raise PermissionError('Industrial protocol ports are never probed by this release')
    budget = _number(approval['max_connections'], 'max_connections', 1, 100, integer=True)
    if len(selected) * len(set(ports)) > budget:
        raise PermissionError('Connection budget exceeded (hard maximum 100)')
    delay = _number(approval['min_delay_seconds'], 'min_delay_seconds', 1, 3600)
    _number(approval.get('max_attempts_per_second', 1), 'max_attempts_per_second', 1 / 3600, 1)
    _number(approval.get('per_host_cooldown_seconds', delay), 'per_host_cooldown_seconds', 1, 3600)
    _number(approval.get('max_consecutive_failures', 1), 'max_consecutive_failures', 1, 100, integer=True)
    return approval, sorted(selected), delay


def _plan(approval, selected, ports, delay):
    interval = max(delay, 1 / approval.get('max_attempts_per_second', 1))
    cooldown = approval.get('per_host_cooldown_seconds', delay)
    planned, last_host, last = [], {}, None
    for target in selected:
        for port in sorted(set(ports)):
            offset = max(0 if last is None else last + interval,
                         last_host.get(target, -cooldown) + cooldown)
            planned.append({'target': target, 'port': port, 'earliest_offset_seconds': offset})
            last_host[target], last = offset, offset
    plan = {'schema_version': 1, 'operator': approval['operator'], 'ticket': approval['ticket'],
            'expires_utc': approval['expires_utc'], 'checks': planned,
            'limits': {'max_connections': approval['max_connections'], 'concurrency': 1,
                       'global_interval_seconds': interval, 'per_host_cooldown_seconds': cooldown,
                       'max_consecutive_failures': approval.get('max_consecutive_failures', 1),
                       'connect_timeout_seconds': 1.0},
            'caution': 'Connection-attempt limits are not packet-rate limits. OS TCP retransmissions are outside this budget.'}
    # Bind the reviewed plan to the entire signed approval, including future policy fields.
    canonical = json.dumps({'plan': plan, 'approval': approval}, sort_keys=True, separators=(',', ':'))
    plan['plan_id'] = hashlib.sha256(canonical.encode()).hexdigest()
    return plan


def connect_checks(approval_path, targets, ports, acknowledged=False, execute=False,
                   stop_file=None, audit_file=None, plan_id=None):
    approval, selected, delay = validate_approval(approval_path, targets, ports, acknowledged)
    plan = _plan(approval, selected, ports, delay)
    if not execute:
        return {'mode': 'dry-run', **plan}
    if plan_id != plan['plan_id']:
        raise PermissionError('Execution requires --plan-id from the current reviewed dry-run')
    if not audit_file:
        raise PermissionError('Execution requires an audit file')
    results = []
    attempted_count = 0
    run_id = os.urandom(16).hex()

    def audit(event):
        record = {'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                  'run_id': run_id, 'plan_id': plan['plan_id'], 'ticket': approval['ticket'], **event}
        with Path(audit_file).open('a', encoding='utf-8') as log:
            log.write(json.dumps(record, sort_keys=True) + '\n')
            log.flush()
            os.fsync(log.fileno())

    def stop_reason():
        if stop_file and Path(stop_file).exists():
            return 'operator_stop'
        if datetime.now(timezone.utc) >= _expiry(approval):
            return 'approval_expired'
        return None

    audit({'event': 'execution_started', 'plan': plan})
    started = time.monotonic()
    last_attempt, host_attempts, failures, reason = None, {}, 0, None
    try:
        for item in plan['checks']:
            target, port = item['target'], item['port']
            while True:
                reason = stop_reason()
                if reason:
                    break
                now = time.monotonic()
                due = max(now if last_attempt is None else last_attempt + plan['limits']['global_interval_seconds'],
                          host_attempts.get(target, now - plan['limits']['per_host_cooldown_seconds'])
                          + plan['limits']['per_host_cooldown_seconds'])
                if due <= now:
                    break
                time.sleep(min(0.1, due - now))
            if reason:
                break
            # Intent is durably recorded before any network operation. Audit failure fails closed.
            audit({'event': 'connection_attempt', 'target': target, 'port': port})
            reason = stop_reason()
            if reason:
                break
            attempted = time.monotonic()
            last_attempt = host_attempts[target] = attempted
            timeout = min(1.0, (_expiry(approval) - datetime.now(timezone.utc)).total_seconds())
            if timeout <= 0:
                reason = 'approval_expired'
                break
            attempted_count += 1
            try:
                with socket.create_connection((target, port), timeout=timeout):
                    status = 'tcp_connected'
            except OSError:
                status = 'not_connected_or_filtered'
            result = {'target': target, 'port': port, 'status': status,
                      'attempt_offset_seconds': attempted - started,
                      'duration_seconds': time.monotonic() - attempted}
            results.append(result)
            audit({'event': 'connection_result', **result})
            failures = failures + 1 if status != 'tcp_connected' else 0
            if failures >= plan['limits']['max_consecutive_failures']:
                reason = 'consecutive_failure_limit'
                break
    except KeyboardInterrupt:
        reason = 'operator_interrupt'
    audit({'event': 'execution_finished', 'attempted_count': attempted_count,
           'stop_reason': reason or 'plan_completed'})
    return {'mode': 'interrupted' if reason else 'executed', 'plan': plan,
            'run_id': run_id, 'ticket': approval['ticket'], 'checks': results,
            'attempted_count': attempted_count, 'planned_count': len(plan['checks']),
            'stop_reason': reason or 'plan_completed', 'caution': plan['caution']}
