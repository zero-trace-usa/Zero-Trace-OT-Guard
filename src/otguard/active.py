"""Strictly approval-gated TCP connect checks. No OT protocol payloads."""
import hashlib
import hmac
import os
import ipaddress
import json
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
    if not isinstance(signature, str) or len(signature) != 64:
        raise PermissionError('Signed approval required')
    payload = {k: v for k, v in approval.items() if k != 'signature'}
    message = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    expected = hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError('Approval signature invalid')


def sign_approval(path):
    """Sign an approval using a separately provisioned shared key (not a PKI signature)."""
    approval = json.loads(Path(path).read_text(encoding='utf-8'))
    approval.pop('signature', None)
    key = os.environ.get('OTGUARD_APPROVAL_KEY', '')
    if len(key) < 32:
        raise PermissionError('OTGUARD_APPROVAL_KEY must be at least 32 characters')
    message = json.dumps(approval, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    approval['signature'] = hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    Path(path).write_text(json.dumps(approval, indent=2) + '\n', encoding='utf-8')


def validate_approval(path,targets,ports,acknowledged):
    if not acknowledged: raise PermissionError('Active checks require --ack-authorized')
    approval=json.loads(Path(path).read_text(encoding='utf-8'))
    _verify_signature(approval)
    required=('operator','ticket','expires_utc','allowed_hosts','allowed_ports','max_connections','min_delay_seconds')
    if any(not approval.get(k) and approval.get(k)!=0 for k in required): raise PermissionError('Approval is missing required fields')
    expiry=datetime.fromisoformat(approval['expires_utc'].replace('Z','+00:00'))
    if expiry.tzinfo is None or expiry<=datetime.now(timezone.utc):raise PermissionError('Approval expired or timezone missing')
    allowed={str(ipaddress.ip_address(x)) for x in approval['allowed_hosts']}
    selected={str(ipaddress.ip_address(x)) for x in targets}
    if not selected or not selected<=allowed:raise PermissionError('Target outside approved host list')
    approved_ports=set(map(int,approval['allowed_ports']))
    if not ports or not set(ports)<=approved_ports:raise PermissionError('Port outside approved list')
    if set(ports)&DENIED_PORTS:raise PermissionError('Industrial protocol ports are never probed by this release')
    if len(selected)*len(set(ports))>min(int(approval['max_connections']),100):raise PermissionError('Connection budget exceeded (hard maximum 100)')
    delay=float(approval['min_delay_seconds'])
    if not 1.0 <= delay <= 3600:raise PermissionError('Minimum delay is 1 second')
    return approval,sorted(selected),delay

def connect_checks(approval_path,targets,ports,acknowledged=False,execute=False,stop_file=None,audit_file=None):
    approval,selected,delay=validate_approval(approval_path,targets,ports,acknowledged)
    planned=[{'target':ip,'port':p} for ip in selected for p in sorted(set(ports))]
    if not execute:return {'mode':'dry-run','ticket':approval['ticket'],'checks':planned}
    results=[]
    def audit(event):
        if audit_file:
            record={'timestamp_utc':datetime.now(timezone.utc).isoformat(),'ticket':approval['ticket'],**event}
            with Path(audit_file).open('a', encoding='utf-8') as log:
                log.write(json.dumps(record,sort_keys=True)+'\n')
    audit({'event':'execution_started','planned_count':len(planned)})
    interrupted=False
    for i,item in enumerate(planned):
        if stop_file and Path(stop_file).exists():
            interrupted=True
            audit({'event':'emergency_stop','completed_count':len(results)})
            break
        if i:
            remaining=delay
            while remaining>0:
                if stop_file and Path(stop_file).exists():
                    interrupted=True
                    break
                pause=min(0.2,remaining)
                time.sleep(pause)
                remaining-=pause
            if interrupted:
                audit({'event':'emergency_stop','completed_count':len(results)})
                break
        try:
            with socket.create_connection((item['target'],item['port']),timeout=1.0):status='tcp_connected'
        except (OSError,TimeoutError):status='not_connected_or_filtered'
        results.append({**item,'status':status})
        audit({'event':'connection_result',**item,'status':status})
    audit({'event':'execution_finished','completed_count':len(results),'interrupted':interrupted})
    return {'mode':'interrupted' if interrupted else 'executed','ticket':approval['ticket'],'checks':results,'caution':'TCP connect only. No service fingerprinting, protocol commands or vulnerability confirmation.'}
