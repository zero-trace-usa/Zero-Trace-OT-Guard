"""Strictly approval-gated TCP connect checks. No OT protocol payloads."""
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

DENIED_PORTS={502,102,44818,2222,20000,4840,47808,2404}

def validate_approval(path,targets,ports,acknowledged):
    if not acknowledged: raise PermissionError('Active checks require --ack-authorized')
    approval=json.loads(Path(path).read_text(encoding='utf-8'))
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
    if len(selected)*len(ports)>min(int(approval['max_connections']),100):raise PermissionError('Connection budget exceeded (hard maximum 100)')
    delay=float(approval['min_delay_seconds'])
    if delay<1.0:raise PermissionError('Minimum delay is 1 second')
    return approval,sorted(selected),delay

def connect_checks(approval_path,targets,ports,acknowledged=False,execute=False):
    approval,selected,delay=validate_approval(approval_path,targets,ports,acknowledged)
    planned=[{'target':ip,'port':p} for ip in selected for p in sorted(set(ports))]
    if not execute:return {'mode':'dry-run','ticket':approval['ticket'],'checks':planned}
    results=[]
    for i,item in enumerate(planned):
        if i:time.sleep(delay)
        try:
            with socket.create_connection((item['target'],item['port']),timeout=1.0):status='tcp_connected'
        except (OSError,TimeoutError):status='not_connected_or_filtered'
        results.append({**item,'status':status})
    return {'mode':'executed','ticket':approval['ticket'],'checks':results,'caution':'TCP connect only. No service fingerprinting, protocol commands or vulnerability confirmation.'}
