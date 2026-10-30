import json
import struct
from pathlib import Path
import pytest
from otguard.core import assess,parse_pcap,write_report
from otguard.active import validate_approval,connect_checks

def test_findings():
    flow=[dict(src_ip='10.0.0.1',dst_ip='10.0.0.2',protocol='TCP',src_port=1000,dst_port=502,packets=2,bytes=40)]
    assets=[dict(ip='10.0.0.1',zone='IT'),dict(ip='10.0.0.2',zone='OT',vendor='V',product='P',version='1')]
    result=assess(flow,assets,[dict(advisory_id='TEST',vendor='V',product='P',version='1')],[dict(src_zone='IT',dst_zone='OT',dst_port='502',action='deny')])
    assert result['summary']['findings']==2

def test_html_escaping(tmp_path):
    result=assess([],assets=[dict(ip='10.0.0.1',vendor='<script>alert(1)</script>')])
    write_report(result,tmp_path)
    assert '<script>' not in (tmp_path/'report.html').read_text()

def test_pcap(tmp_path):
    p=tmp_path/'x.pcap'
    eth=b'\x00'*12+b'\x08\x00'
    ip=b'\x45\x00'+struct.pack('!H',40)+b'\x00\x00\x00\x00\x40\x06\x00\x00'+bytes([10,0,0,1,10,0,0,2])
    tcp=struct.pack('!HH',12345,502)+b'\x00'*16
    packet=eth+ip+tcp
    p.write_bytes(b'\xd4\xc3\xb2\xa1'+b'\x02\x00\x04\x00'+b'\x00'*8+struct.pack('<II',65535,1)+struct.pack('<IIII',0,0,len(packet),len(packet))+packet)
    flows,meta=parse_pcap(p)
    assert len(flows)==1 and flows[0]['dst_port']==502 and meta['packets_processed']==1

def approval(tmp_path):
    p=tmp_path/'approval.json'
    p.write_text(json.dumps(dict(operator='tester',ticket='OT-123',expires_utc='2099-01-01T00:00:00Z',allowed_hosts=['192.0.2.10'],allowed_ports=[443,502],max_connections=2,min_delay_seconds=1)))
    from otguard.active import sign_approval
    import os
    os.environ['OTGUARD_APPROVAL_KEY']='a'*40
    sign_approval(p)
    return p

def test_approval_required(tmp_path):
    with pytest.raises(PermissionError):validate_approval(approval(tmp_path),['192.0.2.10'],[443],False)

def test_scope_rejected(tmp_path):
    with pytest.raises(PermissionError):validate_approval(approval(tmp_path),['192.0.2.11'],[443],True)

def test_ot_ports_rejected(tmp_path):
    with pytest.raises(PermissionError):validate_approval(approval(tmp_path),['192.0.2.10'],[502],True)

def test_dry_run_never_connects(tmp_path,monkeypatch):
    import socket
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k: (_ for _ in ()).throw(AssertionError('Network attempted')))
    assert connect_checks(approval(tmp_path),['192.0.2.10'],[443],True,False)['mode']=='dry-run'

def test_csv_formula_neutralization(tmp_path):
    from otguard.core import csv_safe
    assert csv_safe('=1+1').startswith("'")
    assert csv_safe('normal') == 'normal'

def test_csv_size_limit(tmp_path):
    from otguard.core import rows_csv, MAX_CSV_BYTES
    p=tmp_path/'large.csv'
    with p.open('wb') as f: f.truncate(MAX_CSV_BYTES+1)
    with pytest.raises(ValueError,match='limit'): rows_csv(p)

def test_bad_signature_rejected(tmp_path,monkeypatch):
    monkeypatch.setenv('OTGUARD_APPROVAL_KEY','a'*40)
    p=tmp_path/'approval.json'
    p.write_text(json.dumps({'operator':'x','ticket':'x','signature':'0'*64}))
    with pytest.raises(PermissionError,match='signature'):
        validate_approval(p,['192.0.2.10'],[443],True)

def test_stop_file_prevents_network(tmp_path,monkeypatch):
    import socket
    from otguard.active import sign_approval
    monkeypatch.setenv('OTGUARD_APPROVAL_KEY','a'*40)
    p=approval(tmp_path)
    sign_approval(p)
    stop=tmp_path/'STOP'
    stop.touch()
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k: (_ for _ in ()).throw(AssertionError('network attempted')))
    plan=connect_checks(p,['192.0.2.10'],[443],True)
    result=connect_checks(p,['192.0.2.10'],[443],True,True,stop_file=stop,audit_file=tmp_path/'audit.jsonl',plan_id=plan['plan_id'])
    assert result['mode']=='interrupted' and not result['checks']
